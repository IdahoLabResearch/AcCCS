"""Scenario-driven E2E runner.

Discovers `tests/conformance/scenarios/*.yaml` and runs each as a parametrised
pytest case. Per ADR-0003 § End-to-end layer:

> Seam: two real emulator subprocesses talking over the `acccs_secc` ⇄
> `acccs_evcc` veth pair.
> Oracle: clean session termination — both EVCC and SECC observe
> `SessionStopReq` → `SessionStopRes` with no protocol-level errors raised.

Detecting the success oracle: the EVCC logs `SessionStopRes received` and
the SECC logs `Sent SessionStopRes` (both via the shared
`app/shared/comm_session.py` message logger) when the state machine reaches a
clean SessionStopRes. These markers are protocol-agnostic across DIN, ISO
15118-2, and ISO 15118-20. The runner watches each subprocess's stdout for
its own marker; either subprocess crashing or timing out before both emit it
counts as a failure.

Scenario YAMLs may opt into `xfail: true` for protocol slices that have not
yet landed (ADR-0003 F0 ships the iso2/iso20 smoke YAMLs as `xfail`).
"""

from __future__ import annotations

import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest
import yaml

from app.shared.personality import load_personality

SCENARIOS_DIR = Path(__file__).resolve().parents[1] / "scenarios"
PERSONALITIES_DIR = Path(__file__).resolve().parents[1] / "personalities"
PKI_CERTS_DIR = (
    Path(__file__).resolve().parents[3]
    / "app"
    / "shared"
    / "pki"
    / "iso15118_2"
    / "certs"
)
EVCC_SUCCESS_MARKER = "SessionStopRes received"
SECC_SUCCESS_MARKER = "Sent SessionStopRes"

# The SECC logs this the instant its SLAC receive loop is up — the first thing
# the EVCC talks to. We wait for it instead of a blind sleep before dialling
# (issue #47). SLAC runs below the protocol layer, so the marker is emitted for
# DIN, ISO 15118-2 and ISO 15118-20 alike.
SECC_READY_MARKER = "Sending SET_KEY_REQ"

# Upper bound on how long to wait for the SECC listener to come up before
# launching the EVCC. Generous so a loaded runner (the AcCCS-box Pi under a
# full-suite run) still clears it; if it elapses we launch anyway and let the
# scenario timeout plus captured output surface a genuinely dead SECC.
SECC_READY_TIMEOUT_SECONDS = 15.0


class _ProcessReader:
    """Drain a subprocess's stdout in a background thread (issue #47).

    The runner used to read the EVCC stream to completion and only then read
    the SECC stream. That left the undrained pipe to fill (a latent writer
    deadlock) and, more importantly, discarded every line — so a flaky failure
    reported only ``done=False`` with no clue where the session stalled.

    Each reader thread:

    * captures every line for post-mortem diagnostics (``tail``),
    * sets ``ready`` when the optional readiness marker appears, and
    * sets ``seen`` when the success marker appears.

    On EOF (the process exited) ``ready`` is set so a readiness waiter never
    blocks on a dead process; ``seen`` is deliberately left untouched so an
    early exit reads as failure, not success. Emulators are spawned with
    ``PYTHONUNBUFFERED=1`` (see ``launch_emulator``) so lines flush immediately
    rather than stranding the end-of-session marker in a block buffer when the
    process idles-and-re-arms (#41).
    """

    def __init__(
        self,
        proc: subprocess.Popen,
        marker: str,
        readiness_marker: Optional[str] = None,
    ) -> None:
        self._proc = proc
        self._marker = marker
        self._readiness_marker = readiness_marker
        self.lines: list[str] = []
        self.seen = threading.Event()
        self.ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        assert self._proc.stdout is not None
        for raw in iter(self._proc.stdout.readline, b""):
            line = raw.decode("utf-8", errors="replace")
            self.lines.append(line)
            if self._readiness_marker and self._readiness_marker in line:
                self.ready.set()
            if self._marker in line:
                self.seen.set()
        # EOF: the process closed its stdout (exited). Unblock readiness
        # waiters; leave `seen` as-is so an early exit is not mistaken for the
        # success marker.
        self.ready.set()

    def tail(self, n: int = 50) -> str:
        return "".join(self.lines[-n:])


def _pki_certs_present() -> bool:
    return (PKI_CERTS_DIR / "contractLeafCert.pem").exists()


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    evcc_personality: Path
    secc_personality: Path
    expected_outcome: str
    timeout_seconds: int
    xfail: bool
    xfail_reason: Optional[str]
    path: Path


def _load_scenario(path: Path) -> Scenario:
    data = yaml.safe_load(path.read_text())

    xfail = bool(data.get("xfail", False))
    xfail_reason = data.get("xfail_reason") or None
    if xfail and not xfail_reason:
        raise ValueError(
            f"{path}: xfail: true requires xfail_reason to be set"
        )

    return Scenario(
        name=data["name"],
        description=data.get("description", ""),
        evcc_personality=PERSONALITIES_DIR / f"{data['evcc_personality']}.yaml",
        secc_personality=PERSONALITIES_DIR / f"{data['secc_personality']}.yaml",
        expected_outcome=data.get("expected_outcome", "session_complete"),
        timeout_seconds=int(data.get("timeout_seconds", 60)),
        xfail=xfail,
        xfail_reason=xfail_reason,
        path=path,
    )


def _discover_scenarios() -> list[Scenario]:
    return sorted(
        (_load_scenario(p) for p in SCENARIOS_DIR.glob("*.yaml")),
        key=lambda s: s.name,
    )


def _scenario_params() -> list:
    params = []
    for scenario in _discover_scenarios():
        marks: list = []
        if scenario.xfail:
            marks.append(pytest.mark.xfail(reason=scenario.xfail_reason, strict=True))
        params.append(pytest.param(scenario, id=scenario.name, marks=marks))
    return params


@pytest.mark.parametrize("scenario", _scenario_params())
def test_scenario(scenario: Scenario, launch_emulator):
    if scenario.expected_outcome != "session_complete":
        pytest.skip(
            f"expected_outcome {scenario.expected_outcome!r} not supported "
            f"in Slice 1 — failure-shape grammar deferred"
        )
    if not scenario.evcc_personality.exists():
        pytest.fail(f"missing EVCC personality at {scenario.evcc_personality}")
    if not scenario.secc_personality.exists():
        pytest.fail(f"missing SECC personality at {scenario.secc_personality}")

    # Pre-validate via the same loader the spawned emulators use. Catches a
    # malformed test personality before two subprocesses are launched and
    # surfaces the Pydantic error in the test report rather than buried in
    # subprocess stdout.
    evcc_p = load_personality(str(scenario.evcc_personality), role="evcc")
    secc_p = load_personality(str(scenario.secc_personality), role="secc")

    # Defense-in-depth: if either personality requires TLS and the PKI cert
    # material has not been generated, skip rather than fail — a missing-cert
    # environment should be yellow, not red (AC3 of issue #49).
    needs_tls = (
        evcc_p.residual.tls.use_tls
        or evcc_p.residual.tls.enforce_tls
        or secc_p.residual.tls.use_tls
        or secc_p.residual.tls.enforce_tls
    )
    if needs_tls and not _pki_certs_present():
        pytest.skip(
            f"scenario {scenario.name!r} requires TLS but PKI cert material "
            f"is absent at {PKI_CERTS_DIR} — generate with "
            "`bash app/shared/pki/create_certs.sh -v iso-2`"
        )

    secc = launch_emulator("secc", scenario.secc_personality)
    secc_reader = _ProcessReader(
        secc, SECC_SUCCESS_MARKER, readiness_marker=SECC_READY_MARKER
    )
    # Wait for the SECC's SLAC listener to come up before the EVCC dials,
    # rather than a blind 0.5s sleep that a loaded runner can outrun (#47). If
    # the readiness marker never arrives within the bound (e.g. the SECC died
    # at startup), `ready` is also set on EOF, so we fall through and let the
    # scenario timeout plus captured output report the real failure.
    secc_reader.ready.wait(timeout=SECC_READY_TIMEOUT_SECONDS)

    evcc = launch_emulator("evcc", scenario.evcc_personality)
    evcc_reader = _ProcessReader(evcc, EVCC_SUCCESS_MARKER)

    deadline = time.monotonic() + scenario.timeout_seconds
    evcc_done = evcc_reader.seen.wait(timeout=max(0.0, deadline - time.monotonic()))
    secc_done = secc_reader.seen.wait(timeout=max(0.0, deadline - time.monotonic()))

    assert evcc_done and secc_done, (
        f"scenario {scenario.name!r}: expected EVCC to log "
        f"{EVCC_SUCCESS_MARKER!r} and SECC to log {SECC_SUCCESS_MARKER!r}; "
        f"EVCC done={evcc_done}, SECC done={secc_done}\n"
        f"--- SECC output (tail) ---\n{secc_reader.tail()}\n"
        f"--- EVCC output (tail) ---\n{evcc_reader.tail()}"
    )
