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

import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

import pytest
import yaml

from app.shared.personality import load_personality

SCENARIOS_DIR = Path(__file__).resolve().parents[1] / "scenarios"
PERSONALITIES_DIR = Path(__file__).resolve().parents[1] / "personalities"
EVCC_SUCCESS_MARKER = "SessionStopRes received"
SECC_SUCCESS_MARKER = "Sent SessionStopRes"


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


def _wait_for_success(proc: subprocess.Popen, marker: str, deadline: float) -> bool:
    """Read `proc.stdout` line-by-line until the given marker or the deadline.

    Returns True when the marker is seen. Returns False if the process exits
    or the deadline passes first.
    """
    assert proc.stdout is not None
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                return False
            continue
        if marker in line.decode("utf-8", errors="replace"):
            return True
    return False


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
    load_personality(str(scenario.evcc_personality), role="evcc")
    load_personality(str(scenario.secc_personality), role="secc")

    secc = launch_emulator("secc", scenario.secc_personality)
    # Tiny grace period so the SECC TCP listener is up before EVCC dials.
    time.sleep(0.5)
    evcc = launch_emulator("evcc", scenario.evcc_personality)

    deadline = time.monotonic() + scenario.timeout_seconds
    evcc_done = _wait_for_success(evcc, EVCC_SUCCESS_MARKER, deadline)
    secc_done = (
        _wait_for_success(secc, SECC_SUCCESS_MARKER, deadline) if evcc_done else False
    )

    assert evcc_done and secc_done, (
        f"scenario {scenario.name!r}: expected EVCC to log "
        f"{EVCC_SUCCESS_MARKER!r} and SECC to log {SECC_SUCCESS_MARKER!r}; "
        f"EVCC done={evcc_done}, SECC done={secc_done}"
    )
