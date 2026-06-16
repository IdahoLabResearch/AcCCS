"""E2E-layer fixtures and guards.

The shared conformance fixtures (`exi_codec`, `veth_pair`, `launch_emulator`)
live in the parent `tests/conformance/conftest.py`. This child conftest adds
two safeguards that are specific to the E2E layer, where the only layer that
spawns real `run_secc.py` / `run_evcc.py` subprocesses lives.

1. **Fail-fast pre-flight (issue #62).** Before any E2E test launches its own
   subprocess pairs, assert that no `run_secc.py` / `run_evcc.py` process is
   already alive. The E2E pairs talk over the shared `acccs_secc`/`acccs_evcc`
   veth pair via link-local multicast; a stray emulator left over from a manual
   run hears the E2E's frames and collides every SLAC/SDP handshake, turning a
   ~60s suite into a multi-minute hang with no diagnostic. An `--auto-rearm`
   emulator never self-exits (ADR-0005: only `q` quits), so a backgrounded one
   is immortal until killed. Detecting the orphans up front and aborting with
   their PIDs converts that silent degradation into an actionable error.

2. **Per-test wall-clock backstop (issue #62, defense-in-depth).** A
   `pytest-timeout` cap on every E2E test so a hang that escapes the in-test
   deadlines (e.g. a wedged subprocess teardown) aborts with an all-thread
   traceback rather than running indefinitely. The cap sits *above* the
   layer's own deadlines — the slowest scenario allows 120s for the marker
   wait plus a ~15s SECC-ready wait and teardown — so it never kills a slow but
   legitimate run (notably the loaded AcCCS-box Pi gate); it only catches a
   genuine hang.
"""

from __future__ import annotations

import os
from pathlib import Path

import psutil
import pytest

# Emulator entry-point scripts whose presence in the process table signals a
# live emulator. Matched by basename against each token of a process cmdline.
EMULATOR_SCRIPTS = ("run_secc.py", "run_evcc.py")

# Veth interfaces the E2E pairs share — named in the diagnostic so the operator
# knows why an unrelated-looking process is the problem.
SECC_IFACE = "acccs_secc"
EVCC_IFACE = "acccs_evcc"

# Per-test wall-clock ceiling for the E2E layer. The slowest scenario allows a
# 120s marker-wait deadline (the ISO 15118-20 scenarios) on top of a ~15s
# SECC-ready wait and ~10s subprocess teardown, so a legitimate single test can
# run ~145s worst case on a loaded runner. 180s leaves headroom above that
# while still bounding a true hang. (The issue floated 30-60s, but that is
# below the layer's own deadlines and would flake legitimate slow runs.)
E2E_TIMEOUT_SECONDS = 180


# ---------------------------------------------------------------------------
# Fail-fast pre-flight: no stale emulator processes
# ---------------------------------------------------------------------------


def _cmdline_runs_emulator(cmdline: list[str]) -> bool:
    """True if ``cmdline`` looks like a launched emulator (`python run_*.py`).

    Requires a Python interpreter as argv0 and an emulator script among the
    remaining tokens (matched by basename). The interpreter check keeps an
    editor or grep that merely *names* ``run_secc.py`` from being flagged — the
    orphans we care about are always spawned as ``python run_{secc,evcc}.py``.
    """
    if not cmdline:
        return False
    argv0 = cmdline[0].rsplit("/", 1)[-1].lower()
    if not argv0.startswith("python"):
        return False
    return any(token.rsplit("/", 1)[-1] in EMULATOR_SCRIPTS for token in cmdline[1:])


def _scan_emulator_processes() -> list[tuple[int, str]]:
    """Return ``[(pid, cmdline_str), ...]`` for live emulator processes.

    Walks the process table via ``psutil`` (already a project dependency)
    rather than shelling out to ``pgrep``: the cmdline comes back as a
    structured list, so the match is exact and needs no external tool. The
    current process is skipped; processes that vanish or deny access mid-walk
    are ignored.
    """
    self_pid = os.getpid()
    found: list[tuple[int, str]] = []
    for proc in psutil.process_iter(["pid", "cmdline"]):
        try:
            pid = proc.info["pid"]
            if pid == self_pid:
                continue
            cmdline = proc.info["cmdline"] or []
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if _cmdline_runs_emulator(cmdline):
            found.append((pid, " ".join(cmdline)))
    return found


def _format_stale_message(stale: list[tuple[int, str]]) -> str:
    listing = "\n".join(f"    PID {pid}: {cmd}" for pid, cmd in stale)
    return (
        "Refusing to run the conformance E2E layer: "
        f"{len(stale)} stale emulator process(es) already alive.\n"
        f"These run_secc.py / run_evcc.py processes share the {SECC_IFACE}/"
        f"{EVCC_IFACE} veth pair and will collide with the E2E's own "
        "subprocess pairs, hanging the suite for minutes with no diagnostic "
        "(issue #62). An --auto-rearm emulator never self-exits (ADR-0005: "
        "only 'q' quits), so a backgrounded one stays alive until killed.\n"
        f"Offending process(es):\n{listing}\n"
        "Kill them and re-run, e.g.:  pkill -f run_secc.py; pkill -f run_evcc.py"
    )


@pytest.fixture(scope="session", autouse=True)
def _fail_fast_on_stale_emulators():
    """Abort the E2E session immediately if an emulator is already running.

    Session-scoped and autouse so it fires exactly once, before the first E2E
    test spawns anything — our own subprocess pairs are launched later by
    `launch_emulator` and so never trip it. Scoped to this directory's
    conftest, so a codec/state-machine-only run is unaffected.
    """
    stale = _scan_emulator_processes()
    if stale:
        # returncode is required: a bare pytest.exit() reports success (exit 0),
        # which would let CI go green despite the contended environment.
        pytest.exit(_format_stale_message(stale), returncode=1)
    yield


# ---------------------------------------------------------------------------
# Per-test wall-clock backstop
# ---------------------------------------------------------------------------


def pytest_collection_modifyitems(config, items):
    """Apply the E2E wall-clock cap to every test under this directory.

    Done via a collection hook rather than a per-module `pytestmark` so it
    covers future E2E tests with no per-file edit, and rather than a global
    `pytest.ini` `timeout` so the fast codec/state-machine layers keep their
    own (much tighter) speed targets unencumbered. A test that sets its own
    `@pytest.mark.timeout` is left alone. Inert when pytest-timeout is absent.
    """
    if not config.pluginmanager.hasplugin("timeout"):
        return
    e2e_dir = Path(__file__).resolve().parent
    for item in items:
        item_path = getattr(item, "path", None)
        if item_path is None or e2e_dir not in Path(item_path).parents:
            continue
        if any(mark.name == "timeout" for mark in item.iter_markers()):
            continue
        item.add_marker(pytest.mark.timeout(E2E_TIMEOUT_SECONDS))
