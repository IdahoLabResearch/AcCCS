"""Regression tests for the E2E fail-fast pre-flight (issue #62).

The pre-flight itself is a session-scoped autouse fixture that calls
`pytest.exit` (it would abort this very session, so it cannot be invoked
directly from a test). These tests exercise its building blocks instead — the
cmdline matcher, the live-process scan, and the diagnostic message — which is
where all the logic lives; the fixture is a thin three-line wrapper over them.
"""

from __future__ import annotations

import subprocess
import sys
import time

from tests.conformance.e2e.conftest import (
    E2E_TIMEOUT_SECONDS,
    _cmdline_runs_emulator,
    _format_stale_message,
    _scan_emulator_processes,
)


def test_matcher_flags_launched_emulator():
    assert _cmdline_runs_emulator(["python", "run_secc.py"])
    assert _cmdline_runs_emulator(["python3.12", "run_evcc.py", "--virtual"])
    assert _cmdline_runs_emulator(
        ["/usr/bin/python3", "/repo/run_secc.py", "--config", "x"]
    )


def test_matcher_ignores_non_emulator_cmdlines():
    # No interpreter as argv0 — an editor or pager naming the script.
    assert not _cmdline_runs_emulator(["vim", "run_secc.py"])
    assert not _cmdline_runs_emulator(["less", "run_evcc.py"])
    # A Python process that is not an emulator.
    assert not _cmdline_runs_emulator(["python", "-m", "pytest"])
    assert not _cmdline_runs_emulator(["python", "run_other.py"])
    # Degenerate inputs.
    assert not _cmdline_runs_emulator([])
    assert not _cmdline_runs_emulator(["python"])


def test_matcher_ignores_emulator_script_as_later_argument():
    """The script must be in argv1, not merely somewhere in the args (#64).

    A launched emulator is always ``python run_{secc,evcc}.py ...``, so the
    script is the first token after the interpreter. A Python tool that just
    *passes* the script path as a later argument is not a live emulator and
    must not trip the pre-flight abort.
    """
    assert not _cmdline_runs_emulator(["python", "sometool.py", "run_secc.py"])
    assert not _cmdline_runs_emulator(["python", "-m", "sometool", "run_evcc.py"])
    assert not _cmdline_runs_emulator(
        ["/usr/bin/python3", "-c", "import time; time.sleep(30)", "run_secc.py"]
    )


def test_scan_detects_a_live_emulator_named_process(tmp_path):
    """A live `python run_secc.py` process is found and reported by PID.

    The stand-in is spawned with the emulator script in argv1 — the real
    invocation shape (`python run_secc.py`) — so the scan exercises the
    script-position match (#64) rather than a path that merely appears as a
    later argument.
    """
    standin = tmp_path / "run_secc.py"
    standin.write_text("import time\n\ntime.sleep(30)\n")
    proc = subprocess.Popen([sys.executable, str(standin)])
    try:
        # Give the OS a beat to publish the new process's cmdline.
        deadline = time.monotonic() + 5.0
        pids = []
        while time.monotonic() < deadline:
            pids = [pid for pid, _ in _scan_emulator_processes()]
            if proc.pid in pids:
                break
            time.sleep(0.05)
        assert proc.pid in pids, (
            f"scan did not find the stand-in emulator pid {proc.pid}; "
            f"found {pids}"
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_e2e_items_carry_the_wall_clock_backstop(request):
    """The collection hook attaches the per-test timeout cap to E2E items."""
    marker = request.node.get_closest_marker("timeout")
    assert marker is not None, "E2E test is missing the pytest-timeout backstop"
    assert marker.args[0] == E2E_TIMEOUT_SECONDS


def test_message_names_every_offending_pid():
    msg = _format_stale_message(
        [(123, "python run_secc.py --virtual"), (456, "python run_evcc.py")]
    )
    assert "123" in msg
    assert "456" in msg
    # The operator needs to know why and how to recover.
    assert "#62" in msg
    assert "pkill" in msg
