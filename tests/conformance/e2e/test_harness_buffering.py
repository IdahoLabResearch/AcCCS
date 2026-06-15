"""Regression guard for the E2E harness's subprocess-output handling.

Issue #47: the conformance E2E runner watches each emulator subprocess's
stdout for an end-of-session success marker. Python block-buffers stdout when
it is a pipe (not a tty), so a child that emits a line and then *idles* — which
is exactly what the EVCC/SECC do after the idle-and-re-arm lifecycle landed in
#41 — leaves that line stranded in the unflushed block buffer. The harness then
times out waiting for a marker the child already logged, intermittently failing
with ``done=False``.

The fix is twofold and both halves are pinned here without needing the veth
pair (so this runs in every environment):

1. ``_ProcessReader`` drains a subprocess's stdout in a background thread,
   capturing every line and signalling an ``Event`` when the marker appears.
2. The emulators are spawned with ``PYTHONUNBUFFERED=1`` so each line flushes
   immediately, even while the process subsequently idles.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

from tests.conformance.e2e.test_scenarios import _ProcessReader

MARKER = "SESSION-DONE-MARKER"

# A child that prints the marker once and then idles without exiting — the
# post-#41 emulator shape. With block-buffered stdout the line never flushes.
_IDLE_AFTER_MARKER = (
    "import sys, time\n"
    f"sys.stdout.write({MARKER!r} + '\\n')\n"
    "time.sleep(30)\n"
)


def _spawn(env_extra: dict) -> subprocess.Popen:
    env = dict(os.environ)
    env.update(env_extra)
    return subprocess.Popen(
        [sys.executable, "-c", _IDLE_AFTER_MARKER],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )


def test_buffered_idling_child_strands_marker():
    """RED: block-buffered stdout hides the marker of an idling child."""
    proc = _spawn(env_extra={})
    try:
        reader = _ProcessReader(proc, MARKER)
        assert not reader.seen.wait(timeout=3.0), (
            "expected a block-buffered idling child to strand its marker; if "
            "this child flushed, the test no longer reproduces issue #47"
        )
    finally:
        proc.kill()
        proc.wait(timeout=5)


def test_unbuffered_idling_child_surfaces_marker_promptly():
    """GREEN: PYTHONUNBUFFERED=1 flushes the marker even while the child idles."""
    proc = _spawn(env_extra={"PYTHONUNBUFFERED": "1"})
    try:
        reader = _ProcessReader(proc, MARKER)
        assert reader.seen.wait(timeout=5.0), (
            "PYTHONUNBUFFERED child should surface its marker before it idles"
        )
        assert any(MARKER in line for line in reader.lines)
    finally:
        proc.kill()
        proc.wait(timeout=5)


def test_reader_reports_eof_without_marker():
    """A child that exits without the marker must not falsely report success."""
    proc = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdout.write('nope\\n')"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    try:
        reader = _ProcessReader(proc, MARKER)
        # The process exits quickly; the reader must surface EOF (so waiters
        # unblock) without ever setting `seen`.
        time.sleep(1.0)
        assert not reader.seen.is_set()
        assert "nope\n" in reader.tail()
    finally:
        proc.kill()
        proc.wait(timeout=5)
