"""Phase indicator appears in the footer at process startup, before SLAC completes.

Regression guard for issue #39: the console must paint ``Waiting for SLAC``
in the footer as soon as the TUI starts — before any peer connects and before
``doSLAC()`` returns — so the operator sees the lifecycle phase from the first
frame rather than only after the SLAC handshake has already completed.

Driven through a real pty (identical approach to test_footer_pinning_pty.py)
so the assertion is against actual terminal output, not a unit-level mock.
"""

from __future__ import annotations

import fcntl
import os
import pty
import re
import select
import signal
import struct
import sys
import termios
import time

import pytest

pyte = pytest.importorskip("pyte")

ROWS, COLS = 30, 120
PHASE_MARK = "Waiting for SLAC"

# Child: mimic the production flow — set phase to "Waiting for SLAC" on
# LiveControl, then start run_with_console wrapping a coroutine that holds
# the phase in place (simulating SLAC still pending). No peer required.
_CHILD = r"""
import asyncio, logging, sys
from app.shared.console import run_with_console
from app.shared.live_control import LiveControl

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(levelname)s: %(message)s")

lc = LiveControl()

async def waiting_phase():
    lc.phase = "Waiting for SLAC"
    # Hold here indefinitely — the parent kills us after the capture window.
    await asyncio.sleep(60)

asyncio.run(run_with_console(lc, waiting_phase(), source="EVCC"))
"""


def _capture_under_pty(secs: float) -> bytes:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.getcwd() + os.pathsep + env.get("PYTHONPATH", "")
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(sys.executable, [sys.executable, "-c", _CHILD], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    chunks = []
    cpr_re = re.compile(rb"\x1b\[6n")
    start = time.monotonic()
    while time.monotonic() - start < secs:
        try:
            r, _, _ = select.select([fd], [], [], 0.2)
        except OSError:
            break
        if not r:
            continue
        try:
            data = os.read(fd, 65536)
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
        if cpr_re.search(data):
            os.write(fd, b"\x1b[%d;1R" % ROWS)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
    return b"".join(chunks)


def test_phase_indicator_shows_waiting_for_slac_at_startup():
    """Footer contains ``Waiting for SLAC`` before any session traffic."""
    raw = _capture_under_pty(secs=2.0)
    assert b"AcCCS EVCC" in raw, "footer never rendered at all"

    screen = pyte.Screen(COLS, ROWS)
    stream = pyte.ByteStream(screen)
    stream.feed(raw)
    bottom = screen.display[-1]
    assert PHASE_MARK in bottom, (
        f"footer bottom row does not show {PHASE_MARK!r} at startup; got: {bottom!r}"
    )
