"""The footer stays pinned at the bottom under a real high-rate log flood.

This is the regression test for the issue #28 audit's BLOCKING finding:
acceptance criterion #1 ("a pinned footer; log output scrolls cleanly above
it") was unmet because the original `patch_stdout()` footer was overwritten by
the ~2000 log-lines/s of the ISO-2 DC CurrentDemand loop and visible <2% of the
time. The full-screen TUI repaints logs+footer atomically, so the footer is
present in essentially every frame.

The check has to be end-to-end through a real terminal, because the failure was
purely a rendering one (the prior rebind/keybinding unit tests all passed while
the footer was still invisible). So we drive the *real* `run_with_console`
under a pty that answers Cursor-Position-Report queries and has a window size —
exactly what a terminal emulator does — flood it with logs, then replay the
captured byte stream through `pyte` (a terminal emulator) and assert the footer
occupies the bottom row in the large majority of sampled frames. Run against
the old `patch_stdout` implementation this asserts ~2%; against the full-screen
one it asserts >90%.
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
FOOTER_MARK = "charge-loop stall"

# Runs in the pty child: set up stdout logging the way the app does (a
# StreamHandler bound to sys.stdout, built *before* the console starts), then
# drive `run_with_console` with a coroutine that floods logs like the
# CurrentDemand loop. Kept as source so the child is a fresh interpreter with a
# real (pty) TTY on stdout.
_CHILD = r"""
import asyncio, logging, sys
from app.shared.console import run_with_console
from app.shared.live_control import LiveControl

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("flood")

async def flood():
    i = 0
    while True:
        for _ in range(20):
            log.info("CurrentDemand cycle %d: present_voltage=500 present_current=1", i)
            i += 1
        await asyncio.sleep(0.005)

asyncio.run(run_with_console(LiveControl(stall_charge_loop=True), flood(), source="EVCC"))
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
        if cpr_re.search(data):  # answer CPR like a real terminal
            os.write(fd, b"\x1b[%d;1R" % ROWS)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
    return b"".join(chunks)


def _bottom_row_visibility(raw: bytes, samples: int = 40) -> float:
    """Fraction of evenly-spaced time slices whose bottom screen row is the footer."""
    n = len(raw)
    hits = 0
    for k in range(1, samples + 1):
        screen = pyte.Screen(COLS, ROWS)
        stream = pyte.ByteStream(screen)
        stream.feed(raw[: (n * k) // samples])
        if FOOTER_MARK in screen.display[-1]:
            hits += 1
    return hits / samples


def test_footer_stays_pinned_under_log_flood():
    raw = _capture_under_pty(secs=3.0)
    assert b"AcCCS EVCC" in raw, "footer never rendered at all"
    visibility = _bottom_row_visibility(raw)
    # Full-screen TUI: footer is in essentially every frame (real app measured
    # ~0.97). patch_stdout scored ~0.02 here. 0.8 cleanly separates the two.
    assert visibility >= 0.8, (
        f"footer pinned to the bottom row in only {visibility:.0%} of sampled frames "
        f"(expected >=80%); the footer is being clobbered by the log flood"
    )
