"""Process-lifecycle helpers for the emulator entrypoints.

The run scripts are typically launched via `sudo` from a developer shell or
agent harness. If that parent dies (shell closes, agent moves on) the
emulator is reparented to PID 1 and keeps holding raw sockets — most
visibly the SDP port — which then blocks subsequent runs with
``[Errno 98] Address already in use``.

`die_with_parent` arranges for the kernel to deliver SIGTERM to the
calling process the moment its parent exits, so orphans never survive
their launcher. Linux-only (uses `prctl(PR_SET_PDEATHSIG)`); a no-op on
other platforms.
"""

from __future__ import annotations

import ctypes
import signal
import sys

# include/linux/prctl.h
_PR_SET_PDEATHSIG = 1


def die_with_parent(sig: int = signal.SIGTERM) -> None:
    if sys.platform != "linux":
        return
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    if libc.prctl(_PR_SET_PDEATHSIG, sig, 0, 0, 0) != 0:
        # Non-fatal: the emulator still runs, just without auto-reap.
        pass
