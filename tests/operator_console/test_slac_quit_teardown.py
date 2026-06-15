"""Regression tests for operator-quit SLAC teardown (issue #40).

Pressing 'q' must stop the SLAC handler whose blocking ``recv()`` and timeout
thread run in a thread pool that asyncio task-cancellation cannot reach. Before
the fix, 'q' tore down only the TUI while SLAC kept retransmitting and the
process hung on the executor join. These tests pin the teardown contract at the
transport seam without needing raw sockets (CAP_NET_RAW), so they run in CI.

The threaded tests are the faithful regression: a thread parked in the real
``handleSLAC`` recv loop must terminate quickly after ``stop_handler()`` is
called from another thread — exactly the path the operator-console quit hook
drives.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
import types

import pytest

from app.evcc.transport.slac import SLACHandler as EvccSLAC
from app.secc.transport.slac import SLACHandler as SeccSLAC


def _fake_evcc():
    return types.SimpleNamespace(
        iface="lo",
        sourceMAC="02:00:00:00:00:01",
        sourceIP="fe80::2",
        slacSoundTimeout=1000,
    )


def _fake_secc():
    return types.SimpleNamespace(
        iface="lo",
        sourceMAC="02:00:00:00:00:02",
        NID=b"\x00" * 7,
        NMK=b"\x00" * 16,
    )


# -- stop_handler contract (fast, no threads) -------------------------------


@pytest.mark.parametrize(
    "handler_cls, fake",
    [(EvccSLAC, _fake_evcc()), (SeccSLAC, _fake_secc())],
)
def test_stop_handler_sets_flag_and_closes_socket(handler_cls, fake):
    slac = handler_cls(fake)
    closed = []
    slac.sock = types.SimpleNamespace(close=lambda: closed.append(True))

    slac.stop_handler()

    assert slac.stop is True
    assert closed == [True]


@pytest.mark.parametrize(
    "handler_cls, fake",
    [(EvccSLAC, _fake_evcc()), (SeccSLAC, _fake_secc())],
)
def test_stop_handler_idempotent_and_socket_optional(handler_cls, fake):
    """Quit during a phase where SLAC already finished (sock is None) is a no-op."""
    slac = handler_cls(fake)
    slac.sock = None
    slac.stop_handler()  # must not raise
    assert slac.stop is True


def test_evcc_stop_handler_stops_sniffer():
    slac = EvccSLAC(_fake_evcc())
    slac.sock = types.SimpleNamespace(close=lambda: None)
    stopped = []
    slac.neighborSolicitationThread = types.SimpleNamespace(
        running=True, stop=lambda: stopped.append(True)
    )
    slac.stop_handler()
    assert stopped == [True]


# -- receive() three-way OSError split (issue #51) --------------------------


def _sock_recv_raises(exc):
    def _raise(_n):
        raise exc

    return types.SimpleNamespace(recv=_raise)


@pytest.mark.parametrize(
    "handler_cls, fake",
    [(EvccSLAC, _fake_evcc()), (SeccSLAC, _fake_secc())],
)
def test_receive_timeout_is_idle(handler_cls, fake):
    """The 0.5s poll timeout is ordinary idle: None, and not treated as failure."""
    slac = handler_cls(fake)
    slac.sock = _sock_recv_raises(socket.timeout())
    assert slac.receive() is None
    assert slac.stop is False  # a poll wake must not end the SLAC loop


@pytest.mark.parametrize(
    "handler_cls, fake",
    [(EvccSLAC, _fake_evcc()), (SeccSLAC, _fake_secc())],
)
def test_receive_quit_close_is_clean(handler_cls, fake):
    """A close raced by stop_handler (quit set) is a clean exit, not a failure."""
    slac = handler_cls(fake)
    slac.quit = True
    slac.stop = True
    slac.sock = _sock_recv_raises(OSError("bad fd"))
    assert slac.receive() is None


@pytest.mark.parametrize(
    "handler_cls, fake",
    [(EvccSLAC, _fake_evcc()), (SeccSLAC, _fake_secc())],
)
def test_receive_surfaces_genuine_error(handler_cls, fake, caplog):
    """A genuine socket failure on a live run must be surfaced, not masked as idle."""
    slac = handler_cls(fake)
    slac.sock = _sock_recv_raises(OSError(100, "Network is down"))
    with caplog.at_level(logging.ERROR, logger="SLAC"):
        assert slac.receive() is None
    assert slac.stop is True  # ended the loop rather than spin on a dead link
    assert "socket error" in caplog.text.lower()


# -- _send() guards the quit-close race (issue #51) -------------------------


@pytest.mark.parametrize(
    "handler_cls, fake",
    [(EvccSLAC, _fake_evcc()), (SeccSLAC, _fake_secc())],
)
def test_send_tolerates_quit_close(handler_cls, fake):
    """A send racing a real stop_handler close must not raise an OSError traceback.

    Uses a real socketpair so the OSError is the genuine EBADF from the kernel,
    not a mock — the exact condition a 'q' during the handshake produces.
    """
    ours, peer = socket.socketpair()
    slac = handler_cls(fake)
    slac.sock = ours
    slac.stop_handler()  # closes ours, sets quit + stop
    assert slac._send(b"\x00") is False  # swallowed, no exception escapes
    peer.close()


@pytest.mark.parametrize(
    "handler_cls, fake",
    [(EvccSLAC, _fake_evcc()), (SeccSLAC, _fake_secc())],
)
def test_send_surfaces_genuine_error(handler_cls, fake, caplog):
    """A send failure on a live run (no quit) is surfaced and ends the loop."""
    slac = handler_cls(fake)

    def _raise(_n):
        raise OSError(100, "Network is down")

    slac.sock = types.SimpleNamespace(send=_raise)
    with caplog.at_level(logging.ERROR, logger="SLAC"):
        assert slac._send(b"\x00") is False
    assert slac.stop is True
    assert "socket error" in caplog.text.lower()


# -- threaded unblock: the actual bug pattern -------------------------------


@pytest.mark.parametrize(
    "handler_cls, fake",
    [(EvccSLAC, _fake_evcc()), (SeccSLAC, _fake_secc())],
)
def test_handleSLAC_loop_terminates_after_stop_handler(handler_cls, fake):
    """A thread parked in the real recv loop must end shortly after stop_handler.

    Uses a socketpair (no CAP_NET_RAW): our end never receives, so recv blocks
    until the 0.5s timeout, which is what lets the loop observe ``stop``. Before
    the fix the loop had no timeout and ``stop`` was never set, so the thread —
    and the process — hung forever.
    """
    ours, _peer = socket.socketpair()
    ours.settimeout(0.5)
    slac = handler_cls(fake)
    slac.sock = ours
    # SECC's checkForTimeout would send on a 8s timer; the recv loop is the part
    # under test, so run handleSLAC directly in the worker.
    worker = threading.Thread(target=slac.handleSLAC, daemon=True)
    worker.start()

    # Give the loop a moment to reach its first blocking recv.
    worker.join(0.2)
    assert worker.is_alive(), "loop should still be parked in recv before quit"

    slac.stop_handler()
    worker.join(2.0)
    assert not worker.is_alive(), "recv loop did not terminate after stop_handler"

    _peer.close()


# -- start() re-arm race: 'q' in the executor spin-up window ----------------


@pytest.mark.parametrize(
    "handler_cls, fake",
    [(EvccSLAC, _fake_evcc()), (SeccSLAC, _fake_secc())],
)
def test_start_is_a_noop_after_quit(handler_cls, fake):
    """A quit that lands before start() runs must not be re-armed away.

    Reproduces the startup-window race: doSLAC runs in a thread-pool worker, so
    'q' (via stop_handler) can fire before the worker reaches start(). start()
    used to unconditionally reset ``stop = False`` and loop SLAC forever, hanging
    the process on the executor join. It must now observe the sticky ``quit``
    flag and return without arming — no socket, no SLAC loop, no timeout thread.
    """
    slac = handler_cls(fake)
    armed = []
    slac.create_socket = lambda: armed.append("socket")
    slac.handleSLAC = lambda: armed.append("handleSLAC")

    slac.stop_handler()  # operator quit during executor spin-up
    slac.start()  # the re-arm that previously clobbered the quit

    assert armed == [], "start() armed SLAC despite an in-flight quit"
    assert slac.quit is True  # quit is sticky — start() must not clear it
    assert slac.stop is True  # and the per-cycle stop was not reset to False


@pytest.mark.parametrize(
    "handler_cls, fake",
    [(EvccSLAC, _fake_evcc()), (SeccSLAC, _fake_secc())],
)
def test_checkForTimeout_terminates_on_quit(handler_cls, fake):
    """The timeout thread must exit on a quit even if ``stop`` is False.

    This is the precise re-arm-race condition: start() resets ``stop = False``
    and only then does the quit land, so a checkForTimeout loop keyed solely on
    ``stop`` would spin forever (a non-daemon thread blocking the process exit).
    Setting only ``quit`` here — leaving ``stop`` False — pins that the loop now
    also honours the sticky quit flag.
    """
    slac = handler_cls(fake)
    slac.timeout = 999  # never trip the retransmit branch during the test
    slac.timeSinceLastPkt = int(time.time())
    slac.stop = False  # as start() leaves it after re-arming

    worker = threading.Thread(target=slac.checkForTimeout, daemon=True)
    worker.start()
    worker.join(0.1)
    assert worker.is_alive(), "timeout loop should still be running before quit"

    slac.quit = True  # quit lands after the stop reset (the race)
    worker.join(2.0)
    assert not worker.is_alive(), "checkForTimeout did not exit on quit"
