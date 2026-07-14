"""The SECC's SLAC re-key must fire *during* the wait for a vehicle (issue #90).

``start()`` used to run the timeout/re-key thread only after ``handleSLAC()``
returned, but ``handleSLAC()`` parks in its receive loop until SLAC completes or
the operator quits. The periodic ``SET_KEY_REQ`` retransmit therefore never
fired during the one window it exists to cover: a SECC waiting for a car whose
initial key exchange was lost sat silent forever instead of re-keying.

These tests pin the re-key running concurrently with the receive loop, and the
timer thread being reaped at the end of each cycle so a re-armed cycle
(ADR-0005) cannot leave one behind. They use a socketpair rather than a raw
socket, so they need no CAP_NET_RAW and run in CI.
"""

from __future__ import annotations

import socket
import threading
import time
import types

from app.secc.transport.slac import SLACHandler as SeccSLAC


def _fake_secc():
    return types.SimpleNamespace(
        iface="lo",
        sourceMAC="02:00:00:00:00:02",
        NID=b"\x00" * 7,
        NMK=b"\x00" * 16,
    )


def _armed_slac(sent):
    """A handler wired to a socketpair, its sends recorded instead of transmitted.

    ``timeout = -1`` makes every poll tick of the re-key timer read as expired,
    so the test observes retransmits in milliseconds rather than waiting out the
    real 8s deadline. Our end of the pair never receives, so ``handleSLAC``
    stays parked in ``recv()`` exactly as it does while waiting for a vehicle.
    """
    ours, peer = socket.socketpair()
    ours.settimeout(0.5)
    slac = SeccSLAC(_fake_secc())
    slac.create_socket = lambda: setattr(slac, "sock", ours)
    slac.timeout = -1
    slac._send = lambda pkt: (sent.append(pkt), True)[1]
    return slac, peer


def _wait_until(predicate, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_rekey_fires_while_the_recv_loop_is_still_parked():
    """The retransmit must land while SLAC is *waiting*, not after it ends."""
    sent = []
    slac, peer = _armed_slac(sent)

    worker = threading.Thread(target=slac.start, daemon=True)
    worker.start()
    try:
        assert _wait_until(lambda: len(sent) >= 3), (
            f"expected repeated SET_KEY_REQ during the SLAC wait, saw {len(sent)}"
        )
        # The whole point of the fix: the loop is still parked in recv(), so
        # these retransmits happened *during* the wait for the vehicle.
        assert worker.is_alive()
        assert all(pkt.haslayer("CM_SET_KEY_REQ") for pkt in sent)
    finally:
        slac.stop_handler()
        worker.join(2.0)
        peer.close()

    assert not worker.is_alive(), "SLAC did not tear down after stop_handler"


def test_rekey_thread_is_reaped_when_the_cycle_ends():
    """No timer thread outlives its cycle — a re-arm must not stack them (ADR-0005)."""
    sent = []
    slac, peer = _armed_slac(sent)

    worker = threading.Thread(target=slac.start, daemon=True)
    worker.start()
    try:
        assert _wait_until(lambda: slac.timeoutThread.is_alive())
    finally:
        slac.stop_handler()
        worker.join(2.0)
        peer.close()

    assert not worker.is_alive()
    assert not slac.timeoutThread.is_alive(), "re-key thread leaked past the cycle"


def test_quit_during_the_slac_wait_stops_the_rekey():
    """Operator quit teardown still holds with the timer running (issues #40 / #51).

    A 'q' during the SLAC wait now races a live timer thread that is actively
    sending on the socket ``stop_handler`` closes. That send must be swallowed,
    both threads must end, and no traceback may escape.
    """
    sent = []
    slac, peer = _armed_slac(sent)
    # Send against the real (closable) socket so the quit-close race is genuine
    # rather than stubbed away.
    del slac._send

    worker = threading.Thread(target=slac.start, daemon=True)
    worker.start()
    assert _wait_until(lambda: slac.timeoutThread.is_alive())

    slac.stop_handler()  # closes the socket under both threads

    worker.join(2.0)
    assert not worker.is_alive(), "SLAC loop did not end on quit"
    assert not slac.timeoutThread.is_alive(), "re-key thread did not end on quit"
    assert slac.quit is True  # sticky: a re-arm must not undo the quit
    peer.close()
