"""The EVCC SLAC run ignores a deviating CM_SLAC_PARM.CNF and never leaves a
timer thread behind (issue #137, conformance review SC-047).

ISO 15118-3 fixes the sound count at 10 (Table A.1, C_EV_match_MNBC) and says
a parameter confirmation with deviating content is to be ignored
([V2G3-A09-09]; DIN [V2G-DC-591]). The EVCC used to trust ``NUM_SOUNDS`` as
sent: a zero drove the sound countdown negative, the frame packing raised
inside the SLAC thread, and because ``start()`` had no cleanup the timeout
thread kept re-sending CM_SLAC_PARM.REQ forever and stacked onto the next
cycle. A count that cannot work (zero, or more than the configured sound
timeout lets us send) is now ignored; any other deviation from 10 is
tolerated and logged once. Two seams: ``handle_CM_SLAC_PARM_CNF`` (the frame is ignored) and
``start()`` (the timer thread is reaped however the run ends), with the raw
socket replaced by a socketpair and the sniffer by a stub so no CAP_NET_RAW
is needed.
"""

from __future__ import annotations

import logging
import socket
import threading
import types

import pytest

from app.evcc.transport import slac as evcc_slac
from app.evcc.transport.slac import SOUND_INTERVAL_MS, SLACHandler
from external_libs.HomePlugPWN.layerscapy.HomePlugGP import (
    CM_SLAC_PARM_CNF,
    Ether,
    HomePlugAV,
)
from tests.conformance.out_of_spec_log import (
    OUT_OF_SPEC_LOGGER,
    assert_single_out_of_spec_warning,
    out_of_spec_records,
)

CHARGER_MAC = "02:00:00:00:00:02"
SOUND_TIMEOUT_MS = 1000
# Most sounds the sound phase can send before the personality's sound timeout.
MAX_SENDABLE_SOUNDS = SOUND_TIMEOUT_MS // SOUND_INTERVAL_MS


def _fake_pev():
    return types.SimpleNamespace(
        iface="lo",
        sourceMAC="02:00:00:00:00:01",
        sourceIP="fe80::2",
        slacSoundTimeout=SOUND_TIMEOUT_MS,
        destinationMAC=None,
    )


def _recording_handler():
    sent = []
    slac = SLACHandler(_fake_pev())
    slac._send = lambda pkt: (sent.append(pkt), True)[1]
    return slac, sent


def _parm_cnf(slac: SLACHandler, number_of_sounds: int):
    return (
        Ether(src=CHARGER_MAC, dst=slac.sourceMAC)
        / HomePlugAV()
        / CM_SLAC_PARM_CNF(NumberMSounds=number_of_sounds, RunID=slac.runID)
    )


# -- NUM_SOUNDS is validated before anything is sent --------------------------


@pytest.mark.parametrize("number_of_sounds", [0, MAX_SENDABLE_SOUNDS + 1, 255])
def test_unworkable_sound_count_is_ignored(number_of_sounds, caplog):
    slac, sent = _recording_handler()
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        slac.handle_CM_SLAC_PARM_CNF(_parm_cnf(slac, number_of_sounds))

    assert sent == [], "an ignored CM_SLAC_PARM.CNF must not start the sound phase"
    assert slac.pev.destinationMAC is None, "an ignored frame must not pair us"
    assert slac.CM_START_ATTEN_CHAR_IND_sent is False
    assert_single_out_of_spec_warning(
        caplog, "CM_SLAC_PARM_CNF", "NUM_SOUNDS", number_of_sounds
    )


def test_tolerated_deviation_from_ten_sounds_is_logged_once(caplog):
    slac, sent = _recording_handler()
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        slac.handle_CM_SLAC_PARM_CNF(_parm_cnf(slac, 8))

    assert slac.pev.destinationMAC == CHARGER_MAC
    assert len([pkt for pkt in sent if pkt.haslayer("CM_MNBC_SOUND_IND")]) == 8
    assert_single_out_of_spec_warning(caplog, "CM_SLAC_PARM_CNF", "NUM_SOUNDS", 8, 10)


def test_spec_sound_count_still_runs_the_sound_phase(caplog):
    slac, sent = _recording_handler()
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        slac.handle_CM_SLAC_PARM_CNF(_parm_cnf(slac, 10))

    assert slac.pev.destinationMAC == CHARGER_MAC
    assert [pkt.haslayer("CM_START_ATTEN_CHAR_IND") for pkt in sent[:3]] == [True] * 3
    sounds = [pkt for pkt in sent if pkt.haslayer("CM_MNBC_SOUND_IND")]
    assert len(sounds) == 10
    assert sounds[-1]["CM_MNBC_SOUND_IND"].Countdown == 0
    assert out_of_spec_records(caplog) == []


# -- start() reaps its timer thread however the run ends ----------------------


class _StubSniffer:
    """Stands in for scapy's AsyncSniffer, which needs a raw socket."""

    instances: list = []

    def __init__(self, **_kwargs):
        self.running = False
        _StubSniffer.instances.append(self)

    def start(self):
        self.running = True

    def stop(self):
        self.running = False


def _armed_for_start(monkeypatch):
    monkeypatch.setattr(evcc_slac, "AsyncSniffer", _StubSniffer)
    _StubSniffer.instances.clear()
    ours, peer = socket.socketpair()
    ours.settimeout(0.5)
    slac = SLACHandler(_fake_pev())
    slac.create_socket = lambda: setattr(slac, "sock", ours)
    slac.timeout = 999  # the retransmit branch is not under test here
    return slac, peer


def test_exception_inside_the_run_does_not_leave_a_timer_thread(monkeypatch):
    slac, peer = _armed_for_start(monkeypatch)

    def failing_handle_slac():
        raise RuntimeError("forced SLAC failure")

    slac.handleSLAC = failing_handle_slac
    try:
        with pytest.raises(RuntimeError, match="forced SLAC failure"):
            slac.start()
    finally:
        peer.close()

    assert not slac.timeoutThread.is_alive(), (
        "the timeout thread outlived a failed SLAC run and would keep sending "
        "CM_SLAC_PARM.REQ into the next cycle"
    )
    assert slac.stop is True
    assert all(not sniffer.running for sniffer in _StubSniffer.instances)
    # The run's failure is per cycle: an operator quit was not implied.
    assert slac.quit is False


def test_zero_sounds_on_a_live_run_leaves_the_loop_waiting(monkeypatch):
    """End to end on the real receive loop: the frame is ignored, nothing is
    sent, and the run keeps waiting for a usable confirmation."""
    slac, peer = _armed_for_start(monkeypatch)
    sent = []
    slac._send = lambda pkt: (sent.append(pkt), True)[1]

    worker = threading.Thread(target=slac.start, daemon=True)
    worker.start()
    try:
        peer.send(bytes(_parm_cnf(slac, 0)))
        worker.join(0.5)
        assert worker.is_alive(), "the SLAC run must survive a zero-sound CNF"
        assert all(pkt.haslayer("CM_SLAC_PARM_REQ") for pkt in sent), (
            "only the opening CM_SLAC_PARM.REQ may have gone out"
        )
    finally:
        slac.stop_handler()
        worker.join(2.0)
        peer.close()

    assert not worker.is_alive()
    assert not slac.timeoutThread.is_alive()
