"""Regression tests for the idle-and-re-arm session lifecycle (ADR-0005, #41).

Two hazards the prior one-shot code never exercised, plus the SECC's new
one-cycle-per-handler contract:

1. SLAC must be safely *re-runnable*. ``start()`` is called once per session
   cycle, so it has to re-initialise every per-cycle flag — not just ``stop``.
   The EVCC handshake booleans were only ever cleared inside ``restart()``, and
   the SECC kept a stale ``runID`` that would filter out the next cycle's
   ``SLAC_PARM_REQ``.
2. The SECC receive loop must *return* to the controller after a terminated
   session (so the lifecycle loop can re-arm) instead of looping forever, while
   a PAUSE still keeps the loop alive for resume.

These run without CAP_NET_RAW by stubbing the socket/handshake seams.
"""

from __future__ import annotations

import asyncio
import types

import pytest

from app.evcc.transport.slac import SLACHandler as EvccSLAC
from app.secc.transport.slac import SLACHandler as SeccSLAC
from app.shared.messages.enums import SessionStopAction
from app.shared.notifications import StopNotification


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


class _DummySniffer:
    """Stand-in for scapy's AsyncSniffer so start() needs no real capture."""

    def __init__(self, *args, **kwargs):
        self.running = False

    def start(self):
        self.running = True

    def stop(self):
        self.running = False


class _DummySock:
    def bind(self, *_a):
        pass

    def settimeout(self, *_a):
        pass

    def close(self):
        pass


# -- SLAC start() re-runnability --------------------------------------------


def test_evcc_start_resets_handshake_flags(monkeypatch):
    """A second cycle must clear the handshake booleans a first cycle left True.

    Without this, ``handle_CM_ATTEN_CHAR_IND`` sees ``CM_ATTEN_CHAR_IND_recved``
    still True and skips sending ATTEN_CHAR_RES / SLAC_MATCH_REQ — the second
    SLAC stalls and never matches.
    """
    slac = EvccSLAC(_fake_evcc())
    # State left behind by a completed first SLAC cycle.
    slac.CM_ATTEN_CHAR_IND_recved = True
    slac.CM_START_ATTEN_CHAR_IND_sent = True
    slac.stopSounds = True
    slac.stop = True

    captured = {}

    def fake_handleSLAC():
        captured.update(
            recved=slac.CM_ATTEN_CHAR_IND_recved,
            sent=slac.CM_START_ATTEN_CHAR_IND_sent,
            stop_sounds=slac.stopSounds,
            stop=slac.stop,
        )
        slac.stop = True  # let the real timeout thread exit promptly

    monkeypatch.setattr("app.evcc.transport.slac.AsyncSniffer", _DummySniffer)
    slac.create_socket = lambda: None
    slac.handleSLAC = fake_handleSLAC

    slac.start()

    assert captured == {
        "recved": False,
        "sent": False,
        "stop_sounds": False,
        "stop": False,
    }


def test_secc_start_clears_stale_runid():
    """A second cycle must clear ``runID`` so the new PARM_REQ isn't filtered out.

    The EVCC draws a fresh RunID each cycle; if the SECC keeps the prior one,
    ``receive()`` rejects the new ``SLAC_PARM_REQ`` on RunID mismatch and the
    SECC never answers.
    """
    slac = SeccSLAC(_fake_secc())
    slac.runID = b"OLDRUNID"  # left from a prior cycle
    slac.stop = True

    captured = {}

    def fake_handleSLAC():
        captured["runID"] = slac.runID
        slac.stop = True

    slac.create_socket = lambda: None
    slac.handleSLAC = fake_handleSLAC

    slac.start()

    assert captured["runID"] is None


@pytest.mark.parametrize("handler_cls, fake", [(EvccSLAC, _fake_evcc()), (SeccSLAC, _fake_secc())])
def test_create_socket_closes_prior_socket(handler_cls, fake, monkeypatch):
    """Re-binding each cycle must close the prior socket so fds don't leak."""
    slac = handler_cls(fake)
    closed = []
    slac.sock = types.SimpleNamespace(close=lambda: closed.append(True))

    module = "app.evcc.transport.slac" if handler_cls is EvccSLAC else "app.secc.transport.slac"
    monkeypatch.setattr(f"{module}.socket.socket", lambda *a, **k: _DummySock())

    slac.create_socket()

    assert closed == [True]


# -- SECC receive loop: one cycle per handler -------------------------------


def _make_secc_handler():
    from app.secc.comm_session_handler import CommunicationSessionHandler

    dummy = object()
    codec = types.SimpleNamespace(get_version=lambda: "test")
    return CommunicationSessionHandler(config=dummy, codec=codec, evse_controller=dummy)


def test_secc_rcv_loop_returns_on_terminate():
    """A TERMINATE StopNotification ends the receive loop (controller re-arms)."""

    async def scenario():
        handler = _make_secc_handler()
        calls = []

        async def fake_end(peer, action):
            calls.append(action)

        handler.end_current_session = fake_end
        queue = handler._rcv_queue
        queue.put_nowait(
            StopNotification(True, "done", ("::1", 0), SessionStopAction.TERMINATE)
        )
        await asyncio.wait_for(handler.get_from_rcv_queue(queue), timeout=2)
        return calls

    calls = asyncio.run(scenario())
    assert calls == [SessionStopAction.TERMINATE]


def test_secc_rcv_loop_keeps_running_on_pause():
    """A PAUSE keeps the loop alive (resume on the same servers); TERMINATE ends it."""

    async def scenario():
        handler = _make_secc_handler()
        calls = []

        async def fake_end(peer, action):
            calls.append(action)

        handler.end_current_session = fake_end
        queue = handler._rcv_queue
        queue.put_nowait(
            StopNotification(True, "pause", ("::1", 0), SessionStopAction.PAUSE)
        )
        queue.put_nowait(
            StopNotification(True, "done", ("::1", 0), SessionStopAction.TERMINATE)
        )
        await asyncio.wait_for(handler.get_from_rcv_queue(queue), timeout=2)
        return calls

    calls = asyncio.run(scenario())
    assert calls == [SessionStopAction.PAUSE, SessionStopAction.TERMINATE]


def test_secc_unsupported_renegotiation_rearms_to_idle():
    """The ISO-20 unsupported-renegotiation path re-arms instead of pausing (#61).

    The ISO 15118-20 ``SessionStop`` state emits a TERMINATE StopNotification on
    this path (locked by
    ``tests/conformance/state_machine/secc/test_session_stop_lifecycle.py::
    test_iso20_unsupported_renegotiation_terminates``). This asserts the
    *handler* end of that contract: fed the TERMINATE action that path produces,
    the receive loop returns so the controller re-arms to idle rather than
    holding servers up for a resume the terminating next_state has foreclosed.
    """

    async def scenario():
        handler = _make_secc_handler()
        calls = []

        async def fake_end(peer, action):
            calls.append(action)

        handler.end_current_session = fake_end
        queue = handler._rcv_queue
        queue.put_nowait(
            StopNotification(
                True,
                "renegotiation unsupported",
                ("::1", 0),
                SessionStopAction.TERMINATE,
            )
        )
        await asyncio.wait_for(handler.get_from_rcv_queue(queue), timeout=2)
        return calls

    calls = asyncio.run(scenario())
    # The loop returned after a single TERMINATE -> controller re-arms to idle.
    assert calls == [SessionStopAction.TERMINATE]


# -- auto-rearm: re-arm without an operator advance (ADR-0005, issue #43) ----
#
# Build the controllers via __new__ so the heavy __init__ (personality load,
# NIC MAC lookup, logger) is skipped — these methods only touch live_control
# and the per-role _AUTO_REARM_DELAY_S class attribute.

from app.evcc.controller.pev import PEV  # noqa: E402
from app.secc.controller.evse import EVSE  # noqa: E402
from app.shared.live_control import LiveControl  # noqa: E402


@pytest.mark.parametrize("controller_cls", [PEV, EVSE])
def test_await_rearm_returns_immediately_when_auto_rearm_on(controller_cls):
    """With auto-rearm on, the idle wait must not block on an operator advance.

    No advance is signalled; the wait returns purely because `auto_rearm` is
    set, which is what lets a live `r` toggle (or the --auto-rearm flag) re-arm
    a side sitting in idle.
    """
    ctrl = controller_cls.__new__(controller_cls)
    ctrl.live_control = LiveControl(auto_rearm=True)

    async def scenario():
        await asyncio.wait_for(ctrl._await_rearm(), timeout=1.0)

    asyncio.run(scenario())  # would raise TimeoutError if it blocked


@pytest.mark.parametrize("controller_cls", [PEV, EVSE])
def test_await_rearm_blocks_until_advance_when_auto_rearm_off(controller_cls):
    """Default (auto-rearm off): the wait blocks until an advance is signalled."""
    ctrl = controller_cls.__new__(controller_cls)
    ctrl.live_control = LiveControl(auto_rearm=False)

    async def scenario():
        task = asyncio.ensure_future(ctrl._await_rearm())
        await asyncio.sleep(0.15)
        assert not task.done()  # still waiting — no advance yet
        ctrl.live_control.signal_advance()
        await asyncio.wait_for(task, timeout=1.0)

    asyncio.run(scenario())


def test_evcc_auto_rearm_delay_paces_between_cycles():
    """The EVCC inter-cycle delay is non-trivial so it can't hammer SLAC."""
    assert PEV._AUTO_REARM_DELAY_S >= 1.0

    pev = PEV.__new__(PEV)
    pev.live_control = LiveControl(auto_rearm=True)

    async def scenario():
        loop = asyncio.get_running_loop()
        start = loop.time()
        await pev._auto_rearm_delay()
        return loop.time() - start

    elapsed = asyncio.run(scenario())
    # Allow slack for the 0.05 s poll granularity, but it must actually wait.
    assert elapsed >= PEV._AUTO_REARM_DELAY_S - 0.1


def test_secc_auto_rearm_has_no_inter_cycle_delay():
    """The SECC just re-listens, so its auto-rearm delay is zero (ADR-0005)."""
    assert EVSE._AUTO_REARM_DELAY_S == 0.0

    evse = EVSE.__new__(EVSE)
    evse.live_control = LiveControl(auto_rearm=True)

    async def scenario():
        loop = asyncio.get_running_loop()
        start = loop.time()
        await evse._auto_rearm_delay()
        return loop.time() - start

    elapsed = asyncio.run(scenario())
    assert elapsed < 0.05  # returns essentially immediately


def test_auto_rearm_delay_breaks_promptly_on_quit():
    """An operator quit during the EVCC delay must break out without waiting it out."""
    pev = PEV.__new__(PEV)
    pev.live_control = LiveControl(auto_rearm=True)

    async def scenario():
        loop = asyncio.get_running_loop()
        task = asyncio.ensure_future(pev._auto_rearm_delay())
        await asyncio.sleep(0.1)
        pev.live_control.request_quit()
        start = loop.time()
        await asyncio.wait_for(task, timeout=1.0)
        return loop.time() - start

    # After quit is set the poll loop exits within a tick, well under the full delay.
    assert asyncio.run(scenario()) < 0.5


# -- re-arm re-asserts the "present" electrical state (issue #52) -------------
#
# The idle-and-re-arm loop drops each side to its idle electrical state at the
# end of a cycle (EVCC -> CP State A, SECC -> relay open). The pre-loop
# toggleProximity() asserts the "present" state once, but only for the first
# cycle; on re-arm the loop re-ran SLAC with the device still idle, so on real
# hardware the EVSE never detected the EV and cycle 2+ SLAC never engaged. The
# fix re-asserts "present" (EVCC closeProximity = CP State B, SECC closeProximity
# = relay closed) at the top of every cycle, guarded by `not self.virtual`.
#
# These drive the real `start()` lifecycle loop through two stubbed cycles and
# assert the call ordering — the per-cycle re-assert lands *before* each SLAC.


async def _drive_two_cycles(monkeypatch, *, role, virtual):
    """Run a controller's `start()` through two stubbed cycles; return the
    ordered list of proximity / SLAC events.

    The heavy session handler, SLAC handler, codec, and per-cycle controller are
    stubbed so no socket or capture is needed; the proximity/SLAC methods are
    replaced with recorders so we observe only the loop's call ordering. The
    fake session handler quits after the second cycle so the loop exits.
    """
    events: list[str] = []
    cycles = {"n": 0}

    async def _no_delay() -> None:  # skip the EVCC's 1.5 s inter-cycle pace
        return

    if role == "evcc":
        module = "app.evcc.controller.pev"
        ctrl = PEV.__new__(PEV)
        ctrl.evcc_config = object()
        ctrl.sourceMAC = "02:00:00:00:00:01"

        class _FakeHandler:
            def __init__(self, **_kwargs):
                pass

            async def start(self):
                events.append("session")
                cycles["n"] += 1
                if cycles["n"] >= 2:
                    ctrl.live_control.request_quit()

        monkeypatch.setattr(f"{module}.EVCCHandler", _FakeHandler)
        monkeypatch.setattr(f"{module}.SimEVController", lambda *a, **k: object())
    else:
        module = "app.secc.controller.evse"
        ctrl = EVSE.__new__(EVSE)
        ctrl.personality = object()
        ctrl.sourceMAC = "02:00:00:00:00:02"

        class _FakeController:
            def __init__(self, **_kwargs):
                pass

            async def set_status(self, _status):
                pass

        class _FakeHandler:
            def __init__(self, **_kwargs):
                pass

            async def start(self, _iface):
                events.append("session")
                cycles["n"] += 1
                if cycles["n"] >= 2:
                    ctrl.live_control.request_quit()

        monkeypatch.setattr(f"{module}.SimEVSEController", _FakeController)
        monkeypatch.setattr(f"{module}.SECCHandler", _FakeHandler)

    monkeypatch.setattr(f"{module}.SLACHandler", lambda _owner: object())
    monkeypatch.setattr(f"{module}.EXPyEXICodec", lambda *a, **k: object())

    ctrl.virtual = virtual
    ctrl.config = types.SimpleNamespace(iface="lo")
    ctrl.slac = None
    ctrl.live_control = LiveControl(console_enabled=False, auto_rearm=True)
    ctrl.bus = types.SimpleNamespace(write_byte_data=lambda *a, **k: None)
    ctrl.I2C_ADDR = 0x20
    ctrl.toggleProximity = lambda *a, **k: events.append("toggle")
    ctrl.closeProximity = lambda: events.append("close")
    ctrl.openProximity = lambda: events.append("open")
    ctrl.doSLAC = lambda: events.append("slac")
    ctrl._auto_rearm_delay = _no_delay

    await asyncio.wait_for(ctrl.start(), timeout=5)
    return events


@pytest.mark.parametrize("role", ["evcc", "secc"])
def test_rearm_reasserts_present_before_every_slac(role, monkeypatch):
    """On real hardware, each cycle (incl. re-arm) closes proximity before SLAC.

    Two cycles run; every SLAC must be immediately preceded by a closeProximity
    (CP State B / relay closed). Without the fix the second cycle re-ran SLAC
    straight from the idle state and the count of pre-SLAC closes would be 1.
    """
    events = asyncio.run(_drive_two_cycles(monkeypatch, role=role, virtual=False))

    slac_indices = [i for i, e in enumerate(events) if e == "slac"]
    assert len(slac_indices) == 2  # two full cycles ran
    # Every SLAC — first cycle and the re-armed second — is preceded by a close.
    assert all(events[i - 1] == "close" for i in slac_indices)
    assert events.count("close") == 2


@pytest.mark.parametrize("role", ["evcc", "secc"])
def test_rearm_present_reassert_is_noop_under_virtual(role, monkeypatch):
    """`--virtual` skips the presence re-assert (and the pre-loop toggle).

    The guard keeps the virtual demo's log/electrical-call stream unchanged:
    closeProximity and toggleProximity must never fire, while the loop still
    runs SLAC each cycle.
    """
    events = asyncio.run(_drive_two_cycles(monkeypatch, role=role, virtual=True))

    assert "close" not in events
    assert "toggle" not in events
    assert events.count("slac") == 2  # the lifecycle loop still cycled
