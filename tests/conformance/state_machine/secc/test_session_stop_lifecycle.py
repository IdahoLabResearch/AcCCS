"""SECC SessionStop -> idle-and-re-arm parity for DIN and ISO 15118-20 (#42).

The idle-and-re-arm lifecycle (ADR-0005) re-arms a side only when a session
*cycle* ends. On the SECC that decision is made in the receive loop, which
returns to the controller's lifecycle loop on a ``SessionStopAction.TERMINATE``
StopNotification and keeps the loop alive on ``PAUSE`` (see
``tests/operator_console/test_session_lifecycle.py``). What feeds that loop is
each protocol's ``SessionStop`` state: it sets ``comm_session.stop_reason`` (the
StopNotification whose ``stop_action`` the receive loop keys off) and the
``next_state`` that the shared ``rcv_loop`` checks against ``(Terminate, Pause)``
to decide whether the session cycle is over at all.

#41 proved this for ISO 15118-2 DC. This module locks the *remaining* protocol
paths in #42's scope at the ADR-0003 state-machine seam:

* **DIN SPEC 70121** — a SessionStopReq always terminates the cycle.
* **ISO 15118-20** — ``ChargingSession.TERMINATE`` terminates; a
  ``SERVICE_RENEGOTIATION`` the SECC supports routes back to ServiceDiscovery
  (next_state is *neither* Terminate nor Pause, so the shared rcv_loop keeps the
  session alive and the controller does **not** re-arm — a clean end-of-cycle
  still has to arrive via a later TERMINATE); a plain ``PAUSE`` keeps the
  servers up for resume rather than terminating.

The composition assertion for the renegotiation path (AC2) is the
``next_state is ServiceDiscovery`` check: because the shared rcv_loop only ends
a cycle on ``next_state in (Terminate, Pause)``, routing to ServiceDiscovery is
exactly what makes renegotiation compose with re-arm instead of tripping it.
"""

from __future__ import annotations

import types
from time import time

import pytest

from app.secc.controller.simulator import SimEVSEController
from app.shared.messages.enums import Protocol, SessionStopAction
from app.shared.states import Terminate
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession


def _stub_writer() -> types.SimpleNamespace:
    """SessionStop reads the peer name off the transport writer for logging."""
    return types.SimpleNamespace(get_extra_info=lambda _name: ("::1", 0))


# -- DIN SPEC 70121 ---------------------------------------------------------


@pytest.mark.asyncio
async def test_din_session_stop_terminates_cycle(exi_codec):
    """A DIN SessionStopReq ends the cycle: TERMINATE action, next_state Terminate."""
    from app.secc.states.din_spec_states import SessionStop
    from app.shared.messages.din_spec.body import Body, SessionStopReq
    from app.shared.messages.din_spec.header import MessageHeader
    from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC

    session = StubCommSession(
        protocol=Protocol.DIN_SPEC_70121, session_id=bytes(1).hex()
    )
    session.evse_controller = SimEVSEController()
    session.writer = _stub_writer()
    peer = ScriptedPeer(session, start_state=SessionStop)

    req = V2GMessageDINSPEC(
        header=MessageHeader(session_id=session.session_id),
        body=Body(session_stop_req=SessionStopReq()),
    )
    result = await peer.feed(req)

    assert result.next_state is Terminate
    assert session.stop_reason is not None
    assert session.stop_reason.stop_action == SessionStopAction.TERMINATE


# -- ISO 15118-20 -----------------------------------------------------------


def _iso20_session(*, renegotiation_supported: bool) -> StubCommSession:
    controller = SimEVSEController()
    controller.set_selected_protocol(Protocol.ISO_15118_20_COMMON_MESSAGES)
    if renegotiation_supported:
        async def _supported() -> bool:
            return True

        controller.service_renegotiation_supported = _supported  # type: ignore[method-assign]
    session = StubCommSession(
        protocol=Protocol.ISO_15118_20_COMMON_MESSAGES, session_id=bytes(1).hex()
    )
    session.evse_controller = controller
    session.writer = _stub_writer()
    return session


def _iso20_stop_req(session: StubCommSession, charging_session):
    from app.shared.messages.iso15118_20.common_messages import SessionStopReq
    from app.shared.messages.iso15118_20.common_types import MessageHeader

    return SessionStopReq(
        header=MessageHeader(session_id=session.session_id, timestamp=int(time())),
        charging_session=charging_session,
    )


@pytest.mark.asyncio
async def test_iso20_terminate_ends_cycle(exi_codec):
    """ChargingSession.TERMINATE ends the cycle: TERMINATE action, next_state Terminate."""
    from app.secc.states.iso15118_20_states import SessionStop
    from app.shared.messages.iso15118_20.common_messages import ChargingSession

    session = _iso20_session(renegotiation_supported=False)
    peer = ScriptedPeer(session, start_state=SessionStop)

    result = await peer.feed(_iso20_stop_req(session, ChargingSession.TERMINATE))

    assert result.next_state is Terminate
    assert session.stop_reason.stop_action == SessionStopAction.TERMINATE


@pytest.mark.asyncio
async def test_iso20_service_renegotiation_routes_to_service_discovery(exi_codec):
    """A supported SERVICE_RENEGOTIATION composes with re-arm by NOT ending the cycle.

    next_state is ServiceDiscovery — neither Terminate nor Pause — so the shared
    rcv_loop keeps the session alive and the controller stays out of idle. The
    stop_action is PAUSE, but it is never delivered to the handler queue on this
    path (the rcv_loop only enqueues a StopNotification when next_state is
    Terminate/Pause), so re-arm is not tripped mid-renegotiation.
    """
    from app.secc.states.iso15118_20_states import ServiceDiscovery, SessionStop
    from app.shared.messages.iso15118_20.common_messages import ChargingSession

    session = _iso20_session(renegotiation_supported=True)
    peer = ScriptedPeer(session, start_state=SessionStop)

    result = await peer.feed(
        _iso20_stop_req(session, ChargingSession.SERVICE_RENEGOTIATION)
    )

    assert result.next_state is ServiceDiscovery
    assert result.next_state is not Terminate
    assert session.stop_reason.stop_action == SessionStopAction.PAUSE


@pytest.mark.asyncio
async def test_iso20_unsupported_renegotiation_terminates(exi_codec):
    """If the SECC does not support renegotiation, the request cannot route back.

    next_state falls through to Terminate (the default), so the shared rcv_loop
    ends the cycle rather than hanging waiting for a ServiceDiscoveryReq the SECC
    never offered to accept. The StopNotification must label this TERMINATE to
    match: a PAUSE here would tell the *handler* to keep servers up for a resume
    that the terminating next_state has already foreclosed (the inconsistency
    fixed in #61). Locking stop_action == TERMINATE alongside next_state keeps
    the two ends of this path agreeing.
    """
    from app.secc.states.iso15118_20_states import SessionStop
    from app.shared.messages.iso15118_20.common_messages import ChargingSession

    session = _iso20_session(renegotiation_supported=False)
    peer = ScriptedPeer(session, start_state=SessionStop)

    result = await peer.feed(
        _iso20_stop_req(session, ChargingSession.SERVICE_RENEGOTIATION)
    )

    assert result.next_state is Terminate
    assert session.stop_reason.stop_action == SessionStopAction.TERMINATE


@pytest.mark.asyncio
async def test_iso20_pause_keeps_servers_for_resume(exi_codec):
    """ChargingSession.PAUSE pauses (next_state Terminate leaf) with a PAUSE action.

    The PAUSE action is what keeps the SECC receive loop alive for a resume on
    the same servers (the rcv-loop test asserts that half); here we lock that
    the ISO-20 SessionStop state emits PAUSE, not TERMINATE, for a pause request.
    """
    from app.secc.states.iso15118_20_states import SessionStop
    from app.shared.messages.iso15118_20.common_messages import ChargingSession

    session = _iso20_session(renegotiation_supported=False)
    peer = ScriptedPeer(session, start_state=SessionStop)

    result = await peer.feed(_iso20_stop_req(session, ChargingSession.PAUSE))

    assert session.stop_reason.stop_action == SessionStopAction.PAUSE
    assert result.next_state is Terminate
