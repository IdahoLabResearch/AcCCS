"""EVCC ISO 15118-20 SessionStop routing -> idle-and-re-arm parity (#42).

The SECC half of the renegotiation composition is locked in
``tests/conformance/state_machine/secc/test_session_stop_lifecycle.py``; this is
the EVCC mirror. The EVCC's ISO-20 ``SessionStop`` state decides, on receiving a
SessionStopRes, whether to loop back to ServiceDiscovery (renegotiation) or fall
through to Terminate — driven by its own stored intent
(``renegotiation_requested`` + ``service_renegotiation_supported``), not by any
field on the response.

Routing to ServiceDiscovery (neither Terminate nor Pause) is what keeps the
EVCC's session cycle alive across a renegotiation, so the controller's
lifecycle loop does not drop to idle mid-renegotiation; a genuine end-of-cycle
falls through to Terminate, which ends the cycle and returns the EVCC to idle.
"""

from __future__ import annotations

import types
from time import time

import pytest

from app.evcc.states.iso15118_20_states import ServiceDiscovery, SessionStop
from app.shared.messages.enums import Protocol, SessionStopAction
from app.shared.messages.iso15118_20.common_messages import (
    ChargingSession,
    SessionStopRes,
)
from app.shared.messages.iso15118_20.common_types import MessageHeader, ResponseCode
from app.shared.states import Terminate
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession


def _evcc_session(
    *, renegotiation_supported: bool, renegotiation_requested: bool, charging_session
) -> StubCommSession:
    session = StubCommSession(
        protocol=Protocol.ISO_15118_20_COMMON_MESSAGES, session_id=bytes(1).hex()
    )
    session.service_renegotiation_supported = renegotiation_supported
    session.renegotiation_requested = renegotiation_requested
    # The state stores the EVCC's own stop intent here (set when it sent the
    # SessionStopReq); SessionStop reads it to label the StopNotification.
    session.charging_session_stop_v20 = charging_session
    session.writer = types.SimpleNamespace(get_extra_info=lambda _name: ("::1", 0))
    return session


def _stop_res(session: StubCommSession) -> SessionStopRes:
    return SessionStopRes(
        header=MessageHeader(session_id=session.session_id, timestamp=int(time())),
        response_code=ResponseCode.OK,
    )


@pytest.mark.asyncio
async def test_terminate_routes_to_terminate(exi_codec):
    """A plain terminate ends the cycle (next_state Terminate, TERMINATE action)."""
    session = _evcc_session(
        renegotiation_supported=False,
        renegotiation_requested=False,
        charging_session=ChargingSession.TERMINATE,
    )
    peer = ScriptedPeer(session, start_state=SessionStop)

    result = await peer.feed(_stop_res(session))

    assert result.next_state is Terminate
    assert session.stop_reason.stop_action == SessionStopAction.TERMINATE


@pytest.mark.asyncio
async def test_renegotiation_routes_to_service_discovery(exi_codec):
    """A requested+supported renegotiation loops to ServiceDiscovery, not Terminate.

    next_state is ServiceDiscovery (neither Terminate nor Pause), so the shared
    rcv_loop keeps the EVCC session alive and the controller does not re-arm
    mid-renegotiation. The one-shot ``renegotiation_requested`` is also cleared.
    """
    session = _evcc_session(
        renegotiation_supported=True,
        renegotiation_requested=True,
        charging_session=ChargingSession.SERVICE_RENEGOTIATION,
    )
    peer = ScriptedPeer(session, start_state=SessionStop)

    result = await peer.feed(_stop_res(session))

    assert result.next_state is ServiceDiscovery
    assert result.next_state is not Terminate
    assert session.renegotiation_requested is False


@pytest.mark.asyncio
async def test_renegotiation_requested_but_unsupported_terminates(exi_codec):
    """Without SECC support the EVCC cannot loop back, so the cycle terminates."""
    session = _evcc_session(
        renegotiation_supported=False,
        renegotiation_requested=True,
        charging_session=ChargingSession.SERVICE_RENEGOTIATION,
    )
    peer = ScriptedPeer(session, start_state=SessionStop)

    result = await peer.feed(_stop_res(session))

    assert result.next_state is Terminate


@pytest.mark.asyncio
async def test_pause_labels_stop_action_pause(exi_codec):
    """A pause request labels the StopNotification PAUSE while still terminating here."""
    session = _evcc_session(
        renegotiation_supported=False,
        renegotiation_requested=False,
        charging_session=ChargingSession.PAUSE,
    )
    peer = ScriptedPeer(session, start_state=SessionStop)

    result = await peer.feed(_stop_res(session))

    assert session.stop_reason.stop_action == SessionStopAction.PAUSE
    assert result.next_state is Terminate
