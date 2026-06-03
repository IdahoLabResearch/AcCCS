"""SECC ISO 15118-20 authorization-stall (ADR-0004, issue #32).

ISO-20 parity for the auth-stall proven on ISO 15118-2 (#30) and DIN SPEC
70121 (#31). Drives the real SECC ISO-20 `Authorization` state through
`process_message()` at the ADR-0003 state-machine seam and asserts the operator
[[stall]] behaviour on the ISO-20 Authorization loop:

- armed -> the SECC reports ``Processing.ONGOING`` and keeps expecting another
  AuthorizationReq, even though authorization itself has completed (the gate is
  forceful, not a wait-for-auth);
- pressing ``[a]dvance`` -> ``Processing.FINISHED`` exactly once, after which the
  state stops expecting an AuthorizationReq (the EVCC advances to
  ServiceDiscovery);
- disarmed -> the normal path (FINISHED on first request) is restored.

The simulator authorises with EIM by default, so there is no PnC signature path
to skip — the gate logic is what is under test.
"""

from __future__ import annotations

from time import time

import pytest

from app.secc.controller.simulator import SimEVSEController
from app.secc.states.iso15118_20_states import Authorization
from app.shared.live_control import LiveControl
from app.shared.messages.enums import AuthEnum, Protocol
from app.shared.messages.iso15118_20.common_messages import (
    AuthorizationReq,
    AuthorizationRes,
    EIMAuthReqParams,
)
from app.shared.messages.iso15118_20.common_types import MessageHeader, Processing
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession


def _secc_session(live_control: LiveControl) -> StubCommSession:
    controller = SimEVSEController(live_control=live_control)
    controller.set_selected_protocol(Protocol.ISO_15118_20_COMMON_MESSAGES)
    session = StubCommSession(
        protocol=Protocol.ISO_15118_20_COMMON_MESSAGES, session_id=bytes(1).hex()
    )
    session.evse_controller = controller
    session.selected_auth_option = AuthEnum.EIM
    return session


def _auth_req(session: StubCommSession) -> AuthorizationReq:
    return AuthorizationReq(
        header=MessageHeader(session_id=session.session_id, timestamp=int(time())),
        selected_auth_service=AuthEnum.EIM,
        eim_params=EIMAuthReqParams(),
    )


def _evse_processing(result) -> Processing:
    return result.outbound_msg.evse_processing


@pytest.mark.asyncio
async def test_unarmed_authentication_finishes_immediately(exi_codec):
    """Baseline: with no stall, the SECC finishes auth on the first request."""
    session = _secc_session(LiveControl())
    peer = ScriptedPeer(session, start_state=Authorization)

    result = await peer.feed(_auth_req(session))

    assert isinstance(result.outbound_msg, AuthorizationRes)
    assert _evse_processing(result) == Processing.FINISHED
    assert peer.state.expecting_authorization_req is False


@pytest.mark.asyncio
async def test_armed_gate_holds_ongoing_indefinitely(exi_codec):
    """While armed the gate reports ONGOING and keeps expecting AuthorizationReq."""
    lc = LiveControl(stall_authorization=True)
    session = _secc_session(lc)
    peer = ScriptedPeer(session, start_state=Authorization)

    for _ in range(5):
        result = await peer.feed(_auth_req(session))
        assert _evse_processing(result) == Processing.ONGOING
        assert peer.state.expecting_authorization_req is True


@pytest.mark.asyncio
async def test_advance_releases_finished_once(exi_codec):
    """[a]dvance passes the gate exactly once -> FINISHED, and stops expecting a req."""
    lc = LiveControl(stall_authorization=True)
    session = _secc_session(lc)
    peer = ScriptedPeer(session, start_state=Authorization)

    held = await peer.feed(_auth_req(session))
    assert _evse_processing(held) == Processing.ONGOING

    lc.release_authorization()  # operator presses [a]
    released = await peer.feed(_auth_req(session))
    assert _evse_processing(released) == Processing.FINISHED
    assert peer.state.expecting_authorization_req is False

    # The release is one-shot: a subsequent armed poll holds ONGOING again.
    again = await peer.feed(_auth_req(session))
    assert _evse_processing(again) == Processing.ONGOING


@pytest.mark.asyncio
async def test_disarm_restores_normal_path(exi_codec):
    """Disarming the gate falls back to finishing auth normally."""
    lc = LiveControl(stall_authorization=True)
    session = _secc_session(lc)
    peer = ScriptedPeer(session, start_state=Authorization)

    held = await peer.feed(_auth_req(session))
    assert _evse_processing(held) == Processing.ONGOING

    lc.disarm_authorization_stall()
    result = await peer.feed(_auth_req(session))
    assert _evse_processing(result) == Processing.FINISHED
    assert peer.state.expecting_authorization_req is False
