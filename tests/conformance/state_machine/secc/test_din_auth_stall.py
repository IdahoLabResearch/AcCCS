"""SECC DIN SPEC 70121 authorization-stall (ADR-0004, issue #31).

DIN parity for the ISO 15118-2 auth-stall proven in issue #30. Drives the real
SECC DIN `ContractAuthentication` state through `process_message()` at the
ADR-0003 state-machine seam and asserts the operator [[stall]] behaviour on the
DIN `ContractAuthentication` loop:

- armed → the SECC reports ``EVSEProcessing.ONGOING`` and stays in
  `ContractAuthentication`, even though authorization itself has completed (the
  gate is forceful, not a wait-for-auth);
- pressing ``[a]dvance`` → ``EVSEProcessing.FINISHED`` exactly once and a hand
  off to `ChargeParameterDiscovery`;
- disarmed → the normal path (FINISHED on first request) is restored.

DIN SPEC only supports EIM, so there is no PnC signature path to skip — the
gate logic is what is under test.
"""

from __future__ import annotations

import pytest

from app.secc.controller.simulator import SimEVSEController
from app.shared.personality.model import SECCPersonality
from app.secc.states.din_spec_states import (
    ChargeParameterDiscovery,
    ContractAuthentication,
)
from app.shared.live_control import LiveControl
from app.shared.messages.din_spec.body import (
    Body,
    ContractAuthenticationReq,
    ContractAuthenticationRes,
)
from app.shared.messages.din_spec.header import MessageHeader
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import AuthEnum, EVSEProcessing, Protocol
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession


def _secc_session(live_control: LiveControl) -> StubCommSession:
    controller = SimEVSEController(personality=SECCPersonality(), live_control=live_control)
    controller.set_selected_protocol(Protocol.DIN_SPEC_70121)
    session = StubCommSession(
        protocol=Protocol.DIN_SPEC_70121, session_id=bytes(1).hex()
    )
    session.evse_controller = controller
    session.selected_auth_option = AuthEnum.EIM_V2
    return session


def _contract_auth_req(session: StubCommSession) -> V2GMessageDINSPEC:
    return V2GMessageDINSPEC(
        header=MessageHeader(session_id=session.session_id),
        body=Body(contract_authentication_req=ContractAuthenticationReq()),
    )


def _evse_processing(result) -> EVSEProcessing:
    return result.outbound_msg.body.contract_authentication_res.evse_processing


@pytest.mark.asyncio
async def test_unarmed_authentication_finishes_immediately(exi_codec):
    """Baseline: with no stall, the SECC finishes auth on the first request."""
    session = _secc_session(LiveControl())
    peer = ScriptedPeer(session, start_state=ContractAuthentication)

    result = await peer.feed(_contract_auth_req(session))

    assert isinstance(
        result.outbound_msg.body.contract_authentication_res, ContractAuthenticationRes
    )
    assert _evse_processing(result) == EVSEProcessing.FINISHED
    assert result.next_state is ChargeParameterDiscovery


@pytest.mark.asyncio
async def test_armed_gate_holds_ongoing_indefinitely(exi_codec):
    """While armed the gate reports ONGOING and never leaves ContractAuthentication."""
    lc = LiveControl(stall_authorization=True)
    session = _secc_session(lc)
    peer = ScriptedPeer(session, start_state=ContractAuthentication)

    for _ in range(5):
        result = await peer.feed(_contract_auth_req(session))
        assert _evse_processing(result) == EVSEProcessing.ONGOING
        # next_state None means "stay in ContractAuthentication, expect another req".
        assert result.next_state is None


@pytest.mark.asyncio
async def test_advance_releases_finished_once(exi_codec):
    """[a]dvance passes the gate exactly once -> FINISHED + ChargeParameterDiscovery."""
    lc = LiveControl(stall_authorization=True)
    session = _secc_session(lc)
    peer = ScriptedPeer(session, start_state=ContractAuthentication)

    held = await peer.feed(_contract_auth_req(session))
    assert _evse_processing(held) == EVSEProcessing.ONGOING

    lc.release_authorization()  # operator presses [a]
    released = await peer.feed(_contract_auth_req(session))
    assert _evse_processing(released) == EVSEProcessing.FINISHED
    assert released.next_state is ChargeParameterDiscovery


@pytest.mark.asyncio
async def test_disarm_restores_normal_path(exi_codec):
    """Disarming the gate falls back to finishing auth normally."""
    lc = LiveControl(stall_authorization=True)
    session = _secc_session(lc)
    peer = ScriptedPeer(session, start_state=ContractAuthentication)

    held = await peer.feed(_contract_auth_req(session))
    assert _evse_processing(held) == EVSEProcessing.ONGOING

    lc.disarm_authorization_stall()
    result = await peer.feed(_contract_auth_req(session))
    assert _evse_processing(result) == EVSEProcessing.FINISHED
    assert result.next_state is ChargeParameterDiscovery
