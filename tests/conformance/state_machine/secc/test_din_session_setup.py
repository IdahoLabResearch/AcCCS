"""DIN 70121 SECC state-machine tracer bullet.

This is the one DIN state-machine test ADR-0003 / issue #18 requires for the
foundation slice. It proves the scripted-peer harness can drive a real SECC
DIN state through `process_message()` and observe the state trajectory.

Per-state coverage growth is owned by personality Slices 2–4 (#7 / #8 / #9).
"""

from __future__ import annotations

import pytest

from app.secc.controller.simulator import SimEVSEController
from app.shared.personality.model import SECCPersonality
from app.secc.states.din_spec_states import ServiceDiscovery, SessionSetup
from app.shared.messages.din_spec.body import (
    Body,
    ResponseCode,
    SessionSetupReq,
    SessionSetupRes,
)
from app.shared.messages.din_spec.header import MessageHeader
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import Protocol
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession


@pytest.fixture
def secc_din_session(exi_codec):
    """Stub SECC comm_session in DIN mode with a sim EVSE controller."""
    session = StubCommSession(
        protocol=Protocol.DIN_SPEC_70121,
        session_id=bytes(1).hex(),
    )
    session.evse_controller = SimEVSEController(personality=SECCPersonality())
    return session


@pytest.mark.asyncio
async def test_din_session_setup_advances_to_service_discovery(secc_din_session):
    peer = ScriptedPeer(secc_din_session, start_state=SessionSetup)

    req = V2GMessageDINSPEC(
        header=MessageHeader(session_id=bytes(1).hex()),
        body=Body(session_setup_req=SessionSetupReq(evcc_id="00112233445566")),
    )

    result = await peer.feed(req)

    assert result.next_state is ServiceDiscovery, (
        f"SessionSetup should hand off to ServiceDiscovery, got {result.next_state}"
    )
    assert isinstance(result.outbound_msg, V2GMessageDINSPEC), (
        "Outbound must be a DIN V2GMessage"
    )
    assert isinstance(result.outbound_msg.body.session_setup_res, SessionSetupRes), (
        "Outbound body must be SessionSetupRes"
    )
    assert result.outbound_msg.body.session_setup_res.response_code == (
        ResponseCode.OK_NEW_SESSION_ESTABLISHED
    ), "Fresh EVCC session ID must produce OK_NEW_SESSION_ESTABLISHED"
    assert result.outbound_v2gtp is not None, (
        "create_next_message should populate next_v2gtp_msg for non-terminal states"
    )
    # Session ID is reassigned by SessionSetup; harness must reflect that.
    assert secc_din_session.session_id != bytes(1).hex(), (
        "SECC must assign a fresh session ID when EVCC sends the bootstrap zero ID"
    )
