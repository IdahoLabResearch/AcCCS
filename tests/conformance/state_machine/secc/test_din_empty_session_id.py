"""A real EVCC sends an empty SessionID in its first DIN SessionSetupReq.

Regression for a real-vehicle interop failure captured on the SECC. In its
opening ``SessionSetupReq`` a real car requests a brand-new session by sending
a **zero-length** ``Header.SessionID`` (0 bytes on the wire). libcbv2g's JSON
emits that empty hexBinary as ``{"bytesLen": 0}`` with the ``bytes`` key elided
(exactly as it elides ``array`` for a zero-length list). Two defects then broke
the SECC before the session could start:

1. ``everest_shape`` only converted a byte field to a hex string when the
   ``bytes`` key was present, so the empty ``SessionID`` leaked through as the
   raw ``{"bytesLen": 0}`` dict and Pydantic rejected the ``MessageHeader``
   with ``V2GMessageValidationError`` in state ``SessionSetup``.
2. ``MessageHeader.check_sessionid_is_hexbinary`` rejected the legal empty
   hexBinary because ``int("", 16)`` raises.

The exact bytes below are the ``V2G_Message`` the car put on the wire
(``809a0011d0200003c1fc3001ac7000``); its ``EVCCID`` is 8 bytes and its
``SessionID`` is empty.
"""

from __future__ import annotations

import pytest

from app.secc.controller.simulator import SimEVSEController
from app.secc.states.din_spec_states import ServiceDiscovery, SessionSetup
from app.shared.exi_codec import EXI
from app.shared.messages.din_spec.body import (
    Body,
    ResponseCode,
    SessionSetupReq,
    SessionSetupRes,
)
from app.shared.messages.din_spec.header import MessageHeader
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import Namespace, Protocol
from app.shared.personality.model import SECCPersonality
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession

# The exact DIN V2G_Message a real vehicle put on the wire: a SessionSetupReq
# carrying an 8-byte EVCCID and an empty (zero-length) SessionID.
REAL_CAR_SETUP_REQ_HEX = "809a0011d0200003c1fc3001ac7000"
EXPECTED_EVCC_ID = "0000F07F0C006B1C"


def test_decode_real_car_empty_session_id_setup_req(exi_codec):
    """The captured bytes decode to a valid SessionSetupReq with empty SessionID."""
    decoded = EXI().from_exi_document(
        bytes.fromhex(REAL_CAR_SETUP_REQ_HEX), Namespace.DIN_MSG_DEF
    )
    assert isinstance(decoded, V2GMessageDINSPEC)
    # The empty hexBinary must decode to an empty string, not leak a dict.
    assert decoded.header.session_id == ""
    setup_req = decoded.body.session_setup_req
    assert isinstance(setup_req, SessionSetupReq)
    assert setup_req.evcc_id == EXPECTED_EVCC_ID


@pytest.mark.asyncio
async def test_secc_accepts_empty_session_id_as_new_session(exi_codec):
    """An empty SessionID is a new-session request, not a false/mismatched ID."""
    session = StubCommSession(
        protocol=Protocol.DIN_SPEC_70121, session_id=bytes(1).hex()
    )
    session.evse_controller = SimEVSEController(personality=SECCPersonality())
    peer = ScriptedPeer(session, start_state=SessionSetup)

    req = V2GMessageDINSPEC(
        header=MessageHeader(session_id=""),
        body=Body(session_setup_req=SessionSetupReq(evcc_id="0000F07F0C006B1C")),
    )
    result = await peer.feed(req)

    assert result.next_state is ServiceDiscovery
    res = result.outbound_msg.body.session_setup_res
    assert isinstance(res, SessionSetupRes)
    assert res.response_code == ResponseCode.OK_NEW_SESSION_ESTABLISHED
    # The SECC assigns a fresh non-empty session ID for the rest of the session.
    assert session.session_id not in ("", bytes(1).hex())
