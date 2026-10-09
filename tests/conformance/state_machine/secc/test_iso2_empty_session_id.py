"""The ISO-2 SECC accepts a zero-length SessionID in SessionSetupReq (issue #136).

A real vehicle opens its DIN session with a **zero-length** ``Header.SessionID``
(0 bytes on the wire) to request a new session; the DIN SECC already treats
that as the all-zero "new session" value (``test_din_empty_session_id.py``).
Under ISO 15118-2 the same vehicle got no SessionSetupRes at all, because the
ISO-2 header validator rejected the empty value before the state ran
(conformance review SC-035). Annex C.6 ``sessionIDType`` is ``hexBinary``
maxLength 8, so length 0 is schema-legal; [V2G2-750] says a new session is
requested with a zero SessionID, so the empty value is logged as out-of-spec
and then handled like zero.

Three behaviours are pinned at the ADR-0003 ``process_message()`` seam:

1. SessionSetupReq with an empty SessionID → SessionSetupRes carrying
   ``OK_NewSessionEstablished`` and a fresh, non-empty session ID, with exactly
   one out-of-spec warning.
2. A later request still echoing the empty ID is matched against the issued
   ID by the ordinary session-ID check (``FAILED_UnknownSession``), not
   rejected by the header validator.
3. ``MeteringReceiptReq → SessionID`` carries the same validator and accepts
   the empty value the same way.
"""

from __future__ import annotations

import logging

import pytest

from app.secc.controller.simulator import SimEVSEController
from app.secc.failed_responses import init_failed_responses_iso_v2
from app.secc.states.iso15118_2_states import ServiceDiscovery, SessionSetup
from app.shared.exi_codec import EXI
from app.shared.messages.enums import Namespace, Protocol
from app.shared.messages.iso15118_2.body import (
    Body,
    MeteringReceiptReq,
    ResponseCode,
    ServiceDiscoveryReq,
    ServiceDiscoveryRes,
    SessionSetupReq,
    SessionSetupRes,
)
from app.shared.messages.iso15118_2.datatypes import MeterInfo
from app.shared.messages.iso15118_2.header import MessageHeader
from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from app.shared.personality.model import SECCPersonality
from app.shared.states import Terminate
from tests.conformance.out_of_spec_log import (
    OUT_OF_SPEC_LOGGER,
    assert_single_out_of_spec_warning,
    out_of_spec_records,
)
from tests.conformance.state_machine.harness import (
    ScriptedPeer,
    StubCommSession,
    StubWriter,
)

EVCC_ID = "0000F07F0C00"
# An ISO-2 V2G_Message SessionSetupReq with a 6-byte EVCCID and a zero-length
# SessionID, as the codec puts it on the wire (same shape as the DIN capture
# in ``test_din_empty_session_id.py``).
EMPTY_SESSION_ID_SETUP_REQ_HEX = "80980011d0180003c1fc300000"


def _secc_session() -> StubCommSession:
    session = StubCommSession(protocol=Protocol.ISO_15118_2, session_id=bytes(1).hex())
    session.evse_controller = SimEVSEController(personality=SECCPersonality())
    session.writer = StubWriter()
    session.failed_responses_isov2 = init_failed_responses_iso_v2()
    return session


def _session_setup_req(session_id: str) -> V2GMessageV2:
    return V2GMessageV2(
        header=MessageHeader(session_id=session_id),
        body=Body(session_setup_req=SessionSetupReq(evcc_id=EVCC_ID)),
    )


def test_decode_empty_session_id_setup_req(exi_codec, caplog):
    """The wire bytes decode to a SessionSetupReq with an empty SessionID."""
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        decoded = EXI().from_exi_document(
            bytes.fromhex(EMPTY_SESSION_ID_SETUP_REQ_HEX), Namespace.ISO_V2_MSG_DEF
        )
    assert isinstance(decoded, V2GMessageV2)
    # The empty hexBinary must decode to an empty string, not leak a dict.
    assert decoded.header.session_id == ""
    assert isinstance(decoded.body.session_setup_req, SessionSetupReq)
    assert decoded.body.session_setup_req.evcc_id == EVCC_ID
    assert_single_out_of_spec_warning(caplog, "MessageHeader", "SessionID", "''")


@pytest.mark.asyncio
async def test_empty_session_id_establishes_a_new_session(exi_codec, caplog):
    session = _secc_session()
    peer = ScriptedPeer(session, start_state=SessionSetup)

    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        # Validation runs when the vehicle's message is built (the decode
        # path in production); processing it must not add a second warning.
        result = await peer.feed(_session_setup_req(""))

    assert result.next_state is ServiceDiscovery
    res = result.outbound_msg.body.session_setup_res
    assert isinstance(res, SessionSetupRes)
    assert res.response_code == ResponseCode.OK_NEW_SESSION_ESTABLISHED
    # The SECC assigns a fresh non-empty session ID for the rest of the session.
    assert session.session_id not in ("", bytes(1).hex())
    assert result.outbound_msg.header.session_id == session.session_id
    assert_single_out_of_spec_warning(caplog, "MessageHeader", "SessionID", "''")


@pytest.mark.asyncio
async def test_later_message_echoing_empty_id_fails_ordinary_session_check(
    exi_codec, caplog
):
    session = _secc_session()
    peer = ScriptedPeer(session, start_state=SessionSetup)
    await peer.feed(_session_setup_req(""))
    issued = session.session_id

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        result = await peer.feed(
            V2GMessageV2(
                header=MessageHeader(session_id=""),
                body=Body(service_discovery_req=ServiceDiscoveryReq()),
            )
        )

    # The header validator let the value through; the ordinary session-ID
    # check in `check_msg` is what rejected it, against the issued ID.
    assert result.next_state is Terminate
    res = result.outbound_msg.body.service_discovery_res
    assert isinstance(res, ServiceDiscoveryRes)
    assert res.response_code == ResponseCode.FAILED_UNKNOWN_SESSION
    assert issued in session.stop_reason.reason
    assert_single_out_of_spec_warning(caplog, "MessageHeader", "SessionID", "''")


@pytest.mark.asyncio
async def test_zero_sentinel_session_id_still_opens_new_session(exi_codec, caplog):
    """The sentinel zero byte still opens a new session without any warning."""
    session = _secc_session()
    peer = ScriptedPeer(session, start_state=SessionSetup)

    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        result = await peer.feed(_session_setup_req(bytes(1).hex()))

    assert result.next_state is ServiceDiscovery
    res = result.outbound_msg.body.session_setup_res
    assert res.response_code == ResponseCode.OK_NEW_SESSION_ESTABLISHED
    assert out_of_spec_records(caplog) == []


def test_metering_receipt_req_accepts_empty_session_id(exi_codec, caplog):
    """The body-level SessionID of MeteringReceiptReq gets the same treatment."""
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        message = V2GMessageV2(
            header=MessageHeader(session_id="0011223344556677"),
            body=Body(
                metering_receipt_req=MeteringReceiptReq(
                    session_id="", meter_info=MeterInfo(meter_id="METER-1")
                )
            ),
        )
    assert message.body.metering_receipt_req.session_id == ""
    assert_single_out_of_spec_warning(caplog, "MeteringReceiptReq", "SessionID", "''")

    # And it survives the EXI round trip the receive path performs.
    encoded = EXI().to_exi_document(message, Namespace.ISO_V2_MSG_DEF)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        decoded = EXI().from_exi_document(encoded, Namespace.ISO_V2_MSG_DEF)
    assert decoded.body.metering_receipt_req.session_id == ""
    assert_single_out_of_spec_warning(caplog, "MeteringReceiptReq", "SessionID", "''")
