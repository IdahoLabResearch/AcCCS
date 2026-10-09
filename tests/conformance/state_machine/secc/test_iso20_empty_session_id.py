"""The ISO-20 SECC accepts a zero-length SessionID in SessionSetupReq (issue #136).

ISO 15118-20 parity for ``test_iso2_empty_session_id.py``: the common-types
header validator rejected a zero-length ``SessionID`` (conformance review
SC-035), so a vehicle that opens its session the way a real one does under DIN
got no SessionSetupRes at all. ``sessionIDType`` is ``hexBinary`` maxLength 8
(length 0 schema-legal); [V2G20-2106] says a new session is requested with a
SessionID of zeroes, so the empty value is logged as out-of-spec and then
handled like zero.
"""

from __future__ import annotations

import logging
from time import time

import pytest

from app.secc.controller.simulator import SimEVSEController
from app.secc.failed_responses import init_failed_responses_iso_v20
from app.secc.states.iso15118_20_states import AuthorizationSetup, SessionSetup
from app.shared.exi_codec import EXI
from app.shared.messages.enums import Namespace, Protocol
from app.shared.messages.iso15118_20.common_messages import (
    AuthorizationSetupReq,
    AuthorizationSetupRes,
    SessionSetupReq,
    SessionSetupRes,
)
from app.shared.messages.iso15118_20.common_types import MessageHeader, ResponseCode
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

EVCC_ID = "WMIV1234567890ABC"
# An ISO-20 SessionSetupReq with a zero-length SessionID, as the codec puts it
# on the wire.
EMPTY_SESSION_ID_SETUP_REQ_HEX = "808c00080f09dc706209aba6a4ab1899199a1a9b1b9c1c9820a12180"


def _secc_session() -> StubCommSession:
    controller = SimEVSEController(personality=SECCPersonality())
    controller.set_selected_protocol(Protocol.ISO_15118_20_COMMON_MESSAGES)
    session = StubCommSession(
        protocol=Protocol.ISO_15118_20_COMMON_MESSAGES, session_id=bytes(1).hex()
    )
    session.evse_controller = controller
    session.writer = StubWriter()
    session.failed_responses_isov20 = init_failed_responses_iso_v20()
    return session


def _session_setup_req(session_id: str) -> SessionSetupReq:
    return SessionSetupReq(
        header=MessageHeader(session_id=session_id, timestamp=int(time())),
        evcc_id=EVCC_ID,
    )


def test_decode_empty_session_id_setup_req(exi_codec, caplog):
    """The wire bytes decode to a SessionSetupReq with an empty SessionID."""
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        decoded = EXI().from_exi_document(
            bytes.fromhex(EMPTY_SESSION_ID_SETUP_REQ_HEX), Namespace.ISO_V20_COMMON_MSG
        )
    assert isinstance(decoded, SessionSetupReq)
    # The empty hexBinary must decode to an empty string, not leak a dict.
    assert decoded.header.session_id == ""
    assert decoded.evcc_id == EVCC_ID
    assert_single_out_of_spec_warning(caplog, "MessageHeader", "SessionID", "''")


@pytest.mark.asyncio
async def test_empty_session_id_establishes_a_new_session(exi_codec, caplog):
    session = _secc_session()
    peer = ScriptedPeer(session, start_state=SessionSetup)

    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        result = await peer.feed(_session_setup_req(""))

    assert result.next_state is AuthorizationSetup
    res = result.outbound_msg
    assert isinstance(res, SessionSetupRes)
    assert res.response_code == ResponseCode.OK_NEW_SESSION_ESTABLISHED
    assert session.session_id not in ("", bytes(1).hex())
    assert res.header.session_id == session.session_id
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
            AuthorizationSetupReq(
                header=MessageHeader(session_id="", timestamp=int(time()))
            )
        )

    assert result.next_state is Terminate
    res = result.outbound_msg
    assert isinstance(res, AuthorizationSetupRes)
    assert res.response_code == ResponseCode.FAILED_UNKNOWN_SESSION
    assert res.header.session_id == issued
    assert issued in session.stop_reason.reason
    assert_single_out_of_spec_warning(caplog, "MessageHeader", "SessionID", "''")


@pytest.mark.asyncio
async def test_zero_sentinel_session_id_still_opens_new_session(exi_codec, caplog):
    """The sentinel zero byte still opens a new session without any warning."""
    session = _secc_session()
    peer = ScriptedPeer(session, start_state=SessionSetup)

    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        result = await peer.feed(_session_setup_req(bytes(1).hex()))

    assert result.next_state is AuthorizationSetup
    assert result.outbound_msg.response_code == ResponseCode.OK_NEW_SESSION_ESTABLISHED
    assert out_of_spec_records(caplog) == []
