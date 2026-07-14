"""The DIN EVCC handles a charger whose EVSEID is longer than 16 bytes.

Regression for a real-charger interop failure: a live SECC answers
``SessionSetupReq`` with a 19-byte EVSEID -- the ASCII ``US*INL*EVILCHBDC1*1``
-- which is legal. DIN's ``evseIDType`` is ``hexBinary`` with a 32-byte maximum
(libcbv2g: ``din_evseIDType_BYTES_SIZE``), and XSD length facets on
``hexBinary`` count octets. The decoder hands Pydantic the hex *string*, so 32
bytes is 64 characters; the model used to bound that string at 32 characters,
silently capping EVSEID at 16 bytes -- half the schema allowance. The 19-byte
ID decoded to 38 characters and was rejected with ``String should have at most
32 characters``, so the EVCC tore down the TCP connection in ``SessionSetup``,
burned its single SDP retry cycle, and went back to state A.

The virtual demo never caught this: our own SECC personalities send short
EVSEIDs (``din-secc-baseline`` sends ``00``, ``default-secc`` sends
``49A89A6360``), comfortably under the accidental 16-byte ceiling.

This drives the shipped run default (`din_dc_extended-evcc`) through
SessionSetup with the real charger's EVSEID and asserts the EVCC advances to
ServiceDiscovery instead of rejecting the message.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.evcc.states.din_spec_states import SessionSetup
from app.shared.exi_codec import EXI
from app.shared.messages.din_spec.body import Body, ServiceDiscoveryReq, SessionSetupRes
from app.shared.messages.din_spec.header import MessageHeader
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import Namespace, Protocol
from app.shared.personality.loader import load_personality
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession

PERSONALITIES_DIR = Path(__file__).resolve().parents[4] / "personalities"

# What the real charger sends: 19 bytes of ASCII, 38 hex characters. Over the
# old 32-character bound, well under DIN's 32-byte (64-character) maximum.
REAL_EVSE_ID = b"US*INL*EVILCHBDC1*1".hex().upper()

# DIN's schema maximum and the first value past it.
MAX_EVSE_ID = "AB" * 32
OVERLONG_EVSE_ID = "AB" * 33


def _run_default_session() -> StubCommSession:
    # The shipped run default for run_evcc.py, not a test-only personality.
    personality = load_personality("din_dc_extended-evcc", "evcc")
    config = EVCCConfig.from_personality(personality)
    session = StubCommSession(
        protocol=Protocol.DIN_SPEC_70121, session_id=bytes(1).hex()
    )
    session.config = config
    session.ev_controller = SimEVController(config)
    session.live_control = None
    session.selected_auth_option = None
    session.selected_services = []
    session.selected_energy_mode = None
    session.selected_schedule = None
    session.ongoing_timer = -1
    return session


def _decode(result):
    payload = result.outbound_v2gtp.payload
    return EXI().from_exi_document(payload, Namespace.DIN_MSG_DEF).body.get_message()


@pytest.mark.asyncio
async def test_evcc_accepts_long_evse_id(exi_codec):
    session = _run_default_session()
    peer = ScriptedPeer(session, SessionSetup)

    # SessionSetupRes carrying the real charger's 19-byte EVSEID.
    # Under the old 32-character bound this raised before ever reaching the EVCC.
    reply = _decode(
        await peer.feed(
            V2GMessageDINSPEC(
                header=MessageHeader(session_id=session.session_id),
                body=Body(
                    session_setup_res=SessionSetupRes(
                        response_code="OK", evse_id=REAL_EVSE_ID
                    )
                ),
            )
        )
    )

    assert isinstance(reply, ServiceDiscoveryReq), (
        "EVCC must accept an EVSEID longer than 16 bytes and advance to "
        "ServiceDiscovery; a hex-character bound here tears down the session "
        "against any charger with a full-length DIN SPEC 91286 identifier."
    )


@pytest.mark.parametrize(
    "evse_id",
    [
        pytest.param("00", id="1-byte-secc-provides-no-id"),
        pytest.param(REAL_EVSE_ID, id="19-byte-real-charger"),
        pytest.param(MAX_EVSE_ID, id="32-byte-schema-maximum"),
    ],
)
def test_session_setup_res_accepts_evse_id_up_to_schema_maximum(evse_id):
    assert SessionSetupRes(response_code="OK", evse_id=evse_id).evse_id == evse_id


def test_session_setup_res_rejects_evse_id_past_schema_maximum():
    with pytest.raises(ValidationError):
        SessionSetupRes(response_code="OK", evse_id=OVERLONG_EVSE_ID)
