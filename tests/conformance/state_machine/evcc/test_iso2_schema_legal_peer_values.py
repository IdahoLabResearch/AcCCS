"""The ISO-2 EVCC keeps the session alive on schema-legal peer values (issue #124).

Two values hit in the field were legal on the wire but outside our message
model, so the EVCC closed the socket instead of answering (conformance review
SC-032 and SC-034):

- ``SessionSetupRes → EVSEID`` of one NUL byte. Annex C.6 ``evseIDType`` says
  minLength 7, so the charger is non-conformant, but the posture is to log
  and continue; only the 37-character upper bound is still enforced.
- ``ServiceDiscoveryRes → ChargeService → ServiceID`` outside 1-4.
  ``serviceIDType`` is ``xs:unsignedShort`` and 60001-65535 is reserved for
  implementation-specific services (8.6.3.6).

Each replay feeds the charger's message to the real state at the ADR-0003
``process_message()`` seam (no codec round-trip: the codec layer covers the
decode) and asserts the EVCC advances to its next request with exactly one
out-of-spec warning.
"""

from __future__ import annotations

import logging

import pytest

from app.evcc.states.iso15118_2_states import ServiceDiscovery, SessionSetup
from app.shared.exi_codec import EXI
from app.shared.messages.enums import AuthEnum, EnergyTransferModeEnum, Namespace
from app.shared.messages.iso15118_2.body import (
    Body,
    PaymentServiceSelectionReq,
    ServiceDiscoveryReq,
    ServiceDiscoveryRes,
    SessionSetupRes,
)
from app.shared.messages.iso15118_2.datatypes import (
    AuthOptionList,
    ChargeService,
    EnergyTransferModeList,
    ServiceCategory,
)
from app.shared.messages.iso15118_2.header import MessageHeader
from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from tests.conformance.state_machine.evcc._iso2_session import baseline_session
from tests.conformance.out_of_spec_log import (
    OUT_OF_SPEC_LOGGER,
    assert_single_out_of_spec_warning,
    out_of_spec_records,
)
from tests.conformance.state_machine.harness import ScriptedPeer

# What the real ISO-2 charger put on the wire in SessionSetupRes.
ONE_NUL_EVSE_ID = "\x00"
# An implementation-specific ServiceID (8.6.3.6 reserves 60001-65535) and a
# name outside Table 105, as a fielded charger advertises.
VENDOR_SERVICE_ID = 60001
VENDOR_SERVICE_NAME = "DC_CHARGING"



def _decode(result):
    payload = result.outbound_v2gtp.payload
    return EXI().from_exi_document(payload, Namespace.ISO_V2_MSG_DEF).body.get_message()



@pytest.mark.asyncio
async def test_session_setup_res_with_one_nul_evse_id_advances(exi_codec, caplog):
    session = baseline_session()
    peer = ScriptedPeer(session, SessionSetup)
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        # Validation runs when the charger's message is built (the codec
        # layer covers the decode); processing it must not add a warning.
        charger_message = V2GMessageV2(
            header=MessageHeader(session_id=session.session_id),
            body=Body(
                session_setup_res=SessionSetupRes(
                    response_code="OK", evse_id=ONE_NUL_EVSE_ID
                )
            ),
        )
        reply = _decode(await peer.feed(charger_message))

    assert isinstance(reply, ServiceDiscoveryReq), (
        "EVCC must accept an EVSEID shorter than seven characters and advance "
        "to ServiceDiscovery; the charger is non-conformant, the session is "
        "still worth keeping."
    )
    assert session.evse_id == ONE_NUL_EVSE_ID
    assert_single_out_of_spec_warning(
        caplog, "SessionSetupRes", "EVSEID", repr(ONE_NUL_EVSE_ID), "minLength 7"
    )


@pytest.mark.asyncio
async def test_service_discovery_res_with_vendor_service_advances_and_echoes(
    exi_codec, caplog
):
    session = baseline_session()
    peer = ScriptedPeer(session, ServiceDiscovery)
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        # Validation runs when the charger's message is built (the codec
        # layer covers the decode); processing it must not add a warning.
        charger_message = V2GMessageV2(
            header=MessageHeader(session_id=session.session_id),
            body=Body(
                service_discovery_res=ServiceDiscoveryRes(
                    response_code="OK",
                    auth_option_list=AuthOptionList(auth_options=[AuthEnum.EIM_V2]),
                    charge_service=ChargeService(
                        service_id=VENDOR_SERVICE_ID,
                        service_name=VENDOR_SERVICE_NAME,
                        service_category=ServiceCategory.CHARGING,
                        free_service=False,
                        supported_energy_transfer_mode=EnergyTransferModeList(
                            energy_modes=[EnergyTransferModeEnum.DC_EXTENDED]
                        ),
                    ),
                )
            ),
        )
        reply = _decode(await peer.feed(charger_message))

    assert isinstance(reply, PaymentServiceSelectionReq), (
        "EVCC must accept a ServiceID outside 1-4 (serviceIDType is "
        "unsignedShort; 60001-65535 is implementation-specific) and advance "
        "to PaymentServiceSelection."
    )
    selected = reply.selected_service_list.selected_service
    assert [s.service_id for s in selected] == [VENDOR_SERVICE_ID], (
        "EVCC must echo the SECC's advertised ServiceID in SelectedServiceList."
    )
    # ISO-2 ServiceName is already a free string: the only warning is the ID's.
    assert_single_out_of_spec_warning(
        caplog, "ChargeService", "ServiceID", str(VENDOR_SERVICE_ID), "1..4"
    )
