"""The DIN EVCC keeps the session alive on schema-legal peer values (issue #124).

Two values a real DIN charger sends were legal on the wire but outside our
message model, so the EVCC closed the socket instead of answering
(conformance review SC-002 and SC-033):

- ``CableCheckRes → DC_EVSEStatus → NotificationMaxDelay = 50331648``
  (3 << 24). DIN types the field ``xs:unsignedInt`` and tells the EVCC to
  ignore it ([V2G-DC-636]); our 65535 bound was copied from ISO 15118-2.
- ``ServiceDiscoveryRes → ChargeService → ServiceTag → ServiceName`` outside
  the standard's own names. DIN forbids the element outright ([V2G-DC-628]),
  so anything that arrives is the charger's choice, not ours to validate.

Each replay feeds the charger's message to the real state at the ADR-0003
``process_message()`` seam (no codec round-trip: the codec layer covers the
decode) and asserts the EVCC advances to its next request with exactly one
out-of-spec warning.
"""

from __future__ import annotations

import logging

import pytest

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.evcc.states.din_spec_states import CableCheck, ServiceDiscovery
from app.shared.exi_codec import EXI
from app.shared.messages.datatypes import DCEVSEStatus, DCEVSEStatusCode
from app.shared.messages.din_spec.body import (
    Body,
    CableCheckRes,
    PreChargeReq,
    ServiceDiscoveryRes,
    ServicePaymentSelectionReq,
)
from app.shared.messages.din_spec.datatypes import (
    AuthOptionList,
    ChargeService,
    EVSENotification,
    ServiceCategory,
    ServiceDetails,
    ServiceID,
)
from app.shared.messages.din_spec.header import MessageHeader
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import (
    AuthEnum,
    EnergyTransferModeEnum,
    EVSEProcessing,
    IsolationLevel,
    Namespace,
    Protocol,
)
from app.shared.personality.loader import load_personality
from tests.conformance.out_of_spec_log import (
    OUT_OF_SPEC_LOGGER,
    assert_single_out_of_spec_warning,
    out_of_spec_records,
)
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession

# What the real DIN charger put on the wire (3 << 24).
OVERSIZED_NOTIFICATION_MAX_DELAY = 50331648
# A name outside ISO 15118-2 Table 105, as a fielded charger advertises.
VENDOR_SERVICE_NAME = "DC_CHARGING"


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
async def test_cable_check_res_with_oversized_delay_advances_to_precharge(
    exi_codec, caplog
):
    session = _run_default_session()
    peer = ScriptedPeer(session, CableCheck)
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        # Validation runs when the charger's message is built (the codec
        # layer covers the decode); processing it must not add a warning.
        charger_message = V2GMessageDINSPEC(
            header=MessageHeader(session_id=session.session_id),
            body=Body(
                cable_check_res=CableCheckRes(
                    response_code="OK",
                    dc_evse_status=DCEVSEStatus(
                        notification_max_delay=OVERSIZED_NOTIFICATION_MAX_DELAY,
                        evse_notification=EVSENotification.NONE,
                        evse_isolation_status=IsolationLevel.VALID,
                        evse_status_code=DCEVSEStatusCode.EVSE_READY,
                    ),
                    evse_processing=EVSEProcessing.FINISHED,
                )
            ),
        )
        reply = _decode(await peer.feed(charger_message))

    assert isinstance(reply, PreChargeReq), (
        "EVCC must accept a NotificationMaxDelay above 65535 (legal DIN "
        "unsignedInt, ignored per [V2G-DC-636]) and advance to PreCharge."
    )
    assert_single_out_of_spec_warning(
        caplog, "DCEVSEStatus", "NotificationMaxDelay", "50331648", "65535"
    )


@pytest.mark.asyncio
async def test_service_discovery_res_with_vendor_service_name_advances(
    exi_codec, caplog
):
    session = _run_default_session()
    peer = ScriptedPeer(session, ServiceDiscovery)
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        # Validation runs when the charger's message is built (the codec
        # layer covers the decode); processing it must not add a warning.
        charger_message = V2GMessageDINSPEC(
            header=MessageHeader(session_id=session.session_id),
            body=Body(
                service_discovery_res=ServiceDiscoveryRes(
                    response_code="OK",
                    auth_option_list=AuthOptionList(auth_options=[AuthEnum.EIM_V2]),
                    charge_service=ChargeService(
                        service_tag=ServiceDetails(
                            service_id=ServiceID.CHARGING,
                            service_name=VENDOR_SERVICE_NAME,
                            service_category=ServiceCategory.CHARGING,
                        ),
                        free_service=False,
                        energy_transfer_type=EnergyTransferModeEnum.DC_EXTENDED,
                    ),
                )
            ),
        )
        reply = _decode(await peer.feed(charger_message))

    assert isinstance(reply, ServicePaymentSelectionReq), (
        "EVCC must accept a ServiceName outside the standard's names and "
        "advance to ServicePaymentSelection; DIN forbids the element, so "
        "whatever arrives is the charger's to answer for, not ours to reject."
    )
    assert_single_out_of_spec_warning(
        caplog, "ServiceDetails", "ServiceName", VENDOR_SERVICE_NAME
    )
