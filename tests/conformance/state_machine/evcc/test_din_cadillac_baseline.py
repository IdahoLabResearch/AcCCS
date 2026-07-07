"""The shipped `din-evcc-baseline` reproduces the Cadillac Lyriq field-for-field.

Issue #74 / ADR-0006: the DIN EVCC baseline replicates the Cadillac Lyriq from
`ABB_Cadillac_Lyric.pcapng` — the vehicle-side mirror of the ABB
`din-secc-baseline` (#73). This drives the real EVCC through a full DIN session
with the shipped `personalities/din-evcc-baseline.yaml`, feeding scripted SECC
`*Res` messages, decodes the bytes the EVCC actually put on the wire for each
`*Req`, and asserts every Cadillac baseline field — proving the message field
tree reaches the wire for the whole EVCC DIN path.

Runtime/computed fields (EVCCID, SessionID, EVReady, ChargingComplete, and the
present/target voltage & current that ramp) are deliberately NOT asserted — the
baseline leaves them computed. The Cadillac's static 88% SOC, its announced
500 A / 410 V envelope, FullSOC/BulkSOC targets, BulkChargingComplete, and the
omitted EVMaximumPowerLimit on CurrentDemandReq are the headline behaviours.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.evcc.states.din_spec_states import (
    CableCheck,
    ChargeParameterDiscovery,
    ContractAuthentication,
    PowerDelivery,
    PreCharge,
    ServiceDiscovery,
    ServicePaymentSelection,
    SessionSetup,
    WeldingDetection,
)
from app.shared.exi_codec import EXI
from app.shared.messages.datatypes import (
    DCEVSEStatus,
    PVEVSEPresentVoltageDin,
)
from app.shared.messages.din_spec.body import (
    Body,
    CableCheckRes,
    ChargeParameterDiscoveryRes,
    ContractAuthenticationRes,
    CurrentDemandRes,
    PowerDeliveryRes,
    PreChargeRes,
    ServiceDiscoveryRes,
    ServicePaymentSelectionRes,
    SessionSetupRes,
    WeldingDetectionRes,
)
from app.shared.messages.din_spec.datatypes import (
    AuthOptionList,
    ChargeService,
    DCEVSEStatusCode,
    EVSENotification,
    PMaxScheduleEntry,
    PMaxScheduleEntryDetails,
    RelativeTimeInterval,
    SAScheduleList,
    SAScheduleTupleEntry,
    ServiceCategory,
    ServiceDetails,
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
    UnitSymbol,
)
from app.shared.personality.loader import load_personality
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession

PERSONALITIES_DIR = Path(__file__).resolve().parents[4] / "personalities"


def _baseline_session() -> StubCommSession:
    personality = load_personality(
        str(PERSONALITIES_DIR / "din-evcc-baseline.yaml"), "evcc"
    )
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


def _dc_evse_status_valid() -> DCEVSEStatus:
    return DCEVSEStatus(
        notification_max_delay=0,
        evse_notification=EVSENotification.NONE,
        evse_isolation_status=IsolationLevel.VALID,
        evse_status_code=DCEVSEStatusCode.EVSE_READY,
    )


def _decode(result):
    """Decode the EVCC's outbound wire bytes back into the DIN Req message."""
    payload = result.outbound_v2gtp.payload
    return EXI().from_exi_document(payload, Namespace.DIN_MSG_DEF).body.get_message()


@pytest.mark.asyncio
async def test_din_evcc_baseline_reproduces_cadillac_capture(exi_codec):
    session = _baseline_session()
    hdr = lambda: MessageHeader(session_id=session.session_id)  # noqa: E731
    peer = ScriptedPeer(session, SessionSetup)

    # --- SessionSetupRes -> ServiceDiscoveryReq (ServiceCategory EVCharging) --
    res = _decode(
        await peer.feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    session_setup_res=SessionSetupRes(response_code="OK", evse_id="00")
                ),
            )
        )
    )
    assert res.service_category == ServiceCategory.CHARGING

    # --- ServiceDiscoveryRes -> ServicePaymentSelectionReq -------------------
    # Offer exactly what the ABB advertises (ServiceID 1). SelectedPaymentOption
    # is the tree pin (ExternalPayment); the selected ServiceID is echoed from
    # this ServiceDiscoveryRes, so advertising 1 yields a selected 1.
    res = _decode(
        await peer.feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    service_discovery_res=ServiceDiscoveryRes(
                        response_code="OK",
                        auth_option_list=AuthOptionList(
                            auth_options=[AuthEnum.EIM_V2]
                        ),
                        charge_service=ChargeService(
                            service_tag=ServiceDetails(
                                service_id=1,
                                service_category=ServiceCategory.CHARGING,
                            ),
                            free_service=False,
                            energy_transfer_type=EnergyTransferModeEnum.DC_EXTENDED,
                        ),
                    )
                ),
            )
        )
    )
    assert res.selected_payment_option == AuthEnum.EIM_V2  # "ExternalPayment"
    [selected] = res.selected_service_list.selected_service
    assert selected.service_id == 1

    # --- ServicePaymentSelectionRes -> ContractAuthenticationReq (empty) -----
    res = _decode(
        await peer.feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    service_payment_selection_res=ServicePaymentSelectionRes(
                        response_code="OK"
                    )
                ),
            )
        )
    )
    assert res is not None  # empty body, routed through the tree helper cleanly

    # --- ContractAuthenticationRes(FINISHED) -> ChargeParameterDiscoveryReq ---
    res = _decode(
        await peer.feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    contract_authentication_res=ContractAuthenticationRes(
                        response_code="OK", evse_processing=EVSEProcessing.FINISHED
                    )
                ),
            )
        )
    )
    dcp = res.dc_ev_charge_parameter
    assert dcp.dc_ev_status.ev_ress_soc == 88
    assert dcp.ev_maximum_current_limit.get_decimal_value() == 500
    assert dcp.ev_maximum_voltage_limit.get_decimal_value() == 410
    assert dcp.full_soc == 100
    assert dcp.bulk_soc == 80
    # The Cadillac omits EVMaximumPowerLimit / EVEnergyCapacity here.
    assert dcp.ev_maximum_power_limit is None
    assert dcp.ev_energy_capacity is None
    assert res.requested_energy_mode == EnergyTransferModeEnum.DC_EXTENDED

    # --- ChargeParameterDiscoveryRes(FINISHED) -> CableCheckReq (SOC 88) -----
    res = _decode(
        await peer.feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    charge_parameter_discovery_res=ChargeParameterDiscoveryRes(
                        response_code="OK",
                        evse_processing=EVSEProcessing.FINISHED,
                        sa_schedule_list=SAScheduleList(
                            values=[
                                SAScheduleTupleEntry(
                                    sa_schedule_tuple_id=1,
                                    p_max_schedule=PMaxScheduleEntry(
                                        p_max_schedule_id=1,
                                        entry_details=[
                                            PMaxScheduleEntryDetails(
                                                p_max=24000,
                                                time_interval=RelativeTimeInterval(
                                                    start=0
                                                ),
                                            )
                                        ],
                                    ),
                                )
                            ]
                        ),
                    )
                ),
            )
        )
    )
    assert res.dc_ev_status.ev_ress_soc == 88

    # --- CableCheckRes(FINISHED, Valid) -> PreChargeReq (SOC 88) -------------
    res = _decode(
        await peer.feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    cable_check_res=CableCheckRes(
                        response_code="OK",
                        dc_evse_status=_dc_evse_status_valid(),
                        evse_processing=EVSEProcessing.FINISHED,
                    )
                ),
            )
        )
    )
    assert res.dc_ev_status.ev_ress_soc == 88

    # --- PreChargeRes -> PowerDeliveryReq (BulkChargingComplete true, SOC 88) -
    # Force the precharge loop complete so the EVCC advances to PowerDelivery.
    session.ev_controller.precharge_loop_cycles = 5
    res = _decode(
        await peer.feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    pre_charge_res=PreChargeRes(
                        response_code="OK",
                        dc_evse_status=_dc_evse_status_valid(),
                        evse_present_voltage=PVEVSEPresentVoltageDin(
                            multiplier=0, value=390, unit=UnitSymbol.VOLTAGE
                        ),
                    )
                ),
            )
        )
    )
    assert res.dc_ev_power_delivery_parameter.bulk_charging_complete is True
    assert res.dc_ev_power_delivery_parameter.dc_ev_status.ev_ress_soc == 88

    # --- PowerDeliveryRes -> CurrentDemandReq (full Cadillac envelope) -------
    res = _decode(
        await peer.feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    power_delivery_res=PowerDeliveryRes(
                        response_code="OK",
                        dc_evse_status=_dc_evse_status_valid(),
                    )
                ),
            )
        )
    )
    assert res.dc_ev_status.ev_ress_soc == 88
    assert res.ev_max_voltage_limit.get_decimal_value() == 410
    assert res.ev_max_current_limit.get_decimal_value() == 500
    assert res.bulk_charging_complete is True
    assert res.remaining_time_to_full_soc.get_decimal_value() == 2111
    assert res.remaining_time_to_bulk_soc.get_decimal_value() == 0
    # The Cadillac omits EVMaximumPowerLimit from CurrentDemandReq.
    assert res.ev_max_power_limit is None


@pytest.mark.asyncio
async def test_din_evcc_baseline_welding_detection_req_soc(exi_codec):
    """WeldingDetectionReq carries the pinned 88% SOC too."""
    session = _baseline_session()
    session.ongoing_timer = -1
    peer = ScriptedPeer(session, WeldingDetection)

    res = _decode(
        await peer.feed(
            V2GMessageDINSPEC(
                header=MessageHeader(session_id=session.session_id),
                body=Body(
                    welding_detection_res=WeldingDetectionRes(
                        response_code="OK",
                        dc_evse_status=_dc_evse_status_valid(),
                        evse_present_voltage=PVEVSEPresentVoltageDin(
                            multiplier=0, value=390, unit=UnitSymbol.VOLTAGE
                        ),
                    )
                ),
            )
        )
    )
    assert res.dc_ev_status.ev_ress_soc == 88
