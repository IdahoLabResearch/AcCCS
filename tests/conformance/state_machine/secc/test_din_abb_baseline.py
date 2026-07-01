"""The shipped `din-secc-baseline` reproduces the ABB charger field-for-field.

Issue #73 / ADR-0006: the DIN SECC baseline replicates the ABB charger from
`ABB_Cadillac_Lyric.pcapng`. This drives the SECC through a full DIN session
with the shipped `personalities/din-secc-baseline.yaml`, decodes the bytes the
SECC actually put on the wire for each `*Res`, and asserts every ABB baseline
field — proving the message field tree reaches the wire for the whole SECC DIN
path, not just the one field wired in #71.

Runtime/computed fields (SessionID, DateTimeNow, present voltage/current, the
CurrentDemandRes limit-achieved flags) are deliberately NOT asserted — the
baseline leaves them computed. The isolation-status progression (Invalid /
IsolationMonitoringActive through ChargeParameterDiscoveryRes + CableCheckRes,
then Valid / EVSE_Ready from PreChargeRes on) is the headline behaviour.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.secc.controller.simulator import SimEVSEController
from app.secc.states.din_spec_states import (
    CableCheck,
    ChargeParameterDiscovery,
    ContractAuthentication,
    CurrentDemand,
    PowerDelivery,
    PreCharge,
    ServiceDiscovery,
    ServicePaymentSelection,
    SessionSetup,
    SessionStop,
    WeldingDetection,
)
from app.shared.exi_codec import EXI
from app.shared.messages.datatypes import (
    PVEVTargetCurrentDin,
    PVEVTargetVoltageDin,
    PVEVMaxCurrentLimitDin,
    PVEVMaxVoltageLimitDin,
    SelectedService,
    SelectedServiceList,
)
from app.shared.messages.din_spec.body import (
    Body,
    CableCheckReq,
    ChargeParameterDiscoveryReq,
    ContractAuthenticationReq,
    CurrentDemandReq,
    PowerDeliveryReq,
    PreChargeReq,
    ServiceDiscoveryReq,
    ServicePaymentSelectionReq,
    SessionSetupReq,
    SessionStopReq,
    WeldingDetectionReq,
)
from app.shared.messages.din_spec.datatypes import (
    DCEVChargeParameter,
    DCEVPowerDeliveryParameter,
    DCEVSEStatusCode,
    DCEVStatus,
    ServiceCategory,
)
from app.shared.messages.din_spec.header import MessageHeader
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import (
    AuthEnum,
    DCEVErrorCode,
    EnergyTransferModeEnum,
    EVSEProcessing,
    IsolationLevel,
    Namespace,
    UnitSymbol,
)
from app.shared.personality.loader import load_personality
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession

PERSONALITIES_DIR = Path(__file__).resolve().parents[4] / "personalities"


class _StubWriter:
    def get_extra_info(self, _key: str):
        return ("fe80::2", 0)


def _baseline_session() -> StubCommSession:
    from app.secc.failed_responses import init_failed_responses_din_spec_70121
    from app.secc.secc_settings import Config
    from app.shared.messages.enums import Protocol
    from app.shared.personality.model import Runtime

    personality = load_personality(
        str(PERSONALITIES_DIR / "din-secc-baseline.yaml"), "secc"
    )
    session = StubCommSession(
        protocol=Protocol.DIN_SPEC_70121, session_id=bytes(1).hex()
    )
    session.evse_controller = SimEVSEController(personality=personality)
    session.config = Config.from_personality(personality, Runtime())
    session.offered_auth_options = []
    session.selected_auth_option = None
    session.selected_services = []
    session.charge_progress_started = False
    session.ongoing_timer = -1
    session.writer = _StubWriter()
    session.failed_responses_din_spec = init_failed_responses_din_spec_70121()
    return session


def _dc_ev_status() -> DCEVStatus:
    return DCEVStatus(
        ev_ready=True, ev_error_code=DCEVErrorCode.NO_ERROR, ev_ress_soc=42
    )


def _decode(result):
    """Decode the SECC's outbound wire bytes back into the DIN message."""
    payload = result.outbound_v2gtp.payload
    return EXI().from_exi_document(payload, Namespace.DIN_MSG_DEF).body.get_message()


@pytest.mark.asyncio
async def test_din_secc_baseline_reproduces_abb_capture(exi_codec):
    session = _baseline_session()
    hdr = lambda: MessageHeader(session_id=session.session_id)  # noqa: E731

    # --- SessionSetupRes: EVSEID "00" (ABB reports no ID) --------------------
    res = _decode(
        await ScriptedPeer(session, SessionSetup).feed(
            V2GMessageDINSPEC(
                header=MessageHeader(session_id=bytes(1).hex()),
                body=Body(
                    session_setup_req=SessionSetupReq(evcc_id="00112233445566")
                ),
            )
        )
    )
    assert res.evse_id == "00"

    # --- ServiceDiscoveryRes -------------------------------------------------
    session.offered_auth_options = [AuthEnum.EIM_V2]
    res = _decode(
        await ScriptedPeer(session, ServiceDiscovery).feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    service_discovery_req=ServiceDiscoveryReq(
                        service_category=ServiceCategory.CHARGING
                    )
                ),
            )
        )
    )
    assert res.auth_option_list.auth_options == [AuthEnum.EIM_V2]  # ExternalPayment
    assert res.charge_service.service_tag.service_id == 1
    assert res.charge_service.service_tag.service_category == ServiceCategory.CHARGING
    assert res.charge_service.free_service is False
    assert (
        res.charge_service.energy_transfer_type == EnergyTransferModeEnum.DC_EXTENDED
    )

    # --- ServicePaymentSelectionRes ------------------------------------------
    await ScriptedPeer(session, ServicePaymentSelection).feed(
        V2GMessageDINSPEC(
            header=hdr(),
            body=Body(
                service_payment_selection_req=ServicePaymentSelectionReq(
                    selected_payment_option=AuthEnum.EIM_V2,
                    selected_service_list=SelectedServiceList(
                        selected_service=[SelectedService(service_id=1)]
                    ),
                )
            ),
        )
    )

    # --- ContractAuthenticationRes -------------------------------------------
    await ScriptedPeer(session, ContractAuthentication).feed(
        V2GMessageDINSPEC(
            header=hdr(),
            body=Body(contract_authentication_req=ContractAuthenticationReq()),
        )
    )

    # --- ChargeParameterDiscoveryRes: full ABB DC envelope, Invalid isolation -
    res = _decode(
        await ScriptedPeer(session, ChargeParameterDiscovery).feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    charge_parameter_discovery_req=ChargeParameterDiscoveryReq(
                        requested_energy_mode=EnergyTransferModeEnum.DC_EXTENDED,
                        dc_ev_charge_parameter=DCEVChargeParameter(
                            dc_ev_status=_dc_ev_status(),
                            ev_maximum_current_limit=PVEVMaxCurrentLimitDin(
                                multiplier=0, value=60, unit=UnitSymbol.AMPERE
                            ),
                            ev_maximum_voltage_limit=PVEVMaxVoltageLimitDin(
                                multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
                            ),
                        ),
                    )
                ),
            )
        )
    )
    dcp = res.dc_charge_parameter
    assert dcp.dc_evse_status.evse_isolation_status == IsolationLevel.INVALID
    assert (
        dcp.dc_evse_status.evse_status_code
        == DCEVSEStatusCode.EVSE_ISOLATION_MONITORING_ACTIVE
    )
    assert dcp.dc_evse_status.notification_max_delay == 0
    assert dcp.evse_maximum_voltage_limit.get_decimal_value() == 451
    assert dcp.evse_maximum_current_limit.get_decimal_value() == 60
    assert dcp.evse_maximum_power_limit.get_decimal_value() == 24000
    assert dcp.evse_minimum_voltage_limit.get_decimal_value() == 150
    assert dcp.evse_minimum_current_limit.get_decimal_value() == 1
    assert dcp.evse_peak_current_ripple.get_decimal_value() == 3
    # SAScheduleList PMax stays sourced from evse_dc (list-nested).
    [tuple_entry] = res.sa_schedule_list.values
    [pmax_details] = tuple_entry.p_max_schedule.entry_details
    assert pmax_details.p_max == 24000

    # --- CableCheckRes: Invalid / IsolationMonitoringActive while monitoring,
    # then Valid / EVSE_Ready on the completing (FINISHED) response — the ABB
    # progression from ABB_Cadillac_Lyric.pcapng (frames 316-465 Invalid, frame
    # 469 Valid). The completing flip is what lets a conformant EVCC advance.
    cc = ScriptedPeer(session, CableCheck)
    # First feed: contactors close, isolation monitoring still Ongoing.
    res = _decode(
        await cc.feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(cable_check_req=CableCheckReq(dc_ev_status=_dc_ev_status())),
            )
        )
    )
    assert res.evse_processing != EVSEProcessing.FINISHED
    assert res.dc_evse_status.evse_isolation_status == IsolationLevel.INVALID
    assert (
        res.dc_evse_status.evse_status_code
        == DCEVSEStatusCode.EVSE_ISOLATION_MONITORING_ACTIVE
    )
    # Second feed: isolation complete → FINISHED, isolation flips to Valid.
    res = _decode(
        await cc.feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(cable_check_req=CableCheckReq(dc_ev_status=_dc_ev_status())),
            )
        )
    )
    assert res.evse_processing == EVSEProcessing.FINISHED
    assert res.dc_evse_status.evse_isolation_status == IsolationLevel.VALID
    assert res.dc_evse_status.evse_status_code == DCEVSEStatusCode.EVSE_READY

    # --- PreChargeRes: isolation now Valid / EVSE_Ready ----------------------
    res = _decode(
        await ScriptedPeer(session, PreCharge).feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    pre_charge_req=PreChargeReq(
                        dc_ev_status=_dc_ev_status(),
                        ev_target_voltage=PVEVTargetVoltageDin(
                            multiplier=0, value=390, unit=UnitSymbol.VOLTAGE
                        ),
                        ev_target_current=PVEVTargetCurrentDin(
                            multiplier=0, value=1, unit=UnitSymbol.AMPERE
                        ),
                    )
                ),
            )
        )
    )
    assert res.dc_evse_status.evse_isolation_status == IsolationLevel.VALID
    assert res.dc_evse_status.evse_status_code == DCEVSEStatusCode.EVSE_READY

    # --- PowerDeliveryRes: Valid / EVSE_Ready --------------------------------
    res = _decode(
        await ScriptedPeer(session, PowerDelivery).feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    power_delivery_req=PowerDeliveryReq(
                        ready_to_charge=True,
                        dc_ev_power_delivery_parameter=DCEVPowerDeliveryParameter(
                            dc_ev_status=_dc_ev_status(), charging_complete=False
                        ),
                    )
                ),
            )
        )
    )
    assert res.dc_evse_status.evse_isolation_status == IsolationLevel.VALID
    assert res.dc_evse_status.evse_status_code == DCEVSEStatusCode.EVSE_READY

    # --- CurrentDemandRes: Valid, and echoes the max V/A/W envelope ----------
    res = _decode(
        await ScriptedPeer(session, CurrentDemand).feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    current_demand_req=CurrentDemandReq(
                        dc_ev_status=_dc_ev_status(),
                        ev_target_current=PVEVTargetCurrentDin(
                            multiplier=0, value=60, unit=UnitSymbol.AMPERE
                        ),
                        ev_target_voltage=PVEVTargetVoltageDin(
                            multiplier=0, value=390, unit=UnitSymbol.VOLTAGE
                        ),
                        charging_complete=False,
                    )
                ),
            )
        )
    )
    assert res.dc_evse_status.evse_isolation_status == IsolationLevel.VALID
    assert res.dc_evse_status.evse_status_code == DCEVSEStatusCode.EVSE_READY
    assert res.evse_max_voltage_limit.get_decimal_value() == 451
    assert res.evse_max_current_limit.get_decimal_value() == 60
    assert res.evse_max_power_limit.get_decimal_value() == 24000

    # --- WeldingDetectionRes: Valid / EVSE_Ready -----------------------------
    res = _decode(
        await ScriptedPeer(session, WeldingDetection).feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    welding_detection_req=WeldingDetectionReq(
                        dc_ev_status=_dc_ev_status()
                    )
                ),
            )
        )
    )
    assert res.dc_evse_status.evse_isolation_status == IsolationLevel.VALID
    assert res.dc_evse_status.evse_status_code == DCEVSEStatusCode.EVSE_READY

    # --- SessionStopRes ------------------------------------------------------
    res = _decode(
        await ScriptedPeer(session, SessionStop).feed(
            V2GMessageDINSPEC(
                header=hdr(), body=Body(session_stop_req=SessionStopReq())
            )
        )
    )
    assert res is not None
