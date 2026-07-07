"""Every #83 allowlist entry has a real builder fallback (empty-tree build).

ADR-0006 #83 makes the optional-field allowlist a **standalone** statement of
which required DIN wire fields the emulator produces on its own at runtime — so
they may be omitted from the message field tree. This test is the guard that the
list cannot lie: it drives both roles through a full DIN session with an
**empty-tree** personality (`SECCPersonality()` / `EVCCPersonality()`), so every
message is built purely from the builders' computed values, then asserts each
allowlisted leaf still populates. A liar entry — a field claimed
emulator-produced that the builder does *not* set — would either fail message
construction outright (the fields are all Pydantic-required) or surface here as
a `None`, rather than silently relocating a mid-session crash.

The load-time behaviour of the check itself lives in
`tests/personality/test_completeness.py`.
"""

from __future__ import annotations

import pytest

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.evcc.states.din_spec_states import (
    SessionSetup as EVCCSessionSetup,
    WeldingDetection as EVCCWeldingDetection,
)
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
    DCEVSEStatus,
    PVEVSEPresentVoltageDin,
    PVEVMaxCurrentLimitDin,
    PVEVMaxVoltageLimitDin,
    PVEVTargetCurrentDin,
    PVEVTargetVoltageDin,
    SelectedService,
    SelectedServiceList,
)
from app.shared.messages.din_spec.body import (
    Body,
    CableCheckReq,
    CableCheckRes,
    ChargeParameterDiscoveryReq,
    ChargeParameterDiscoveryRes,
    ContractAuthenticationReq,
    ContractAuthenticationRes,
    CurrentDemandReq,
    PowerDeliveryReq,
    PowerDeliveryRes,
    PreChargeReq,
    PreChargeRes,
    ServiceDiscoveryReq,
    ServiceDiscoveryRes,
    ServicePaymentSelectionReq,
    ServicePaymentSelectionRes,
    SessionSetupReq,
    SessionSetupRes,
    SessionStopReq,
    WeldingDetectionReq,
    WeldingDetectionRes,
)
from app.shared.messages.din_spec.datatypes import (
    AuthOptionList,
    ChargeService,
    DCEVChargeParameter,
    DCEVPowerDeliveryParameter,
    DCEVSEStatusCode,
    DCEVStatus,
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
    DCEVErrorCode,
    EnergyTransferModeEnum,
    EVSEProcessing,
    IsolationLevel,
    Namespace,
    Protocol,
    UnitSymbol,
)
from app.shared.personality.completeness import allowlist_for
from app.shared.personality.model import EVCCPersonality, Runtime, SECCPersonality
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession


class _StubWriter:
    def get_extra_info(self, _key: str):
        return ("fe80::2", 0)


def _decode(result):
    payload = result.outbound_v2gtp.payload
    return EXI().from_exi_document(payload, Namespace.DIN_MSG_DEF).body.get_message()


def _resolve(obj, path):
    """Walk a Python-name leaf path over a built message; None if any hop is None."""
    cursor = obj
    for name in path:
        if cursor is None:
            return None
        cursor = getattr(cursor, name, None)
    return cursor


def _dc_ev_status() -> DCEVStatus:
    return DCEVStatus(
        ev_ready=True, ev_error_code=DCEVErrorCode.NO_ERROR, ev_ress_soc=42
    )


def _dc_evse_status_valid() -> DCEVSEStatus:
    return DCEVSEStatus(
        notification_max_delay=0,
        evse_notification=EVSENotification.NONE,
        evse_isolation_status=IsolationLevel.VALID,
        evse_status_code=DCEVSEStatusCode.EVSE_READY,
    )


def _assert_allowlist_populated(role, captured):
    """Every allowlist entry for a captured message must resolve to a value."""
    missing = []
    for message_name, paths in allowlist_for(role).items():
        message = captured.get(message_name)
        if message is None:
            continue
        for path in paths:
            if _resolve(message, path) is None:
                missing.append(f"{message_name} -> {' -> '.join(path)}")
    assert not missing, (
        f"{role} allowlist entries not populated by the empty-tree builder: "
        f"{missing}"
    )


# ---------------------------------------------------------------------------
# SECC — full session with an empty-tree personality
# ---------------------------------------------------------------------------


def _secc_session() -> StubCommSession:
    from app.secc.failed_responses import init_failed_responses_din_spec_70121
    from app.secc.secc_settings import Config

    personality = SECCPersonality()  # empty message_field_tree
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


@pytest.mark.asyncio
async def test_secc_allowlist_entries_populate_from_empty_tree(exi_codec):
    session = _secc_session()
    hdr = lambda: MessageHeader(session_id=session.session_id)  # noqa: E731
    captured = {}

    captured["SessionSetupRes"] = _decode(
        await ScriptedPeer(session, SessionSetup).feed(
            V2GMessageDINSPEC(
                header=MessageHeader(session_id=bytes(1).hex()),
                body=Body(session_setup_req=SessionSetupReq(evcc_id="00112233445566")),
            )
        )
    )

    session.offered_auth_options = [AuthEnum.EIM_V2]
    captured["ServiceDiscoveryRes"] = _decode(
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

    captured["ServicePaymentSelectionRes"] = _decode(
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
    )

    captured["ContractAuthenticationRes"] = _decode(
        await ScriptedPeer(session, ContractAuthentication).feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(contract_authentication_req=ContractAuthenticationReq()),
            )
        )
    )

    captured["ChargeParameterDiscoveryRes"] = _decode(
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

    cc = ScriptedPeer(session, CableCheck)
    captured["CableCheckRes"] = _decode(
        await cc.feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(cable_check_req=CableCheckReq(dc_ev_status=_dc_ev_status())),
            )
        )
    )
    # Second feed → FINISHED; keep the completing frame (EVSEProcessing populated).
    captured["CableCheckRes"] = _decode(
        await cc.feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(cable_check_req=CableCheckReq(dc_ev_status=_dc_ev_status())),
            )
        )
    )

    captured["PreChargeRes"] = _decode(
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

    captured["PowerDeliveryRes"] = _decode(
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

    captured["CurrentDemandRes"] = _decode(
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

    captured["WeldingDetectionRes"] = _decode(
        await ScriptedPeer(session, WeldingDetection).feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    welding_detection_req=WeldingDetectionReq(dc_ev_status=_dc_ev_status())
                ),
            )
        )
    )

    captured["SessionStopRes"] = _decode(
        await ScriptedPeer(session, SessionStop).feed(
            V2GMessageDINSPEC(
                header=hdr(), body=Body(session_stop_req=SessionStopReq())
            )
        )
    )

    _assert_allowlist_populated("secc", captured)


# ---------------------------------------------------------------------------
# EVCC — full session with an empty-tree personality
# ---------------------------------------------------------------------------


def _evcc_session() -> StubCommSession:
    personality = EVCCPersonality()  # empty message_field_tree
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


@pytest.mark.asyncio
async def test_evcc_allowlist_entries_populate_from_empty_tree(exi_codec):
    session = _evcc_session()
    hdr = lambda: MessageHeader(session_id=session.session_id)  # noqa: E731
    peer = ScriptedPeer(session, EVCCSessionSetup)
    captured = {}

    # SessionSetupRes -> ServiceDiscoveryReq
    _decode(
        await peer.feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    session_setup_res=SessionSetupRes(response_code="OK", evse_id="00")
                ),
            )
        )
    )

    # ServiceDiscoveryRes -> ServicePaymentSelectionReq. Advertise a ServiceID
    # the well-known enum does NOT name (4660 / 0x1234, as the Tellus Power
    # charger does) so the capture proves the EVCC echoes the advertised value
    # rather than a static tree pin — the builder fallback the allowlist claims.
    captured["ServicePaymentSelectionReq"] = _decode(
        await peer.feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    service_discovery_res=ServiceDiscoveryRes(
                        response_code="OK",
                        auth_option_list=AuthOptionList(auth_options=[AuthEnum.EIM_V2]),
                        charge_service=ChargeService(
                            service_tag=ServiceDetails(
                                service_id=4660,
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
    # The echoed ServiceID must be the advertised 4660, not a static pin.
    [echoed] = captured["ServicePaymentSelectionReq"].selected_service_list.selected_service
    assert echoed.service_id == 4660

    # ServicePaymentSelectionRes -> ContractAuthenticationReq
    _decode(
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

    # ContractAuthenticationRes(FINISHED) -> ChargeParameterDiscoveryReq
    captured["ChargeParameterDiscoveryReq"] = _decode(
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

    # ChargeParameterDiscoveryRes(FINISHED) -> CableCheckReq
    captured["CableCheckReq"] = _decode(
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

    # CableCheckRes(FINISHED) -> PreChargeReq
    captured["PreChargeReq"] = _decode(
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

    # PreChargeRes -> PowerDeliveryReq (force the precharge loop complete)
    session.ev_controller.precharge_loop_cycles = 5
    captured["PowerDeliveryReq"] = _decode(
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

    # PowerDeliveryRes -> CurrentDemandReq
    captured["CurrentDemandReq"] = _decode(
        await peer.feed(
            V2GMessageDINSPEC(
                header=hdr(),
                body=Body(
                    power_delivery_res=PowerDeliveryRes(
                        response_code="OK", dc_evse_status=_dc_evse_status_valid()
                    )
                ),
            )
        )
    )

    # WeldingDetectionReq (driven from its own state, as in the baseline test)
    wd_peer = ScriptedPeer(session, EVCCWeldingDetection)
    captured["WeldingDetectionReq"] = _decode(
        await wd_peer.feed(
            V2GMessageDINSPEC(
                header=hdr(),
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

    _assert_allowlist_populated("evcc", captured)


@pytest.mark.asyncio
async def test_evcc_session_setup_evcc_id_has_builder_fallback():
    """SessionSetupReq.EVCCID is emitted before the DIN state machine runs, so it
    is covered here rather than in the driven session. For DIN the EVCCID is the
    NIC MAC produced at runtime (not the VIN-shaped identity.evcc_id, which is the
    ISO-20 EVCCID) — with an empty-tree personality `get_evcc_id` still resolves a
    non-empty value (the MAC, or the '000000000000' fallback when the virtual NIC
    is absent), and a SessionSetupReq built from it validates."""
    personality = EVCCPersonality()
    controller = SimEVController(EVCCConfig.from_personality(personality))
    evcc_id = await controller.get_evcc_id(
        Protocol.DIN_SPEC_70121, personality.residual.network.interface
    )
    assert evcc_id
    req = SessionSetupReq(evcc_id=evcc_id)
    assert req.evcc_id == evcc_id
