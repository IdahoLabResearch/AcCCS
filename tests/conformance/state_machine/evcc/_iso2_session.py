"""Shared ISO-15118-2 EVCC DC-session driver for the #97 state-machine tests.

Drives the real EVCC ISO-2 states through `process_message()` at the ADR-0003
seam, feeding scripted SECC ``*Res`` messages for a full DC/EIM session and
returning the ``*Req`` the EVCC actually put on the wire for each step, decoded
back through the EXI codec. Both the Mach-E baseline-reproduction test and the
allowlist-fallback guard drive the same sequence — the first with the shipped
`iso2-evcc-baseline`, the second with an empty-tree personality.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.evcc.states.iso15118_2_states import SessionSetup
from app.shared.exi_codec import EXI
from app.shared.messages.datatypes import (
    DCEVSEStatus,
    DCEVSEStatusCode,
    EVSENotification,
    PVEVSEPresentVoltage,
    PVPMax,
)
from app.shared.messages.enums import (
    AuthEnum,
    EnergyTransferModeEnum,
    EVSEProcessing,
    IsolationLevel,
    Namespace,
    Protocol,
    UnitSymbol,
)
from app.shared.messages.iso15118_2.body import (
    AuthorizationRes,
    Body,
    CableCheckRes,
    ChargeParameterDiscoveryRes,
    CurrentDemandRes,
    PaymentServiceSelectionRes,
    PowerDeliveryRes,
    PreChargeRes,
    ResponseCode,
    ServiceDiscoveryRes,
    SessionSetupRes,
    WeldingDetectionRes,
)
from app.shared.messages.iso15118_2.datatypes import (
    ChargeService,
    EnergyTransferModeList,
    PMaxSchedule,
    PMaxScheduleEntry,
    RelativeTimeInterval,
    SAScheduleList,
    SAScheduleTuple,
    ServiceCategory,
)
from app.shared.messages.iso15118_2.datatypes import (
    AuthOptionList,
)
from app.shared.messages.iso15118_2.header import MessageHeader
from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from app.shared.personality.loader import load_personality
from app.shared.personality.model import EVCCPersonality
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession

PERSONALITIES_DIR = Path(__file__).resolve().parents[4] / "personalities"


def baseline_session() -> StubCommSession:
    """A session driven by the shipped `iso2-evcc-baseline` (tree-backed)."""
    personality = load_personality(
        str(PERSONALITIES_DIR / "iso2-evcc-baseline.yaml"), "evcc"
    )
    return _session(EVCCConfig.from_personality(personality))


def empty_tree_session() -> StubCommSession:
    """A session driven by an empty-tree personality (builder fallbacks only)."""
    return _session(EVCCConfig.from_personality(EVCCPersonality()))


def _session(config: EVCCConfig) -> StubCommSession:
    session = StubCommSession(protocol=Protocol.ISO_15118_2, session_id=bytes(1).hex())
    session.config = config
    session.ev_controller = SimEVController(config)
    session.live_control = None
    session.is_tls = False
    session.selected_auth_option = None
    session.selected_services = []
    session.selected_energy_mode = None
    session.selected_charging_type_is_ac = False
    session.selected_schedule = None
    session.charging_session_stop_v2 = None
    session.renegotiation_requested = False
    session.service_details_to_request = []
    session.ongoing_timer = -1
    return session


def _hdr(session: StubCommSession) -> MessageHeader:
    return MessageHeader(session_id=session.session_id)


def _decode(result):
    """Decode the EVCC's outbound wire bytes back into the ISO-2 Req message."""
    payload = result.outbound_v2gtp.payload
    return EXI().from_exi_document(payload, Namespace.ISO_V2_MSG_DEF).body.get_message()


def _dc_evse_status(status_code, isolation) -> DCEVSEStatus:
    return DCEVSEStatus(
        notification_max_delay=0,
        evse_notification=EVSENotification.NONE,
        evse_isolation_status=isolation,
        evse_status_code=status_code,
    )


def _sa_schedule_list() -> SAScheduleList:
    return SAScheduleList(
        schedule_tuples=[
            SAScheduleTuple(
                sa_schedule_tuple_id=1,
                p_max_schedule=PMaxSchedule(
                    schedule_entries=[
                        PMaxScheduleEntry(
                            p_max=PVPMax(multiplier=1, value=20000, unit=UnitSymbol.WATT),
                            time_interval=RelativeTimeInterval(start=0),
                        )
                    ]
                ),
            )
        ]
    )


async def drive_dc_session(session: StubCommSession) -> Dict[str, object]:
    """Drive a full ISO-2 DC/EIM session; return each emitted ``*Req`` by name.

    Feeds the scripted SECC ``*Res`` sequence for a clean DC session and captures
    the decoded ``*Req`` the EVCC emits at every step. The charge loop is walked
    once, then stopped so WeldingDetection and SessionStop are reached.
    """
    reqs: Dict[str, object] = {}
    peer = ScriptedPeer(session, SessionSetup)

    async def feed(body: Body):
        return await peer.feed(V2GMessageV2(header=_hdr(session), body=body))

    def valid_status() -> DCEVSEStatus:
        return _dc_evse_status(DCEVSEStatusCode.EVSE_READY, IsolationLevel.VALID)

    reqs["ServiceDiscoveryReq"] = _decode(
        await feed(
            Body(
                session_setup_res=SessionSetupRes(
                    response_code="OK", evse_id="USFRDE9001"
                )
            )
        )
    )
    reqs["PaymentServiceSelectionReq"] = _decode(
        await feed(
            Body(
                service_discovery_res=ServiceDiscoveryRes(
                    response_code="OK",
                    auth_option_list=AuthOptionList(auth_options=[AuthEnum.EIM_V2]),
                    charge_service=ChargeService(
                        service_id=1,
                        service_category=ServiceCategory.CHARGING,
                        free_service=False,
                        supported_energy_transfer_mode=EnergyTransferModeList(
                            energy_modes=[EnergyTransferModeEnum.DC_EXTENDED]
                        ),
                    ),
                )
            )
        )
    )
    reqs["AuthorizationReq"] = _decode(
        await feed(
            Body(
                payment_service_selection_res=PaymentServiceSelectionRes(
                    response_code="OK"
                )
            )
        )
    )
    reqs["ChargeParameterDiscoveryReq"] = _decode(
        await feed(
            Body(
                authorization_res=AuthorizationRes(
                    response_code="OK", evse_processing=EVSEProcessing.FINISHED
                )
            )
        )
    )
    reqs["CableCheckReq"] = _decode(
        await feed(
            Body(
                charge_parameter_discovery_res=ChargeParameterDiscoveryRes(
                    response_code="OK",
                    evse_processing=EVSEProcessing.FINISHED,
                    sa_schedule_list=_sa_schedule_list(),
                )
            )
        )
    )
    reqs["PreChargeReq"] = _decode(
        await feed(
            Body(
                cable_check_res=CableCheckRes(
                    response_code="OK",
                    dc_evse_status=valid_status(),
                    evse_processing=EVSEProcessing.FINISHED,
                )
            )
        )
    )
    # Force the precharge loop complete so the EVCC advances to PowerDelivery.
    session.ev_controller.precharge_loop_cycles = 5
    reqs["PowerDeliveryReq"] = _decode(
        await feed(
            Body(
                pre_charge_res=PreChargeRes(
                    response_code="OK",
                    dc_evse_status=valid_status(),
                    evse_present_voltage=PVEVSEPresentVoltage(
                        multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
                    ),
                )
            )
        )
    )
    reqs["CurrentDemandReq"] = _decode(
        await feed(
            Body(
                power_delivery_res=PowerDeliveryRes(
                    response_code="OK", dc_evse_status=valid_status()
                )
            )
        )
    )
    # Stop charging so the loop exits to PowerDelivery(STOP) -> WeldingDetection.
    session.ev_controller._charging_is_completed = True
    reqs["PowerDeliveryReq_stop"] = _decode(
        await feed(
            Body(
                current_demand_res=CurrentDemandRes.model_construct(
                    response_code=ResponseCode.OK, dc_evse_status=valid_status()
                )
            )
        )
    )
    reqs["WeldingDetectionReq"] = _decode(
        await feed(
            Body(
                power_delivery_res=PowerDeliveryRes(
                    response_code="OK", dc_evse_status=valid_status()
                )
            )
        )
    )
    # WeldingDetection loops a few times before finishing; walk it to SessionStop.
    for _ in range(6):
        result = await feed(
            Body(
                welding_detection_res=WeldingDetectionRes(
                    response_code="OK",
                    dc_evse_status=valid_status(),
                    evse_present_voltage=PVEVSEPresentVoltage(
                        multiplier=0, value=10, unit=UnitSymbol.VOLTAGE
                    ),
                )
            )
        )
        emitted = _decode(result)
        if type(emitted).__name__ == "SessionStopReq":
            reqs["SessionStopReq"] = emitted
            break
    return reqs
