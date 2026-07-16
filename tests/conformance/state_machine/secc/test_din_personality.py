"""State-machine layer: DIN personality fields surface on the wire (issue #7).

Sister to `test_din_session_setup.py`. Drives the SECC through the early DIN
states with a custom personality and asserts the outbound message fields
reflect that personality.
"""

from __future__ import annotations

import pytest

from app.secc.controller.simulator import SimEVSEController
from app.secc.states.din_spec_states import (
    ChargeParameterDiscovery,
    ContractAuthentication,
    ServiceDiscovery,
    ServicePaymentSelection,
    SessionSetup,
)
from app.shared.messages.din_spec.body import (
    Body,
    ChargeParameterDiscoveryReq,
    ContractAuthenticationReq,
    ServiceDiscoveryReq,
    ServicePaymentSelectionReq,
    SessionSetupReq,
)
from app.shared.messages.din_spec.datatypes import (
    DCEVChargeParameter,
    DCEVStatus,
    ServiceCategory,
)
from app.shared.messages.datatypes import (
    PVEVMaxCurrentLimitDin,
    PVEVMaxVoltageLimitDin,
    SelectedService,
    SelectedServiceList,
)
from app.shared.messages.din_spec.header import MessageHeader
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import (
    AuthEnum,
    DCEVErrorCode,
    EnergyTransferModeEnum,
    Namespace,
    Protocol,
    UnitSymbol,
)
from app.shared.personality.model import SECCPersonality
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession


@pytest.fixture
def variant_secc_personality() -> SECCPersonality:
    # Issue #73 / ADR-0006: the DIN SECC DC envelope is sourced from the message
    # field tree, not the retired structured `power.evse_dc` reads. Issue #81
    # extends that to the list-nested SAScheduleList — the tree declares the
    # whole SAScheduleTuple list (PMax included). With `identity` retired (#102)
    # the EVSEID is now a tree leaf too (SessionSetupRes.EVSEID); the energy mode
    # still rides the pre-tree `capabilities.energy_transfer_mode` seam (its own
    # tree migration is deferred), and the ServiceDiscoveryRes builder falls back
    # to it since the tree below does not pin an EnergyTransferType.
    return SECCPersonality.model_validate(
        {
            "capabilities": {
                "energy_transfer_mode": "DC_core",
                "supported_protocols": ["DIN_SPEC_70121"],
            },
            "message_field_tree": {
              "DIN_SPEC_70121": {
                "SessionSetupRes": {"EVSEID": "55AA66BB77"},
                "ChargeParameterDiscoveryRes": {
                    "SAScheduleList": {
                        "SAScheduleTuple": [
                            {
                                "SAScheduleTupleID": 1,
                                "PMaxSchedule": {
                                    "PMaxScheduleID": 1,
                                    "PMaxScheduleEntry": [
                                        {
                                            "PMax": 30000,
                                            "RelativeTimeInterval": {"start": 0},
                                        }
                                    ],
                                },
                            }
                        ]
                    },
                    "DC_EVSEChargeParameter": {
                        "EVSEMaximumVoltageLimit": {
                            "Value": 950,
                            "Multiplier": 0,
                            "Unit": "V",
                        },
                        "EVSEMaximumCurrentLimit": {
                            "Value": 350,
                            "Multiplier": 0,
                            "Unit": "A",
                        },
                        # 240000 W = 24000 x 10^1 (int16 value + multiplier).
                        "EVSEMaximumPowerLimit": {
                            "Value": 24000,
                            "Multiplier": 1,
                            "Unit": "W",
                        },
                        "EVSEMinimumVoltageLimit": {
                            "Value": 50,
                            "Multiplier": 0,
                            "Unit": "V",
                        },
                        "EVSEMinimumCurrentLimit": {
                            "Value": 5,
                            "Multiplier": 0,
                            "Unit": "A",
                        },
                        "EVSEPeakCurrentRipple": {
                            "Value": 7,
                            "Multiplier": 0,
                            "Unit": "A",
                        },
                    }
                }
              }
            },
        }
    )


class _StubWriter:
    """Minimal stand-in for the asyncio transport writer.

    `stop_state_machine` only reads `get_extra_info("peername")` off the
    writer when building the StopNotification; nothing in these tests sends
    bytes, so a peername is all it needs.
    """

    def get_extra_info(self, _key: str):
        return ("fe80::2", 0)


def _stub_secc_session(personality: SECCPersonality) -> StubCommSession:
    from app.secc.failed_responses import init_failed_responses_din_spec_70121
    from app.secc.secc_settings import Config
    from app.shared.personality.model import Runtime

    session = StubCommSession(
        protocol=Protocol.DIN_SPEC_70121,
        session_id=bytes(1).hex(),
    )
    session.evse_controller = SimEVSEController(personality=personality)
    session.config = Config.from_personality(personality, Runtime())
    session.offered_auth_options = []
    session.selected_auth_option = None
    session.selected_services = []
    session.charge_progress_started = False
    session.ongoing_timer = -1
    # The rejection path (`stop_state_machine`) needs a writer for the
    # StopNotification peername and the prebuilt failed-response table.
    session.writer = _StubWriter()
    session.failed_responses_din_spec = init_failed_responses_din_spec_70121()
    return session


@pytest.mark.asyncio
async def test_session_setup_emits_personality_evse_id(
    exi_codec, variant_secc_personality
):
    session = _stub_secc_session(variant_secc_personality)
    peer = ScriptedPeer(session, start_state=SessionSetup)

    req = V2GMessageDINSPEC(
        header=MessageHeader(session_id=bytes(1).hex()),
        body=Body(session_setup_req=SessionSetupReq(evcc_id="00112233445566")),
    )
    result = await peer.feed(req)

    assert result.outbound_msg.body.session_setup_res.evse_id == "55AA66BB77"


@pytest.mark.asyncio
async def test_service_discovery_emits_personality_energy_transfer_mode(
    exi_codec, variant_secc_personality
):
    session = _stub_secc_session(variant_secc_personality)
    peer = ScriptedPeer(session, start_state=ServiceDiscovery)

    req = V2GMessageDINSPEC(
        header=MessageHeader(session_id=session.session_id),
        body=Body(
            service_discovery_req=ServiceDiscoveryReq(
                service_category=ServiceCategory.CHARGING
            )
        ),
    )
    result = await peer.feed(req)

    charge_service = result.outbound_msg.body.service_discovery_res.charge_service
    assert charge_service.energy_transfer_type == EnergyTransferModeEnum.DC_CORE


@pytest.mark.asyncio
async def test_charge_parameter_discovery_emits_tree_dc_limits(
    exi_codec, variant_secc_personality
):
    """Issue #73/#81: the ChargeParameterDiscoveryRes DC envelope *and* the
    list-nested SAScheduleList are sourced from the message field tree
    (construction-time substitution at the build site)."""
    session = _stub_secc_session(variant_secc_personality)

    # Walk: ServicePaymentSelection so .selected_auth_option lands.
    session.offered_auth_options = [AuthEnum.EIM_V2]
    sps_peer = ScriptedPeer(session, start_state=ServicePaymentSelection)
    sps_req = V2GMessageDINSPEC(
        header=MessageHeader(session_id=session.session_id),
        body=Body(
            service_payment_selection_req=ServicePaymentSelectionReq(
                selected_payment_option=AuthEnum.EIM_V2,
                selected_service_list=SelectedServiceList(
                    selected_service=[SelectedService(service_id=1)]
                ),
            )
        ),
    )
    await sps_peer.feed(sps_req)

    # ContractAuthentication just flips processing to FINISHED → CPD.
    ca_peer = ScriptedPeer(session, start_state=ContractAuthentication)
    ca_req = V2GMessageDINSPEC(
        header=MessageHeader(session_id=session.session_id),
        body=Body(contract_authentication_req=ContractAuthenticationReq()),
    )
    await ca_peer.feed(ca_req)

    cpd_peer = ScriptedPeer(session, start_state=ChargeParameterDiscovery)
    cpd_req = V2GMessageDINSPEC(
        header=MessageHeader(session_id=session.session_id),
        body=Body(
            charge_parameter_discovery_req=ChargeParameterDiscoveryReq(
                requested_energy_mode=EnergyTransferModeEnum.DC_CORE,
                dc_ev_charge_parameter=DCEVChargeParameter(
                    dc_ev_status=DCEVStatus(
                        ev_ready=True,
                        ev_error_code=DCEVErrorCode.NO_ERROR,
                        ev_ress_soc=42,
                    ),
                    ev_maximum_current_limit=PVEVMaxCurrentLimitDin(
                        multiplier=0, value=80, unit=UnitSymbol.AMPERE
                    ),
                    ev_maximum_voltage_limit=PVEVMaxVoltageLimitDin(
                        multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
                    ),
                ),
            )
        ),
    )
    result = await cpd_peer.feed(cpd_req)

    res = result.outbound_msg.body.charge_parameter_discovery_res
    assert res.dc_charge_parameter.evse_maximum_voltage_limit.get_decimal_value() == 950.0
    assert res.dc_charge_parameter.evse_maximum_current_limit.get_decimal_value() == 350.0
    assert res.dc_charge_parameter.evse_maximum_power_limit.get_decimal_value() == 240000.0
    assert res.dc_charge_parameter.evse_minimum_voltage_limit.get_decimal_value() == 50.0
    assert res.dc_charge_parameter.evse_minimum_current_limit.get_decimal_value() == 5.0
    assert res.dc_charge_parameter.evse_peak_current_ripple.get_decimal_value() == 7.0

    # The SAScheduleList is tree-sourced (#81): one tuple, PMaxScheduleID 1,
    # one PMax entry at 30000 W starting at t=0 with duration omitted.
    [tuple_entry] = res.sa_schedule_list.values
    assert tuple_entry.sa_schedule_tuple_id == 1
    assert tuple_entry.p_max_schedule.p_max_schedule_id == 1
    [pmax_details] = tuple_entry.p_max_schedule.entry_details
    assert pmax_details.p_max == 30000
    assert pmax_details.time_interval.start == 0
    assert pmax_details.time_interval.duration is None


@pytest.mark.asyncio
async def test_charge_parameter_discovery_rejects_unoffered_energy_mode(
    exi_codec, variant_secc_personality
):
    """Issue #67: a DC_core SECC rejecting a DC_extended request must encode a
    clean negative ChargeParameterDiscoveryRes instead of crashing the codec.

    Drives the mode mismatch end-to-end: the rejection goes through
    `stop_state_machine` → `create_next_message`, which EXI-encodes the
    negative response. Before the fix the DIN `ResponseCode` carried the
    ISO-2 spelling `FAILED_WrongEnergyTransferMode`, which has no DIN v2gjson
    member, so the encode raised `EXIEncodingError`.
    """
    from app.shared.exi_codec import EXI
    from app.shared.messages.din_spec.datatypes import ResponseCode

    session = _stub_secc_session(variant_secc_personality)

    cpd_peer = ScriptedPeer(session, start_state=ChargeParameterDiscovery)
    cpd_req = V2GMessageDINSPEC(
        header=MessageHeader(session_id=session.session_id),
        body=Body(
            charge_parameter_discovery_req=ChargeParameterDiscoveryReq(
                requested_energy_mode=EnergyTransferModeEnum.DC_EXTENDED,
                dc_ev_charge_parameter=DCEVChargeParameter(
                    dc_ev_status=DCEVStatus(
                        ev_ready=True,
                        ev_error_code=DCEVErrorCode.NO_ERROR,
                        ev_ress_soc=42,
                    ),
                    ev_maximum_current_limit=PVEVMaxCurrentLimitDin(
                        multiplier=0, value=80, unit=UnitSymbol.AMPERE
                    ),
                    ev_maximum_voltage_limit=PVEVMaxVoltageLimitDin(
                        multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
                    ),
                ),
            )
        ),
    )

    # No EXIEncodingError raised here is the core of the regression.
    result = await cpd_peer.feed(cpd_req)

    # Negative response carries the DIN wrong-energy-transfer code and the
    # session is torn down.
    res = result.outbound_msg.body.charge_parameter_discovery_res
    assert res.response_code == ResponseCode.FAILED_WRONG_ENERGY_TRANSFER_TYPE
    assert session.stop_reason is not None
    assert not session.stop_reason.successful

    # The encoded bytes the SECC would put on the wire round-trip cleanly.
    encoded = result.outbound_v2gtp.payload
    decoded = EXI().from_exi_document(
        encoded, Namespace.DIN_MSG_DEF, model_cls=V2GMessageDINSPEC
    )
    assert (
        decoded.body.charge_parameter_discovery_res.response_code
        == ResponseCode.FAILED_WRONG_ENERGY_TRANSFER_TYPE
    )


# ---------------------------------------------------------------------------
# ADR-0006: the DIN energy transfer mode is single-sourced from the message
# field tree — the ServiceDiscoveryRes builder *and* the ChargeParameterDiscovery
# WrongEnergyTransferType reject-gate read the same tree entry, so advertised ==
# accepted by construction.
# ---------------------------------------------------------------------------


@pytest.fixture
def tree_sourced_secc_personality() -> SECCPersonality:
    """A DIN SECC whose energy mode comes only from the message field tree.

    `capabilities.energy_transfer_mode` is left at its DC_extended default, so
    any assertion that the SECC advertises/accepts DC_core proves the value was
    read from the tree — not from capabilities.
    """
    # This personality is DIN-exclusive, so the #83 load-time completeness check
    # runs: a ServiceDiscoveryRes present in the tree must spell out its other
    # required leaves (PaymentOptions / ServiceTag / FreeService) too. Only
    # EnergyTransferType matters to these tests — the rest is boilerplate to
    # satisfy completeness.
    return SECCPersonality.model_validate(
        {
            "capabilities": {"supported_protocols": ["DIN_SPEC_70121"]},
            "message_field_tree": {
              "DIN_SPEC_70121": {
                "ServiceDiscoveryRes": {
                    "PaymentOptions": {"PaymentOption": ["ExternalPayment"]},
                    "ChargeService": {
                        "ServiceTag": {
                            "ServiceID": 1,
                            "ServiceCategory": "EVCharging",
                        },
                        "FreeService": False,
                        "EnergyTransferType": "DC_core",
                    },
                }
              }
            },
        }
    )


@pytest.mark.asyncio
async def test_service_discovery_advertises_tree_energy_mode(
    exi_codec, tree_sourced_secc_personality
):
    session = _stub_secc_session(tree_sourced_secc_personality)
    peer = ScriptedPeer(session, start_state=ServiceDiscovery)

    req = V2GMessageDINSPEC(
        header=MessageHeader(session_id=session.session_id),
        body=Body(
            service_discovery_req=ServiceDiscoveryReq(
                service_category=ServiceCategory.CHARGING
            )
        ),
    )
    result = await peer.feed(req)

    charge_service = result.outbound_msg.body.service_discovery_res.charge_service
    # capabilities defaults to DC_extended, so DC_core can only come from the tree.
    assert charge_service.energy_transfer_type == EnergyTransferModeEnum.DC_CORE


@pytest.mark.asyncio
async def test_cpd_reject_gate_reads_tree_advertised_mode(
    exi_codec, tree_sourced_secc_personality
):
    """The reject-gate compares the EV's requested mode against the tree's
    advertised EnergyTransferType. A DC_extended request against a DC_core tree
    is rejected even though `capabilities` still defaults to DC_extended."""
    from app.shared.messages.din_spec.datatypes import ResponseCode

    session = _stub_secc_session(tree_sourced_secc_personality)
    cpd_peer = ScriptedPeer(session, start_state=ChargeParameterDiscovery)
    cpd_req = V2GMessageDINSPEC(
        header=MessageHeader(session_id=session.session_id),
        body=Body(
            charge_parameter_discovery_req=ChargeParameterDiscoveryReq(
                requested_energy_mode=EnergyTransferModeEnum.DC_EXTENDED,
                dc_ev_charge_parameter=DCEVChargeParameter(
                    dc_ev_status=DCEVStatus(
                        ev_ready=True,
                        ev_error_code=DCEVErrorCode.NO_ERROR,
                        ev_ress_soc=42,
                    ),
                    ev_maximum_current_limit=PVEVMaxCurrentLimitDin(
                        multiplier=0, value=80, unit=UnitSymbol.AMPERE
                    ),
                    ev_maximum_voltage_limit=PVEVMaxVoltageLimitDin(
                        multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
                    ),
                ),
            )
        ),
    )
    result = await cpd_peer.feed(cpd_req)

    res = result.outbound_msg.body.charge_parameter_discovery_res
    assert res.response_code == ResponseCode.FAILED_WRONG_ENERGY_TRANSFER_TYPE
    assert session.stop_reason is not None and not session.stop_reason.successful
