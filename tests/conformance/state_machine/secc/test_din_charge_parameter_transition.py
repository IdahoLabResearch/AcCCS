"""SECC DIN `ChargeParameterDiscovery` advance is decoupled from the schedule.

Regression for #86 (a #83 follow-up). The advance-to-`CableCheck` transition
used to piggyback on the truthiness of the retired
`get_sa_schedule_list_dinspec` constant scaffold — the same call that built the
`SAScheduleList`. That entanglement is gone: the transition is now stated
directly (`EVSEProcessing.FINISHED` + `CableCheck`), and the `SAScheduleList`
is a wire value with a pre-tree builder default that a personality's
`ChargeParameterDiscoveryRes -> SAScheduleList` tree overrides wholesale.

This drives the real SECC state through `process_message()` at the ADR-0003
state-machine seam with an **empty-tree** personality (the pre-tree path,
ADR-0006 #83) and asserts:

- the response reports `EVSEProcessing.FINISHED` and hands off to `CableCheck`
  regardless of the schedule; and
- the emitted `SAScheduleList` is **non-empty** — the EVCC's
  `process_sa_schedules_dinspec` pops a tuple off it, so an empty list would
  crash the peer.
"""

from __future__ import annotations

import pytest

from app.secc.controller.simulator import SimEVSEController
from app.secc.states.din_spec_states import CableCheck, ChargeParameterDiscovery
from app.shared.messages.datatypes import (
    PVEVMaxCurrentLimitDin,
    PVEVMaxVoltageLimitDin,
)
from app.shared.messages.din_spec.body import Body, ChargeParameterDiscoveryReq
from app.shared.messages.din_spec.datatypes import DCEVChargeParameter, DCEVStatus
from app.shared.messages.din_spec.header import MessageHeader
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import (
    AuthEnum,
    DCEVErrorCode,
    EnergyTransferModeEnum,
    EVSEProcessing,
    Protocol,
    UnitSymbol,
)
from app.shared.personality.model import SECCPersonality
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession


def _empty_tree_secc_session() -> StubCommSession:
    """A DIN SECC session driven by the default (empty message_field_tree)
    personality — the pre-tree builder path (ADR-0006 #83)."""
    controller = SimEVSEController(personality=SECCPersonality())
    controller.set_selected_protocol(Protocol.DIN_SPEC_70121)
    session = StubCommSession(
        protocol=Protocol.DIN_SPEC_70121, session_id=bytes(1).hex()
    )
    session.evse_controller = controller
    session.selected_auth_option = AuthEnum.EIM_V2
    return session


def _charge_parameter_discovery_req(session: StubCommSession) -> V2GMessageDINSPEC:
    return V2GMessageDINSPEC(
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
                        multiplier=0, value=60, unit=UnitSymbol.AMPERE
                    ),
                    ev_maximum_voltage_limit=PVEVMaxVoltageLimitDin(
                        multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
                    ),
                ),
            )
        ),
    )


@pytest.mark.asyncio
async def test_charge_parameter_discovery_finishes_and_advances(exi_codec):
    """The advance is unconditional: FINISHED + handoff to CableCheck."""
    session = _empty_tree_secc_session()
    peer = ScriptedPeer(session, start_state=ChargeParameterDiscovery)

    result = await peer.feed(_charge_parameter_discovery_req(session))

    res = result.outbound_msg.body.charge_parameter_discovery_res
    assert res.evse_processing == EVSEProcessing.FINISHED
    assert result.next_state is CableCheck


@pytest.mark.asyncio
async def test_charge_parameter_discovery_emits_non_empty_schedule(exi_codec):
    """An empty-tree personality still emits a non-empty pre-tree SAScheduleList
    (the retired scaffold's default), so the EVCC's pop() has a tuple to take."""
    session = _empty_tree_secc_session()
    peer = ScriptedPeer(session, start_state=ChargeParameterDiscovery)

    result = await peer.feed(_charge_parameter_discovery_req(session))

    res = result.outbound_msg.body.charge_parameter_discovery_res
    assert res.sa_schedule_list is not None
    assert len(res.sa_schedule_list.values) >= 1
    [entry] = res.sa_schedule_list.values
    [details] = entry.p_max_schedule.entry_details
    # Pre-tree builder default (PMax 200), unchanged from the retired scaffold.
    assert details.p_max == 200
