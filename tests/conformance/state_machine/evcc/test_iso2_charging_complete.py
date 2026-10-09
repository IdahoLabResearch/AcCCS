"""ISO-2 EVCC: ChargingComplete tracks the state of charge and the charge loop
runs exactly the configured cycles (issue #138, conformance review SC-003).

ISO 15118-2 DC_EVPowerDeliveryParameter: ``ChargingComplete`` TRUE means the
EV has reached full charge (100 % SOC). The PowerDeliveryReq(Start) must carry
FALSE, and the Stop that ends an exhausted loop TRUE. Building either request
must not consume a charge-loop cycle, so ``charge_loop_cycle: N`` yields
exactly N CurrentDemandReq on the wire.

The replay feeds the charger's messages to the real states at the ADR-0003
``process_message()`` seam, decoding every request the EVCC emits.
"""

from __future__ import annotations

import pytest

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.evcc.states.iso15118_2_states import (
    CurrentDemand,
    PowerDelivery,
    PreCharge,
    WeldingDetection,
)
from app.shared.exi_codec import EXI
from app.shared.messages.datatypes import (
    DCEVSEStatus,
    DCEVSEStatusCode,
    EVSENotification,
    PVEVSEPresentCurrent,
    PVEVSEPresentVoltage,
)
from app.shared.messages.enums import IsolationLevel, Namespace, Protocol, UnitSymbol
from app.shared.messages.iso15118_2.body import (
    Body,
    CurrentDemandReq,
    CurrentDemandRes,
    PowerDeliveryReq,
    PowerDeliveryRes,
    PreChargeRes,
)
from app.shared.messages.iso15118_2.datatypes import ChargeProgress
from app.shared.messages.iso15118_2.header import MessageHeader
from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from app.shared.personality.model import EVCCPersonality
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession

CYCLES = 4


def _session() -> StubCommSession:
    # An empty-tree personality so EVRESSSOC on the wire is the simulated SOC
    # (the ISO-2 reference-vehicle baseline pins it to a static 24 %).
    config = EVCCConfig.from_personality(EVCCPersonality())
    config.charge_loop_cycle = CYCLES
    session = StubCommSession(protocol=Protocol.ISO_15118_2, session_id=bytes(1).hex())
    session.config = config
    session.ev_controller = SimEVController(config)
    session.ev_controller.charge_loop_delay_time = 0
    session.live_control = None
    session.is_tls = False
    session.selected_auth_option = None
    session.selected_services = []
    session.selected_energy_mode = None
    session.selected_charging_type_is_ac = False
    session.selected_schedule = 1
    session.charging_session_stop_v2 = None
    session.renegotiation_requested = False
    session.service_details_to_request = []
    session.ongoing_timer = -1
    return session


def _decode(result):
    payload = result.outbound_v2gtp.payload
    return EXI().from_exi_document(payload, Namespace.ISO_V2_MSG_DEF).body.get_message()


def _status(code: DCEVSEStatusCode = DCEVSEStatusCode.EVSE_READY) -> DCEVSEStatus:
    return DCEVSEStatus(
        notification_max_delay=0,
        evse_notification=EVSENotification.NONE,
        evse_isolation_status=IsolationLevel.VALID,
        evse_status_code=code,
    )


def _current_demand_res(notification=EVSENotification.NONE) -> CurrentDemandRes:
    status = _status()
    status.evse_notification = notification
    return CurrentDemandRes(
        response_code="OK",
        dc_evse_status=status,
        evse_present_voltage=PVEVSEPresentVoltage(
            multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
        ),
        evse_present_current=PVEVSEPresentCurrent(
            multiplier=0, value=50, unit=UnitSymbol.AMPERE
        ),
        evse_current_limit_achieved=False,
        evse_voltage_limit_achieved=False,
        evse_power_limit_achieved=False,
        evse_id="USFRDE9001",
        sa_schedule_tuple_id=1,
    )


@pytest.mark.asyncio
async def test_charging_complete_follows_soc_and_loop_runs_configured_cycles(
    exi_codec,
):
    session = _session()
    ctrl: SimEVController = session.ev_controller
    peer = ScriptedPeer(session, PreCharge)

    async def feed(body: Body):
        return await peer.feed(
            V2GMessageV2(header=MessageHeader(session_id=session.session_id), body=body)
        )

    # PreChargeRes -> PowerDeliveryReq(Start): not full yet, nothing consumed.
    ctrl.precharge_loop_cycles = 5
    result = await feed(
        Body(
            pre_charge_res=PreChargeRes(
                response_code="OK",
                dc_evse_status=_status(),
                evse_present_voltage=PVEVSEPresentVoltage(
                    multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
                ),
            )
        )
    )
    assert result.next_state is PowerDelivery
    start = _decode(result)
    assert isinstance(start, PowerDeliveryReq)
    assert start.charge_progress == ChargeProgress.START
    assert start.dc_ev_power_delivery_parameter.charging_complete is False
    assert ctrl.charging_loop_cycles == CYCLES

    # PowerDeliveryRes then CurrentDemandRes until the EVCC stops the loop.
    current_demand_reqs: list[CurrentDemandReq] = []
    result = await feed(
        Body(power_delivery_res=PowerDeliveryRes(response_code="OK", dc_evse_status=_status()))
    )
    while isinstance(_decode(result), CurrentDemandReq):
        current_demand_reqs.append(_decode(result))
        assert len(current_demand_reqs) <= CYCLES + 1, "charge loop overran"
        result = await feed(Body(current_demand_res=_current_demand_res()))

    assert len(current_demand_reqs) == CYCLES
    socs = [r.dc_ev_status.ev_ress_soc for r in current_demand_reqs]
    assert socs == sorted(socs)
    assert socs[-1] == 100
    assert current_demand_reqs[-1].charging_complete is True
    assert all(r.charging_complete is False for r in current_demand_reqs[:-1])

    # The exhausted loop ends with PowerDeliveryReq(Stop) at 100 % SOC.
    assert result.next_state is PowerDelivery
    stop = _decode(result)
    assert isinstance(stop, PowerDeliveryReq)
    assert stop.charge_progress == ChargeProgress.STOP
    assert stop.dc_ev_power_delivery_parameter.charging_complete is True
    assert stop.dc_ev_power_delivery_parameter.dc_ev_status.ev_ress_soc == 100

    result = await feed(
        Body(power_delivery_res=PowerDeliveryRes(response_code="OK", dc_evse_status=_status()))
    )
    assert result.next_state is WeldingDetection


@pytest.mark.asyncio
async def test_stop_before_full_charge_does_not_claim_charging_complete(exi_codec):
    """A loop ended by the charger (StopCharging) stops with the flag FALSE."""
    session = _session()
    peer = ScriptedPeer(session, CurrentDemand)

    result = await peer.feed(
        V2GMessageV2(
            header=MessageHeader(session_id=session.session_id),
            body=Body(
                current_demand_res=_current_demand_res(EVSENotification.STOP_CHARGING)
            ),
        )
    )

    assert result.next_state is PowerDelivery
    stop = _decode(result)
    assert isinstance(stop, PowerDeliveryReq)
    assert stop.charge_progress == ChargeProgress.STOP
    assert stop.dc_ev_power_delivery_parameter.charging_complete is False
    assert stop.dc_ev_power_delivery_parameter.dc_ev_status.ev_ress_soc < 100
