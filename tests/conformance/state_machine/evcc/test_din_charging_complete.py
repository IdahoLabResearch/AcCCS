"""DIN EVCC: ChargingComplete tracks the state of charge and the charge loop
runs exactly the configured cycles (issue #138, conformance review SC-003).

DIN Table 47: ``ChargingComplete`` TRUE means the EV has reached full charge
(100 % SOC). The PowerDeliveryReq that starts the loop must therefore carry
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
from app.evcc.states.din_spec_states import (
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
    PVEVSEPresentCurrentDin,
    PVEVSEPresentVoltageDin,
)
from app.shared.messages.din_spec.body import (
    Body,
    CurrentDemandReq,
    CurrentDemandRes,
    PowerDeliveryReq,
    PowerDeliveryRes,
    PreChargeRes,
)
from app.shared.messages.din_spec.header import MessageHeader
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import IsolationLevel, Namespace, Protocol, UnitSymbol
from app.shared.personality.model import EVCCPersonality
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession

CYCLES = 4


def _session() -> StubCommSession:
    # An empty-tree personality so EVRESSSOC on the wire is the simulated SOC
    # (the DIN reference-vehicle baseline pins it to a static 88 %).
    config = EVCCConfig.from_personality(EVCCPersonality())
    config.charge_loop_cycle = CYCLES
    session = StubCommSession(
        protocol=Protocol.DIN_SPEC_70121, session_id=bytes(1).hex()
    )
    session.config = config
    session.ev_controller = SimEVController(config)
    session.ev_controller.charge_loop_delay_time = 0
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


def _status() -> DCEVSEStatus:
    return DCEVSEStatus(
        notification_max_delay=0,
        evse_notification=EVSENotification.NONE,
        evse_isolation_status=IsolationLevel.VALID,
        evse_status_code=DCEVSEStatusCode.EVSE_READY,
    )


def _current_demand_res() -> CurrentDemandRes:
    return CurrentDemandRes(
        response_code="OK",
        dc_evse_status=_status(),
        evse_present_voltage=PVEVSEPresentVoltageDin(
            multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
        ),
        evse_present_current=PVEVSEPresentCurrentDin(
            multiplier=0, value=50, unit=UnitSymbol.AMPERE
        ),
        evse_current_limit_achieved=False,
        evse_voltage_limit_achieved=False,
        evse_power_limit_achieved=False,
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
            V2GMessageDINSPEC(
                header=MessageHeader(session_id=session.session_id), body=body
            )
        )

    # PreChargeRes -> PowerDeliveryReq(Start): not full yet, nothing consumed.
    ctrl.precharge_loop_cycles = 5
    result = await feed(
        Body(
            pre_charge_res=PreChargeRes(
                response_code="OK",
                dc_evse_status=_status(),
                evse_present_voltage=PVEVSEPresentVoltageDin(
                    multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
                ),
            )
        )
    )
    assert result.next_state is PowerDelivery
    start = _decode(result)
    assert isinstance(start, PowerDeliveryReq)
    assert start.ready_to_charge is True
    assert start.dc_ev_power_delivery_parameter.charging_complete is False
    assert ctrl.charging_loop_cycles == CYCLES

    # PowerDeliveryRes then CurrentDemandRes until the EVCC stops the loop.
    current_demand_reqs: list[CurrentDemandReq] = []
    result = await feed(
        Body(power_delivery_res=PowerDeliveryRes(response_code="OK", dc_evse_status=_status()))
    )
    while result.next_state is CurrentDemand or isinstance(
        _decode(result), CurrentDemandReq
    ):
        req = _decode(result)
        assert isinstance(req, CurrentDemandReq)
        current_demand_reqs.append(req)
        assert len(current_demand_reqs) <= CYCLES + 1, "charge loop overran"
        result = await feed(Body(current_demand_res=_current_demand_res()))

    assert len(current_demand_reqs) == CYCLES
    assert [r.dc_ev_status.ev_ress_soc for r in current_demand_reqs] == sorted(
        r.dc_ev_status.ev_ress_soc for r in current_demand_reqs
    )
    assert current_demand_reqs[-1].dc_ev_status.ev_ress_soc == 100
    assert current_demand_reqs[-1].charging_complete is True
    assert all(r.charging_complete is False for r in current_demand_reqs[:-1])

    # The exhausted loop ends with PowerDeliveryReq(Stop) at 100 % SOC.
    assert result.next_state is PowerDelivery
    stop = _decode(result)
    assert isinstance(stop, PowerDeliveryReq)
    assert stop.ready_to_charge is False
    assert stop.dc_ev_power_delivery_parameter.charging_complete is True
    assert stop.dc_ev_power_delivery_parameter.dc_ev_status.ev_ress_soc == 100

    result = await feed(
        Body(power_delivery_res=PowerDeliveryRes(response_code="OK", dc_evse_status=_status()))
    )
    assert result.next_state is WeldingDetection


@pytest.mark.asyncio
async def test_stop_before_full_charge_does_not_claim_charging_complete(exi_codec):
    """A loop ended by the charger (EVSE not ready) stops with the flag FALSE."""
    session = _session()
    peer = ScriptedPeer(session, CurrentDemand)
    not_ready = _current_demand_res()
    not_ready.dc_evse_status.evse_status_code = DCEVSEStatusCode.EVSE_SHUTDOWN

    result = await peer.feed(
        V2GMessageDINSPEC(
            header=MessageHeader(session_id=session.session_id),
            body=Body(current_demand_res=not_ready),
        )
    )

    assert result.next_state is PowerDelivery
    stop = _decode(result)
    assert isinstance(stop, PowerDeliveryReq)
    assert stop.ready_to_charge is False
    assert stop.dc_ev_power_delivery_parameter.charging_complete is False
    assert stop.dc_ev_power_delivery_parameter.dc_ev_status.ev_ress_soc < 100
