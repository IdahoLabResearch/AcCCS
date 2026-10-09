"""ChargingComplete derivation and side-effect-free request builds (issue #138).

The EVCC's ``ChargingComplete`` flag means "full charge (100 % SOC) reached"
(DIN Table 47, ISO-2 DC_EVPowerDeliveryParameter). Conformance finding SC-003
found it sourced from the loop-continuation routine, so building a
PowerDeliveryReq burned a charge-loop cycle, bumped the simulated SOC, and
consumed the operator's one-shot charge-loop release. These tests pin the
controller seam: the power-delivery parameter builders are pure reads of the
simulated state of charge, and only ``continue_charging()`` advances it.
"""

from __future__ import annotations

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.shared.live_control import LiveControl
from app.shared.personality import EVCCPersonality


def _controller(live_control: LiveControl | None = None) -> SimEVController:
    config = EVCCConfig.from_personality(EVCCPersonality())
    return SimEVController(config, live_control)


async def test_building_power_delivery_twice_leaves_loop_state_untouched():
    ctrl = _controller()
    cycles_before = ctrl.charging_loop_cycles
    soc_before = ctrl._soc

    await ctrl.get_dc_ev_power_delivery_parameter_dinspec()
    await ctrl.get_dc_ev_power_delivery_parameter_dinspec()
    await ctrl.get_dc_ev_power_delivery_parameter()
    await ctrl.get_dc_ev_power_delivery_parameter()

    assert ctrl.charging_loop_cycles == cycles_before
    assert ctrl._soc == soc_before


async def test_building_power_delivery_does_not_consume_operator_release():
    lc = LiveControl(stall_charge_loop=True)
    ctrl = _controller(lc)
    lc.release_charge_loop()  # operator pressed [a]dvance; release is pending

    await ctrl.get_dc_ev_power_delivery_parameter_dinspec()
    await ctrl.get_dc_ev_power_delivery_parameter()

    # The pending release is still there for the loop to consume.
    assert await ctrl.continue_charging() is False


async def test_charging_complete_false_until_soc_reaches_100():
    ctrl = _controller()
    assert ctrl._soc < 100

    din = await ctrl.get_dc_ev_power_delivery_parameter_dinspec()
    iso2 = await ctrl.get_dc_ev_power_delivery_parameter()
    assert din.charging_complete is False
    assert iso2.charging_complete is False

    ctrl._soc = 100
    din = await ctrl.get_dc_ev_power_delivery_parameter_dinspec()
    iso2 = await ctrl.get_dc_ev_power_delivery_parameter()
    assert din.charging_complete is True
    assert iso2.charging_complete is True


async def _drain_loop(ctrl: SimEVController) -> list[int]:
    """Run the loop to exhaustion; return the SOC after each continued cycle."""
    socs: list[int] = []
    while await ctrl.continue_charging():
        socs.append(ctrl._soc)
        assert len(socs) < 1000, "charge loop never ended"
    return socs


async def test_loop_runs_exactly_the_configured_cycles_and_ends_at_full_charge():
    ctrl = _controller()
    ctrl.charging_loop_cycles = 10

    socs = await _drain_loop(ctrl)

    assert len(socs) == 10
    assert socs == sorted(socs)
    assert all(s < 100 for s in socs[:-1])
    assert socs[-1] == 100
    assert await ctrl.is_charging_complete() is True


async def test_soc_lands_exactly_on_100_for_a_cycle_count_that_does_not_divide():
    ctrl = _controller()
    ctrl.charging_loop_cycles = 7

    socs = await _drain_loop(ctrl)

    assert len(socs) == 7
    assert socs[-1] == 100


async def test_explicit_stop_ends_the_loop_without_claiming_full_charge():
    ctrl = _controller()
    ctrl.charging_loop_cycles = 10
    assert await ctrl.continue_charging() is True

    await ctrl.stop_charging()

    assert await ctrl.continue_charging() is False
    assert ctrl._soc < 100
    din = await ctrl.get_dc_ev_power_delivery_parameter_dinspec()
    iso2 = await ctrl.get_dc_ev_power_delivery_parameter()
    assert din.charging_complete is False
    assert iso2.charging_complete is False
