"""Simulated charger ramps its reported present values toward the EV (issue #139).

The emulated charger has no power stage, but the present voltage/current it
reports are what a real vehicle's precharge logic reads first. Conformance
finding SC-029 found ``send_charging_command`` a no-op, so every PreChargeRes
reported a constant 1 V and the vehicle looped PreChargeReq until its timer
expired. These tests pin the controller seam: each precharge command steps the
present voltage a fixed fraction of the remaining gap toward the EV target
(converging in a handful of polls), the charge loop reports the target voltage
and requested current clamped to the advertised maxima, and a live operator
override still wins over the computed value.
"""

from __future__ import annotations

import pytest

from app.secc.controller.simulator import (
    PRECHARGE_RAMP_FRACTION,
    PRECHARGE_START_VOLTAGE_V,
    WELDING_DISCHARGE_FRACTION,
    SimEVSEController,
)
from app.shared.live_control import LiveControl
from app.shared.messages.enums import Protocol
from app.shared.personality import SECCPersonality
from app.shared.personality.loader import load_personality

# Advertised maxima of the shipped baselines (ChargeParameterDiscoveryRes).
_DIN_MAX_V, _DIN_MAX_A = 451.0, 60.0
_ISO2_MAX_V, _ISO2_MAX_A = 1000.0, 400.0


def _controller(protocol: Protocol, live_control=None) -> SimEVSEController:
    baseline = {
        Protocol.DIN_SPEC_70121: "din-secc-baseline",
        Protocol.ISO_15118_2: "iso2-secc-baseline",
    }.get(protocol)
    personality = (
        load_personality(baseline, "secc") if baseline else SECCPersonality()
    )
    ctrl = SimEVSEController(personality, live_control)
    ctrl.set_selected_protocol(protocol)
    if protocol == Protocol.ISO_15118_20_DC:
        # ISO-20 reads its advertised envelope from the session limits the
        # DCChargeParameterDiscovery state fills from the tree.
        dc = ctrl.evse_data_context.session_limits.dc_limits
        dc.max_voltage = 1000.0
        dc.max_charge_current = 110.0
    return ctrl


async def _magnitude(read) -> float:
    return (await read).get_decimal_value()


async def test_controller_starts_at_documented_start_voltage():
    ctrl = _controller(Protocol.DIN_SPEC_70121)
    assert ctrl.evse_data_context.present_voltage == PRECHARGE_START_VOLTAGE_V


async def test_precharge_step_moves_fixed_fraction_of_gap():
    ctrl = _controller(Protocol.DIN_SPEC_70121)
    await ctrl.send_charging_command(400, 1, is_precharge=True)
    expected = PRECHARGE_START_VOLTAGE_V + PRECHARGE_RAMP_FRACTION * (
        400 - PRECHARGE_START_VOLTAGE_V
    )
    assert ctrl.evse_data_context.present_voltage == pytest.approx(expected, abs=0.1)


@pytest.mark.parametrize(
    "protocol",
    [Protocol.DIN_SPEC_70121, Protocol.ISO_15118_2, Protocol.ISO_15118_20_DC],
)
async def test_precharge_rises_monotonically_and_converges(protocol):
    ctrl = _controller(protocol)
    seen = []
    for _ in range(15):
        await ctrl.send_charging_command(400, 1, is_precharge=True)
        seen.append(ctrl.evse_data_context.present_voltage)
    assert all(b >= a for a, b in zip(seen, seen[1:]))
    assert seen[0] < 400
    # Converges within a handful of polls, well inside the precharge timer.
    assert seen[9] == 400
    assert await _magnitude(ctrl.get_evse_present_voltage(protocol)) == 400


async def test_precharge_target_clamped_to_advertised_max_voltage():
    ctrl = _controller(Protocol.DIN_SPEC_70121)
    for _ in range(20):
        await ctrl.send_charging_command(900, 1, is_precharge=True)
    assert ctrl.evse_data_context.present_voltage == _DIN_MAX_V


async def test_session_end_resets_present_values():
    ctrl = _controller(Protocol.ISO_15118_2)
    for _ in range(15):
        await ctrl.send_charging_command(400, 1, is_precharge=True)
    await ctrl.send_charging_command(400, 50)
    await ctrl.session_ended("CurrentDemand", "test")
    assert ctrl.evse_data_context.present_voltage == PRECHARGE_START_VOLTAGE_V
    assert ctrl.evse_data_context.present_current == 0


async def test_cable_check_de_energises_for_renegotiated_precharge():
    """An ISO-2 renegotiation re-enters CableCheck -> PreCharge mid-session; the
    PreCharge inrush check must not read the last charge-loop current."""
    ctrl = _controller(Protocol.ISO_15118_2)
    await ctrl.send_charging_command(400, 50)
    await ctrl.start_cable_check()
    assert ctrl.evse_data_context.present_voltage == PRECHARGE_START_VOLTAGE_V
    assert ctrl.evse_data_context.present_current == 0


async def test_no_negotiated_protocol_clamps_to_dc_skeleton():
    ctrl = SimEVSEController(SECCPersonality())
    await ctrl.send_charging_command(5000, 5000)
    assert ctrl.evse_data_context.present_voltage == 500.0
    assert ctrl.evse_data_context.present_current == 400.0


@pytest.mark.parametrize(
    "protocol, max_v, max_a",
    [
        (Protocol.DIN_SPEC_70121, _DIN_MAX_V, _DIN_MAX_A),
        (Protocol.ISO_15118_2, _ISO2_MAX_V, _ISO2_MAX_A),
        (Protocol.ISO_15118_20_DC, 1000.0, 110.0),
    ],
)
async def test_charge_loop_reports_target_and_requested_current(
    protocol, max_v, max_a
):
    ctrl = _controller(protocol)
    await ctrl.send_charging_command(400, 50)
    assert await _magnitude(ctrl.get_evse_present_voltage(protocol)) == 400
    assert await _magnitude(ctrl.get_evse_present_current(protocol)) == 50

    await ctrl.send_charging_command(max_v + 100, max_a + 100)
    assert await _magnitude(ctrl.get_evse_present_voltage(protocol)) == max_v
    assert await _magnitude(ctrl.get_evse_present_current(protocol)) == max_a


async def test_charge_loop_without_targets_keeps_present_values():
    """ISO-20 dynamic control mode passes no targets; nothing is invented."""
    ctrl = _controller(Protocol.ISO_15118_20_DC)
    await ctrl.send_charging_command(400, 50)
    await ctrl.send_charging_command(None, None)
    assert ctrl.evse_data_context.present_voltage == 400
    assert ctrl.evse_data_context.present_current == 50


async def test_operator_override_returned_unchanged():
    lc = LiveControl()
    ctrl = _controller(Protocol.DIN_SPEC_70121, lc)
    lc.set_override_voltage(123.4)
    lc.set_override_current(7)
    await ctrl.send_charging_command(400, 1, is_precharge=True)
    await ctrl.send_charging_command(400, 50)
    voltage = await _magnitude(ctrl.get_evse_present_voltage(Protocol.DIN_SPEC_70121))
    current = await _magnitude(ctrl.get_evse_present_current(Protocol.DIN_SPEC_70121))
    assert voltage == pytest.approx(123.4)
    assert current == 7


# Welding detection (issue #145): after PowerDelivery Stop the simulated output
# discharges a fixed fraction per WeldingDetectionReq, so the EV's welding
# check reads a voltage that actually falls to zero.


async def test_stop_charger_cuts_the_current_and_keeps_the_voltage():
    ctrl = _controller(Protocol.DIN_SPEC_70121)
    await ctrl.send_charging_command(400, 30)
    await ctrl.stop_charger()
    assert ctrl.evse_data_context.present_current == 0
    assert ctrl.evse_data_context.present_voltage == 400


@pytest.mark.parametrize(
    "protocol",
    [Protocol.DIN_SPEC_70121, Protocol.ISO_15118_2, Protocol.ISO_15118_20_DC],
)
async def test_welding_discharge_falls_monotonically_to_zero(protocol):
    ctrl = _controller(protocol)
    await ctrl.send_charging_command(400, 30)
    await ctrl.stop_charger()
    seen = []
    for _ in range(15):
        await ctrl.step_welding_discharge()
        seen.append(ctrl.evse_data_context.present_voltage)
    assert seen[0] == pytest.approx(400 * (1 - WELDING_DISCHARGE_FRACTION), abs=0.1)
    assert all(b <= a for a, b in zip(seen, seen[1:]))
    assert seen[-1] == 0
