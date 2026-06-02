"""Live current/voltage override applied at the charge-loop read sites (issue #29).

The override is role-aware *at the read site*: on an EVCC it replaces the EV's
requested target in `CurrentDemandReq` (sourced from
`SimEVController.get_dc_charge_params`); on an SECC it replaces the EVSE's
reported present/delivered value in `CurrentDemandRes` (sourced from
`get_evse_present_voltage` / `get_evse_present_current`). Scope is ISO 15118-2
DC; DIN parity is a later slice, so DIN reads are deliberately left alone.
"""

from __future__ import annotations

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.secc.controller.simulator import SimEVSEController
from app.shared.live_control import LiveControl
from app.shared.messages.enums import Protocol
from app.shared.personality import EVCCPersonality, SECCPersonality


def _magnitude(pv) -> float:
    """Decode a PhysicalValue (or RationalNumber) to its real magnitude."""
    return pv.value * (10 ** pv.multiplier)


# -- EVCC: requested target in CurrentDemandReq -----------------------------


def _evcc(live_control):
    config = EVCCConfig.from_personality(EVCCPersonality())
    return SimEVController(config, live_control)


async def test_evcc_no_override_uses_personality_target():
    ctrl = _evcc(LiveControl())
    params = await ctrl.get_dc_charge_params(Protocol.ISO_15118_2)
    assert _magnitude(params.dc_target_current) == ctrl.config.ev_dc_target_current_a
    assert _magnitude(params.dc_target_voltage) == ctrl.config.ev_dc_target_voltage_v


async def test_evcc_override_replaces_target_current_and_voltage():
    lc = LiveControl()
    ctrl = _evcc(lc)
    lc.set_override_current(123)
    lc.set_override_voltage(456)
    params = await ctrl.get_dc_charge_params(Protocol.ISO_15118_2)
    assert _magnitude(params.dc_target_current) == 123
    assert _magnitude(params.dc_target_voltage) == 456


async def test_evcc_override_persists_across_calls_until_cleared():
    lc = LiveControl()
    ctrl = _evcc(lc)
    lc.set_override_current(321)
    for _ in range(3):
        params = await ctrl.get_dc_charge_params(Protocol.ISO_15118_2)
        assert _magnitude(params.dc_target_current) == 321
    lc.clear_overrides()
    params = await ctrl.get_dc_charge_params(Protocol.ISO_15118_2)
    assert _magnitude(params.dc_target_current) == ctrl.config.ev_dc_target_current_a


async def test_evcc_override_is_unchecked_out_of_envelope():
    """A value above the personality max is still sent (no clamping)."""
    lc = LiveControl()
    ctrl = _evcc(lc)
    over = ctrl.config.ev_dc_max_voltage_v + 5000
    lc.set_override_voltage(over)
    params = await ctrl.get_dc_charge_params(Protocol.ISO_15118_2)
    assert _magnitude(params.dc_target_voltage) == over


async def test_evcc_din_is_not_overridden():
    """Scope is ISO 15118-2; DIN reads keep the personality value."""
    lc = LiveControl()
    ctrl = _evcc(lc)
    lc.set_override_current(999)
    params = await ctrl.get_dc_charge_params(Protocol.DIN_SPEC_70121)
    assert _magnitude(params.dc_target_current) == ctrl.config.ev_dc_target_current_a


# -- SECC: reported present value in CurrentDemandRes -----------------------


def _secc(live_control):
    return SimEVSEController(personality=SECCPersonality(), live_control=live_control)


async def test_secc_no_override_uses_data_context_present_values():
    lc = LiveControl()
    ctrl = _secc(lc)
    ctrl.evse_data_context.present_voltage = 500
    ctrl.evse_data_context.present_current = 10
    v = await ctrl.get_evse_present_voltage(Protocol.ISO_15118_2)
    c = await ctrl.get_evse_present_current(Protocol.ISO_15118_2)
    assert _magnitude(v) == 500
    assert _magnitude(c) == 10


async def test_secc_override_replaces_present_values():
    lc = LiveControl()
    ctrl = _secc(lc)
    ctrl.evse_data_context.present_voltage = 500
    ctrl.evse_data_context.present_current = 10
    lc.set_override_voltage(750)
    lc.set_override_current(42)
    v = await ctrl.get_evse_present_voltage(Protocol.ISO_15118_2)
    c = await ctrl.get_evse_present_current(Protocol.ISO_15118_2)
    assert _magnitude(v) == 750
    assert _magnitude(c) == 42


async def test_secc_clear_restores_present_values():
    lc = LiveControl(override_voltage_v=750, override_current_a=42)
    ctrl = _secc(lc)
    ctrl.evse_data_context.present_voltage = 500
    ctrl.evse_data_context.present_current = 10
    lc.clear_overrides()
    v = await ctrl.get_evse_present_voltage(Protocol.ISO_15118_2)
    c = await ctrl.get_evse_present_current(Protocol.ISO_15118_2)
    assert _magnitude(v) == 500
    assert _magnitude(c) == 10


async def test_secc_din_is_not_overridden():
    lc = LiveControl(override_voltage_v=750)
    ctrl = _secc(lc)
    ctrl.evse_data_context.present_voltage = 500
    v = await ctrl.get_evse_present_voltage(Protocol.DIN_SPEC_70121)
    assert _magnitude(v) == 500


async def test_secc_without_live_control_is_inert():
    ctrl = SimEVSEController(personality=SECCPersonality())
    ctrl.evse_data_context.present_voltage = 500
    v = await ctrl.get_evse_present_voltage(Protocol.ISO_15118_2)
    assert _magnitude(v) == 500
