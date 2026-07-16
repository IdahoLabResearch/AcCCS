"""Live current/voltage override applied at the charge-loop read sites (issue #29).

The override is role-aware *at the read site*: on an EVCC it replaces the EV's
requested target in `CurrentDemandReq` (sourced from
`SimEVController.get_dc_charge_params`); on an SECC it replaces the EVSE's
reported present/delivered value in `CurrentDemandRes` (sourced from
`get_evse_present_voltage` / `get_evse_present_current`). Scope is the DC charge
loop on ISO 15118-2, DIN SPEC 70121 (DIN parity landed in issue #31) and ISO
15118-20 DC (parity landed in issue #32).

ISO 15118-20 has no `CurrentDemandReq`; the EVCC charge-loop voltage rides on
`DCChargeLoopReq.ev_present_voltage` (sourced from `get_present_voltage`,
present in both scheduled and dynamic modes) and the mode-active target
magnitudes ride on the scheduled/dynamic charge-loop params (`get_scheduled_/
get_dynamic_dc_charge_loop_params`). The SECC reports its present value on
`DCChargeLoopRes` via the same `get_evse_present_*` read sites. ISO-20 AC has no
current/voltage field, so the override has no AC home — AC gets stall only.
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
    # Well beyond any sane DC target voltage — the announced max envelope is now
    # tree-owned (retired from EVCCConfig, #102), so use a plain large literal.
    over = 5500.0
    lc.set_override_voltage(over)
    params = await ctrl.get_dc_charge_params(Protocol.ISO_15118_2)
    assert _magnitude(params.dc_target_voltage) == over


async def test_evcc_din_override_replaces_target():
    """DIN parity (issue #31): DIN reads honour the override too."""
    lc = LiveControl()
    ctrl = _evcc(lc)
    lc.set_override_current(999)
    lc.set_override_voltage(888)
    params = await ctrl.get_dc_charge_params(Protocol.DIN_SPEC_70121)
    assert _magnitude(params.dc_target_current) == 999
    assert _magnitude(params.dc_target_voltage) == 888
    # Clearing falls back to the personality value on the DIN path as well.
    lc.clear_overrides()
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


async def test_secc_din_override_replaces_present_values():
    """DIN parity (issue #31): DIN present-value reads honour the override too."""
    lc = LiveControl(override_voltage_v=750, override_current_a=42)
    ctrl = _secc(lc)
    ctrl.evse_data_context.present_voltage = 500
    ctrl.evse_data_context.present_current = 10
    v = await ctrl.get_evse_present_voltage(Protocol.DIN_SPEC_70121)
    c = await ctrl.get_evse_present_current(Protocol.DIN_SPEC_70121)
    assert _magnitude(v) == 750
    assert _magnitude(c) == 42
    # Clearing restores the data-context value on the DIN path as well.
    lc.clear_overrides()
    v = await ctrl.get_evse_present_voltage(Protocol.DIN_SPEC_70121)
    assert _magnitude(v) == 500


async def test_secc_without_live_control_is_inert():
    ctrl = SimEVSEController(personality=SECCPersonality())
    ctrl.evse_data_context.present_voltage = 500
    v = await ctrl.get_evse_present_voltage(Protocol.ISO_15118_2)
    assert _magnitude(v) == 500


# -- ISO 15118-20 DC parity (issue #32) -------------------------------------
#
# ISO-20 read sites return a RationalNumber (decoded via get_decimal_value),
# not a PhysicalValue. The override flows through the same LiveControl fields.


async def test_evcc_iso20_present_voltage_honours_override():
    """ev_present_voltage on DCChargeLoopReq tracks the voltage override
    (present in both scheduled and dynamic modes)."""
    lc = LiveControl()
    ctrl = _evcc(lc)
    baseline = (await ctrl.get_present_voltage()).get_decimal_value()
    # Retired `power.ev_dc_v20` skeleton default (#102): target_voltage_v.
    assert baseline == 20000.0
    lc.set_override_voltage(456)
    assert (await ctrl.get_present_voltage()).get_decimal_value() == 456
    lc.clear_overrides()
    assert (await ctrl.get_present_voltage()).get_decimal_value() == baseline


async def test_evcc_iso20_scheduled_params_honour_override():
    """Scheduled DC charge-loop params source ev_target_current / ev_target_voltage."""
    lc = LiveControl()
    ctrl = _evcc(lc)
    lc.set_override_current(123)
    lc.set_override_voltage(456)
    params = await ctrl.get_scheduled_dc_charge_loop_params()
    assert params.ev_target_current.get_decimal_value() == 123
    assert params.ev_target_voltage.get_decimal_value() == 456


async def test_evcc_iso20_dynamic_params_honour_override():
    """Dynamic DC charge-loop params source ev_max_charge_current / ev_max_voltage."""
    lc = LiveControl()
    ctrl = _evcc(lc)
    lc.set_override_current(123)
    lc.set_override_voltage(456)
    params = await ctrl.get_dynamic_dc_charge_loop_params()
    assert params.ev_max_charge_current.get_decimal_value() == 123
    assert params.ev_max_voltage.get_decimal_value() == 456


async def test_evcc_iso20_no_override_uses_skeleton():
    """No override -> mode params fall back to the retired `power.ev_dc_v20`
    skeleton defaults (#102: the ISO-20 DC charge loop is tree-sourced now, so
    these builder skeleton magnitudes are the empty-tree fallback)."""
    ctrl = _evcc(LiveControl())
    sched = await ctrl.get_scheduled_dc_charge_loop_params()
    assert sched.ev_target_current.get_decimal_value() == 200.0
    assert sched.ev_target_voltage.get_decimal_value() == 20000.0
    dyn = await ctrl.get_dynamic_dc_charge_loop_params()
    assert dyn.ev_max_charge_current.get_decimal_value() == 40.0
    assert dyn.ev_max_voltage.get_decimal_value() == 400.0


async def test_evcc_iso20_bpt_params_inherit_override():
    """BPT variants reuse the scheduled/dynamic builders, so they inherit the override."""
    lc = LiveControl(override_current_a=77, override_voltage_v=88)
    ctrl = _evcc(lc)
    bpt_sched = await ctrl.get_bpt_scheduled_dc_charge_loop_params()
    assert bpt_sched.ev_target_current.get_decimal_value() == 77
    assert bpt_sched.ev_target_voltage.get_decimal_value() == 88
    bpt_dyn = await ctrl.get_bpt_dynamic_dc_charge_loop_params()
    assert bpt_dyn.ev_max_charge_current.get_decimal_value() == 77
    assert bpt_dyn.ev_max_voltage.get_decimal_value() == 88


async def test_secc_iso20_dc_override_replaces_present_values():
    """SECC reports the override on DCChargeLoopRes present voltage/current."""
    lc = LiveControl()
    ctrl = _secc(lc)
    ctrl.evse_data_context.present_voltage = 500
    ctrl.evse_data_context.present_current = 10
    lc.set_override_voltage(750)
    lc.set_override_current(42)
    v = await ctrl.get_evse_present_voltage(Protocol.ISO_15118_20_DC)
    c = await ctrl.get_evse_present_current(Protocol.ISO_15118_20_DC)
    assert v.get_decimal_value() == 750
    assert c.get_decimal_value() == 42


async def test_secc_iso20_dc_no_override_uses_data_context():
    lc = LiveControl()
    ctrl = _secc(lc)
    ctrl.evse_data_context.present_voltage = 500
    ctrl.evse_data_context.present_current = 10
    v = await ctrl.get_evse_present_voltage(Protocol.ISO_15118_20_DC)
    c = await ctrl.get_evse_present_current(Protocol.ISO_15118_20_DC)
    assert v.get_decimal_value() == 500
    assert c.get_decimal_value() == 10
