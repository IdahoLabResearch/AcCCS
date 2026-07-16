"""ISO 15118-20 personality fields (issue #9, slice 4).

Tests the contract that every personality-shaped field used during an ISO
15118-20 session is sourced from the personality config — see issue #9's
"What to build" / "Acceptance criteria".

Mirrors the structure of `test_iso2_slice.py`: model-level tests assert
the new v20 sub-sections exist with strict validation, and controller-
level tests assert the simulators honour personality values when building
ISO-20 wire messages (AC + DC charge params, AC + DC BPT discharge,
ScheduleExchange announcements, AC/DC charge loops, PreCharge/target
voltage, SECC schedule envelope, ISO-20 meter info).

Note (#98): the ISO-20 *DC SECC* structured reads (`power.evse_dc_v20`,
`power.evse_schedule_exchange_v20`) are retired — those wire values are now
sourced from the `message_field_tree`, so the corresponding SECC builders
return the model-default *skeleton* and the `*_retired_to_skeleton` tests below
assert that. The AC SECC (`evse_ac_v20`) and every EVCC read are unchanged
(their slices have not landed).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.secc.controller.simulator import SimEVSEController
from app.shared.messages.enums import ControlMode, ServiceV20
from app.shared.messages.iso15118_20.common_messages import (
    SelectedEnergyService,
)
from app.shared.personality.model import EVCCPersonality, SECCPersonality


# ---------------------------------------------------------------------------
# Model: ISO-20 v20 sub-blocks exist with strict validation
# ---------------------------------------------------------------------------


def test_power_has_v20_subsections():
    p = SECCPersonality.model_validate({})
    assert p.power.evse_dc_v20.max_charge_power_w > 0
    assert p.power.evse_ac_v20.max_charge_power_w > 0
    assert p.power.evse_schedule_exchange_v20.charge_power_w > 0

    e = EVCCPersonality.model_validate({})
    assert e.power.ev_dc_v20.max_charge_power_w > 0
    assert e.power.ev_ac_v20.max_charge_power_w > 0
    assert e.power.schedule_exchange_v20.departure_time_s > 0


@pytest.mark.parametrize(
    "section",
    [
        "evse_dc_v20",
        "evse_ac_v20",
        "evse_schedule_exchange_v20",
    ],
)
def test_secc_v20_section_rejects_unknown_field(section):
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate({"power": {section: {"bogus": 1}}})


@pytest.mark.parametrize(
    "section",
    [
        "ev_dc_v20",
        "ev_ac_v20",
        "schedule_exchange_v20",
    ],
)
def test_evcc_v20_section_rejects_unknown_field(section):
    with pytest.raises(ValidationError):
        EVCCPersonality.model_validate({"power": {section: {"bogus": 1}}})


def test_schedule_exchange_v20_soc_range_enforced():
    with pytest.raises(ValidationError):
        EVCCPersonality.model_validate(
            {"power": {"schedule_exchange_v20": {"dynamic_target_soc_percent": 101}}}
        )
    with pytest.raises(ValidationError):
        EVCCPersonality.model_validate(
            {"power": {"schedule_exchange_v20": {"dynamic_min_soc_percent": -1}}}
        )


def test_evse_schedule_exchange_v20_soc_range_enforced():
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate(
            {
                "power": {
                    "evse_schedule_exchange_v20": {
                        "dynamic_target_soc_percent": 101
                    }
                }
            }
        )


# ---------------------------------------------------------------------------
# SECC simulator: ISO-20 wire values come from personality
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_secc_ac_v20_charge_params_use_personality():
    personality = SECCPersonality.model_validate(
        {
            "power": {
                "evse_ac_v20": {
                    "max_charge_power_w": 50000.0,
                    "min_charge_power_w": 250.0,
                    "nominal_frequency_hz": 60.0,
                    "max_power_asymmetry_w": 100.0,
                    "power_ramp_limit_w_per_s": 300.0,
                }
            }
        }
    )
    ctrl = SimEVSEController(personality=personality)
    params = await ctrl.get_ac_charge_params_v20(ServiceV20.AC)

    assert params.evse_max_charge_power.get_decimal_value() == 50000.0
    assert params.evse_max_charge_power_l2.get_decimal_value() == 50000.0
    assert params.evse_min_charge_power.get_decimal_value() == 250.0
    assert params.evse_nominal_frequency.get_decimal_value() == 60.0
    assert params.max_power_asymmetry.get_decimal_value() == 100.0
    assert params.evse_power_ramp_limit.get_decimal_value() == 300.0


@pytest.mark.asyncio
async def test_secc_ac_bpt_v20_discharge_uses_personality():
    personality = SECCPersonality.model_validate(
        {
            "power": {
                "evse_ac_v20": {
                    "bpt_max_discharge_power_w": 15000.0,
                    "bpt_min_discharge_power_w": 60.0,
                }
            }
        }
    )
    ctrl = SimEVSEController(personality=personality)
    params = await ctrl.get_ac_charge_params_v20(ServiceV20.AC_BPT)

    assert params.evse_max_discharge_power.get_decimal_value() == 15000.0
    assert params.evse_min_discharge_power_l2.get_decimal_value() == 60.0


@pytest.mark.asyncio
async def test_secc_dc_v20_charge_params_retired_to_skeleton():
    # #98 retired the structured `power.evse_dc_v20` ISO-20 DC SECC read: the DC
    # envelope is now tree-sourced at the DCChargeParameterDiscoveryRes build
    # site, so this builder returns the ISO-20 DC-limit model-default *skeleton*
    # regardless of the personality's evse_dc_v20 (which no longer reaches the
    # ISO-20 wire through here).
    from app.shared.personality.model import EVSEDCLimitsV20

    personality = SECCPersonality.model_validate(
        {
            "power": {
                "evse_dc_v20": {
                    "max_charge_power_w": 350000.0,
                    "min_charge_power_w": 250.0,
                    "max_charge_current_a": 500.0,
                    "min_charge_current_a": 5.0,
                    "max_voltage_v": 920.0,
                    "min_voltage_v": 50.0,
                    "power_ramp_limit_w_per_s": 50.0,
                }
            }
        }
    )
    ctrl = SimEVSEController(personality=personality)
    params = await ctrl.get_dc_charge_params_v20(ServiceV20.DC)

    default = EVSEDCLimitsV20()
    assert params.evse_max_charge_power.get_decimal_value() == default.max_charge_power_w
    assert params.evse_min_charge_power.get_decimal_value() == default.min_charge_power_w
    assert (
        params.evse_max_charge_current.get_decimal_value()
        == default.max_charge_current_a
    )
    assert params.evse_max_voltage.get_decimal_value() == default.max_voltage_v
    assert (
        params.evse_power_ramp_limit.get_decimal_value()
        == default.power_ramp_limit_w_per_s
    )


@pytest.mark.asyncio
async def test_secc_dc_bpt_v20_discharge_retired_to_skeleton():
    # #98: the DC-BPT discharge envelope is likewise tree-sourced now (the
    # baseline pins it as BPT_DC_CPDResEnergyTransferMode leaves), so the builder
    # returns the model-default skeleton, not the personality's evse_dc_v20.
    from app.shared.personality.model import EVSEDCLimitsV20

    personality = SECCPersonality.model_validate(
        {
            "power": {
                "evse_dc_v20": {
                    "bpt_max_discharge_power_w": 150000.0,
                    "bpt_max_discharge_current_a": 250.0,
                }
            }
        }
    )
    ctrl = SimEVSEController(personality=personality)
    params = await ctrl.get_dc_charge_params_v20(ServiceV20.DC_BPT)

    default = EVSEDCLimitsV20()
    assert (
        params.evse_max_discharge_power.get_decimal_value()
        == default.bpt_max_discharge_power_w
    )
    assert (
        params.evse_max_discharge_current.get_decimal_value()
        == default.bpt_max_discharge_current_a
    )


@pytest.mark.asyncio
async def test_secc_meter_info_v20_uses_personality_reading():
    personality = SECCPersonality.model_validate(
        {"meter": {"meter_id": "ACME-V20", "starting_reading_wh": 78910}}
    )
    ctrl = SimEVSEController(personality=personality)
    info = await ctrl.get_meter_info_v20()
    assert info.meter_id == "ACME-V20"
    assert info.charged_energy_reading_wh == 78910


@pytest.mark.asyncio
async def test_secc_scheduled_se_params_retired_to_skeleton():
    # #98 retired the structured `power.evse_schedule_exchange_v20` ISO-20 SECC
    # read: ScheduleExchangeRes wire values are now tree-sourced at the build
    # site, so this builder returns the model-default skeleton regardless of the
    # personality's evse_schedule_exchange_v20.
    from app.shared.personality.model import EVSEScheduleExchangeV20

    personality = SECCPersonality.model_validate(
        {
            "power": {
                "evse_schedule_exchange_v20": {
                    "schedule_duration_s": 2700,
                    "charge_power_w": 22000.0,
                    "available_energy_wh": 250000.0,
                    "power_tolerance_w": 1500.0,
                    "discharge_power_w": 8000.0,
                }
            }
        }
    )
    ctrl = SimEVSEController(personality=personality)
    params = await ctrl.get_scheduled_se_params(
        selected_energy_service=None, schedule_exchange_req=None
    )
    default = EVSEScheduleExchangeV20()
    [tup] = params.schedule_tuples
    [entry] = tup.charging_schedule.power_schedule.schedule_entry_list.entries
    assert entry.duration == default.schedule_duration_s
    assert entry.power.get_decimal_value() == default.charge_power_w
    assert (
        tup.charging_schedule.power_schedule.available_energy.get_decimal_value()
        == default.available_energy_wh
    )
    [dis_entry] = tup.discharging_schedule.power_schedule.schedule_entry_list.entries
    assert dis_entry.power.get_decimal_value() == default.discharge_power_w


@pytest.mark.asyncio
async def test_secc_dynamic_se_params_retired_to_skeleton():
    # #98: the dynamic ScheduleExchangeRes params are likewise builder-skeleton
    # now, not sourced from the personality's evse_schedule_exchange_v20.
    from app.shared.personality.model import EVSEScheduleExchangeV20

    personality = SECCPersonality.model_validate(
        {
            "power": {
                "evse_schedule_exchange_v20": {
                    "dynamic_departure_time_s": 5400,
                    "dynamic_min_soc_percent": 25,
                    "dynamic_target_soc_percent": 90,
                }
            }
        }
    )
    ctrl = SimEVSEController(personality=personality)
    params = await ctrl.get_dynamic_se_params(
        selected_energy_service=None, schedule_exchange_req=None
    )
    default = EVSEScheduleExchangeV20()
    assert params.departure_time == default.dynamic_departure_time_s
    assert params.min_soc == default.dynamic_min_soc_percent
    assert params.target_soc == default.dynamic_target_soc_percent


# ---------------------------------------------------------------------------
# EVCC simulator: ISO-20 wire values come from personality
# ---------------------------------------------------------------------------


def _evcc_sim(personality_data: dict) -> SimEVController:
    personality = EVCCPersonality.model_validate(personality_data)
    return SimEVController(EVCCConfig.from_personality(personality))


@pytest.mark.asyncio
async def test_evcc_ac_v20_cpd_uses_personality():
    sim = _evcc_sim(
        {
            "power": {
                "ev_ac_v20": {
                    "max_charge_power_w": 22000.0,
                    "min_charge_power_w": 250.0,
                }
            }
        }
    )
    params = await sim.get_charge_params_v20(
        SelectedEnergyService(service=ServiceV20.AC, is_free=True, parameter_set=None)
    )
    assert params.ev_max_charge_power.get_decimal_value() == 22000.0
    assert params.ev_min_charge_power.get_decimal_value() == 250.0


@pytest.mark.asyncio
async def test_evcc_ac_bpt_v20_cpd_discharge_uses_personality():
    sim = _evcc_sim(
        {
            "power": {
                "ev_ac_v20": {
                    "bpt_max_discharge_power_w": 7500.0,
                    "bpt_min_discharge_power_w": 75.0,
                }
            }
        }
    )
    params = await sim.get_charge_params_v20(
        SelectedEnergyService(
            service=ServiceV20.AC_BPT, is_free=True, parameter_set=None
        )
    )
    assert params.ev_max_discharge_power.get_decimal_value() == 7500.0
    assert params.ev_min_discharge_power.get_decimal_value() == 75.0


@pytest.mark.asyncio
async def test_evcc_dc_v20_cpd_uses_personality():
    sim = _evcc_sim(
        {
            "power": {
                "ev_dc_v20": {
                    "max_charge_power_w": 320000.0,
                    "min_charge_power_w": 150.0,
                    "max_charge_current_a": 400.0,
                    "min_charge_current_a": 5.0,
                    "max_voltage_v": 920.0,
                    "min_voltage_v": 60.0,
                }
            }
        }
    )
    params = await sim.get_charge_params_v20(
        SelectedEnergyService(service=ServiceV20.DC, is_free=True, parameter_set=None)
    )
    assert params.ev_max_charge_power.get_decimal_value() == 320000.0
    assert params.ev_min_charge_power.get_decimal_value() == 150.0
    assert params.ev_max_charge_current.get_decimal_value() == 400.0
    assert params.ev_max_voltage.get_decimal_value() == 920.0
    assert params.ev_min_voltage.get_decimal_value() == 60.0


@pytest.mark.asyncio
async def test_evcc_dc_bpt_v20_cpd_discharge_uses_personality():
    sim = _evcc_sim(
        {
            "power": {
                "ev_dc_v20": {
                    "bpt_max_discharge_power_w": 22000.0,
                    "bpt_max_discharge_current_a": 22.0,
                }
            }
        }
    )
    params = await sim.get_charge_params_v20(
        SelectedEnergyService(
            service=ServiceV20.DC_BPT, is_free=True, parameter_set=None
        )
    )
    assert params.ev_max_discharge_power.get_decimal_value() == 22000.0
    assert params.ev_max_discharge_current.get_decimal_value() == 22.0


@pytest.mark.asyncio
async def test_evcc_scheduled_se_params_use_personality():
    sim = _evcc_sim(
        {
            "power": {
                "schedule_exchange_v20": {
                    "departure_time_s": 5400,
                    "scheduled_target_energy_request_wh": 15000.0,
                    "scheduled_max_energy_request_wh": 25000.0,
                    "scheduled_min_energy_request_wh": 0.5,
                    "power_schedule_duration_s": 2700,
                    "power_schedule_power_w": -8000.0,
                    "price_currency": "USD",
                    "price_energy_fee": 0.15,
                }
            }
        }
    )
    params = await sim.get_scheduled_se_params(
        selected_energy_service=None,
    )
    assert params.departure_time == 5400
    assert params.ev_target_energy_request.get_decimal_value() == 15000.0
    assert params.ev_max_energy_request.get_decimal_value() == 25000.0
    assert params.ev_min_energy_request.get_decimal_value() == 0.5
    offer = params.ev_energy_offer
    [entry] = offer.ev_power_schedule.ev_power_schedule_entries.entries
    assert entry.duration == 2700
    assert entry.power.get_decimal_value() == -8000.0
    assert offer.ev_absolute_price_schedule.currency == "USD"
    [stack] = offer.ev_absolute_price_schedule.ev_price_rule_stacks.ev_price_rule_stacks
    [price_rule] = stack.ev_price_rules
    assert price_rule.energy_fee.get_decimal_value() == pytest.approx(0.15)


@pytest.mark.asyncio
async def test_evcc_dynamic_se_params_use_personality():
    sim = _evcc_sim(
        {
            "power": {
                "schedule_exchange_v20": {
                    "departure_time_s": 6000,
                    "dynamic_min_soc_percent": 25,
                    "dynamic_target_soc_percent": 90,
                    "dynamic_target_energy_request_wh": 50000.0,
                    "dynamic_max_energy_request_wh": 75000.0,
                    "dynamic_min_energy_request_wh": -10000.0,
                    "dynamic_max_v2x_energy_request_wh": 4000.0,
                    "dynamic_min_v2x_energy_request_wh": 0.0,
                }
            }
        }
    )
    params = await sim.get_dynamic_se_params(selected_energy_service=None)
    assert params.departure_time == 6000
    assert params.min_soc == 25
    assert params.target_soc == 90
    assert params.ev_target_energy_request.get_decimal_value() == 50000.0
    assert params.ev_max_energy_request.get_decimal_value() == 75000.0
    assert params.ev_min_energy_request.get_decimal_value() == -10000.0
    assert params.ev_max_v2x_energy_request.get_decimal_value() == 4000.0


@pytest.mark.asyncio
async def test_evcc_dc_scheduled_loop_uses_personality():
    sim = _evcc_sim(
        {
            "power": {
                "ev_dc_v20": {
                    "target_voltage_v": 800.0,
                    "target_current_a": 250.0,
                }
            }
        }
    )
    params = await sim.get_scheduled_dc_charge_loop_params()
    assert params.ev_target_voltage.get_decimal_value() == 800.0
    assert params.ev_target_current.get_decimal_value() == 250.0


@pytest.mark.asyncio
async def test_evcc_dc_dynamic_loop_uses_personality():
    sim = _evcc_sim(
        {
            "power": {
                "ev_dc_v20": {
                    "dynamic_max_charge_power_w": 5000.0,
                    "dynamic_min_charge_power_w": 500.0,
                    "dynamic_max_charge_current_a": 50.0,
                    "dynamic_max_voltage_v": 500.0,
                    "dynamic_min_voltage_v": 50.0,
                }
            }
        }
    )
    params = await sim.get_dynamic_dc_charge_loop_params()
    assert params.ev_max_charge_power.get_decimal_value() == 5000.0
    assert params.ev_min_charge_power.get_decimal_value() == 500.0
    assert params.ev_max_charge_current.get_decimal_value() == 50.0
    assert params.ev_max_voltage.get_decimal_value() == 500.0
    assert params.ev_min_voltage.get_decimal_value() == 50.0


@pytest.mark.asyncio
async def test_evcc_dc_bpt_dynamic_loop_discharge_uses_personality():
    sim = _evcc_sim(
        {
            "power": {
                "ev_dc_v20": {
                    "bpt_dynamic_max_discharge_power_w": 250000.0,
                    "bpt_dynamic_min_discharge_power_w": 250000.0,
                    "bpt_dynamic_max_discharge_current_a": 250000.0,
                }
            }
        }
    )
    params = await sim.get_bpt_dynamic_dc_charge_loop_params()
    assert params.ev_max_discharge_power.get_decimal_value() == 250000.0
    assert params.ev_min_discharge_power.get_decimal_value() == 250000.0
    assert params.ev_max_discharge_current.get_decimal_value() == 250000.0


@pytest.mark.asyncio
async def test_evcc_present_and_target_voltage_use_personality():
    sim = _evcc_sim(
        {"power": {"ev_dc_v20": {"target_voltage_v": 750.0}}}
    )
    present = await sim.get_present_voltage()
    target = await sim.get_target_voltage()
    assert present.get_decimal_value() == 750.0
    assert target.get_decimal_value() == 750.0


@pytest.mark.asyncio
async def test_evcc_ac_scheduled_loop_uses_personality():
    sim = _evcc_sim(
        {
            "power": {
                "ev_ac_v20": {"scheduled_present_active_power_w": 150000.0}
            }
        }
    )
    params = await sim.get_ac_charge_loop_params_v20(
        ControlMode.SCHEDULED, ServiceV20.AC
    )
    assert params.ev_present_active_power.get_decimal_value() == 150000.0


@pytest.mark.asyncio
async def test_evcc_ac_dynamic_loop_uses_personality():
    sim = _evcc_sim(
        {
            "power": {
                "ev_ac_v20": {
                    "dynamic_max_charge_power_w": 250000.0,
                    "dynamic_min_charge_power_w": 150.0,
                    "dynamic_present_active_power_w": 150000.0,
                    "dynamic_present_reactive_power_w": 15000.0,
                },
                "schedule_exchange_v20": {
                    "ac_dynamic_loop_departure_time_s": 1800,
                    "dynamic_target_energy_request_wh": 35000.0,
                    "dynamic_max_energy_request_wh": 55000.0,
                    "dynamic_min_energy_request_wh": -15000.0,
                },
            }
        }
    )
    params = await sim.get_ac_charge_loop_params_v20(
        ControlMode.DYNAMIC, ServiceV20.AC
    )
    assert params.departure_time == 1800
    assert params.ev_target_energy_request.get_decimal_value() == 35000.0
    assert params.ev_max_charge_power.get_decimal_value() == 250000.0
    assert params.ev_min_charge_power.get_decimal_value() == 150.0
    assert params.ev_present_active_power.get_decimal_value() == 150000.0
    assert params.ev_present_reactive_power.get_decimal_value() == 15000.0


@pytest.mark.asyncio
async def test_evcc_ac_bpt_dynamic_loop_discharge_uses_personality():
    sim = _evcc_sim(
        {
            "power": {
                "ev_ac_v20": {
                    "bpt_max_discharge_power_w": 7500.0,
                    "bpt_min_discharge_power_w": 75.0,
                }
            }
        }
    )
    params = await sim.get_ac_charge_loop_params_v20(
        ControlMode.DYNAMIC, ServiceV20.AC_BPT
    )
    assert params.ev_max_discharge_power.get_decimal_value() == 7500.0
    assert params.ev_min_discharge_power.get_decimal_value() == 75.0
