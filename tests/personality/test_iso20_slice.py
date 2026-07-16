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
assert that.

Note (#100): the ISO-20 *AC SECC* structured read (`power.evse_ac_v20`) is
likewise retired — the AC-emitted ISO-20 messages are tree-sourced now, so the
`get_ac_charge_params_v20` builder returns the `EVSEACLimitsV20` model-default
skeleton (`test_secc_ac_v20_*_retired_to_skeleton`). The AC EVCC reads
(`ev_ac_v20` and the AC uses of `schedule_exchange_v20`) are unchanged.

Note (#99): the ISO-20 *DC EVCC* structured reads (`power.ev_dc_v20` and the DC
uses of `power.schedule_exchange_v20`) are likewise retired — the EVCC-emitted
ISO-20 DC messages are tree-sourced now, so the corresponding EVCC DC builders
return the model-default skeleton (`test_evcc_dc_*_retired_to_skeleton`), and the
live override still wins over that skeleton fallback
(`test_evcc_iso20_live_override_beats_skeleton`).

Note (#101): the ISO-20 *AC EVCC* structured reads (`power.ev_ac_v20` and the AC
uses of `power.schedule_exchange_v20`, incl. `ac_dynamic_loop_departure_time_s`)
are the last per-role gap and are now retired too — the EVCC-emitted ISO-20 AC
messages are tree-sourced, so the corresponding EVCC AC builders return the
`EVACLimitsV20` / `ScheduleExchangeV20` model-default skeleton
(`test_evcc_ac_*_retired_to_skeleton`). With this slice every ISO-20 structured
`power.*` read is retired on both roles.
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
async def test_secc_ac_v20_charge_params_retired_to_skeleton():
    # #100 retired the structured `power.evse_ac_v20` ISO-20 AC SECC read: the AC
    # envelope is now tree-sourced at the ACChargeParameterDiscoveryRes build
    # site, so this builder returns the `EVSEACLimitsV20` model-default *skeleton*
    # regardless of the personality's evse_ac_v20 (which no longer reaches the
    # ISO-20 wire through here).
    from app.shared.personality.model import EVSEACLimitsV20

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

    default = EVSEACLimitsV20()
    assert params.evse_max_charge_power.get_decimal_value() == default.max_charge_power_w
    assert (
        params.evse_max_charge_power_l2.get_decimal_value() == default.max_charge_power_w
    )
    assert params.evse_min_charge_power.get_decimal_value() == default.min_charge_power_w
    assert (
        params.evse_nominal_frequency.get_decimal_value() == default.nominal_frequency_hz
    )
    assert params.max_power_asymmetry.get_decimal_value() == default.max_power_asymmetry_w
    assert (
        params.evse_power_ramp_limit.get_decimal_value()
        == default.power_ramp_limit_w_per_s
    )


@pytest.mark.asyncio
async def test_secc_ac_bpt_v20_discharge_retired_to_skeleton():
    # #100: the AC-BPT discharge envelope is likewise tree-sourced now (an AC-BPT
    # device pins it as BPT_AC_CPDResEnergyTransferMode leaves), so the builder
    # returns the model-default skeleton, not the personality's evse_ac_v20.
    from app.shared.personality.model import EVSEACLimitsV20

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

    default = EVSEACLimitsV20()
    assert (
        params.evse_max_discharge_power.get_decimal_value()
        == default.bpt_max_discharge_power_w
    )
    assert (
        params.evse_min_discharge_power_l2.get_decimal_value()
        == default.bpt_min_discharge_power_w
    )


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
async def test_evcc_ac_v20_cpd_retired_to_skeleton():
    # #101 retired the structured `power.ev_ac_v20` ISO-20 AC EVCC read: the AC
    # requested envelope is now tree-sourced at the ACChargeParameterDiscoveryReq
    # build site, so this builder returns the `EVACLimitsV20` model-default
    # *skeleton* regardless of the personality's ev_ac_v20 (which no longer reaches
    # the ISO-20 wire through here).
    from app.shared.personality.model import EVACLimitsV20

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
    default = EVACLimitsV20()
    assert params.ev_max_charge_power.get_decimal_value() == default.max_charge_power_w
    assert params.ev_min_charge_power.get_decimal_value() == default.min_charge_power_w


@pytest.mark.asyncio
async def test_evcc_ac_bpt_v20_cpd_discharge_retired_to_skeleton():
    # #101: the AC-BPT requested discharge envelope is likewise tree-sourced now
    # (an AC-BPT device pins it as BPT_AC_CPDReqEnergyTransferMode leaves), so the
    # builder returns the model-default skeleton, not the personality's ev_ac_v20.
    from app.shared.personality.model import EVACLimitsV20

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
    default = EVACLimitsV20()
    assert (
        params.ev_max_discharge_power.get_decimal_value()
        == default.bpt_max_discharge_power_w
    )
    assert (
        params.ev_min_discharge_power.get_decimal_value()
        == default.bpt_min_discharge_power_w
    )


@pytest.mark.asyncio
async def test_evcc_dc_v20_cpd_retired_to_skeleton():
    # #99 retired the structured `power.ev_dc_v20` ISO-20 DC EVCC read: the DC
    # requested envelope is now tree-sourced at the DCChargeParameterDiscoveryReq
    # build site, so this builder returns the `EVDCLimitsV20` model-default
    # *skeleton* regardless of the personality's ev_dc_v20 (which no longer
    # reaches the ISO-20 wire through here).
    from app.shared.personality.model import EVDCLimitsV20

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
    default = EVDCLimitsV20()
    assert params.ev_max_charge_power.get_decimal_value() == default.max_charge_power_w
    assert params.ev_min_charge_power.get_decimal_value() == default.min_charge_power_w
    assert (
        params.ev_max_charge_current.get_decimal_value() == default.max_charge_current_a
    )
    assert params.ev_max_voltage.get_decimal_value() == default.max_voltage_v
    assert params.ev_min_voltage.get_decimal_value() == default.min_voltage_v


@pytest.mark.asyncio
async def test_evcc_dc_bpt_v20_cpd_discharge_retired_to_skeleton():
    # #99: the DC-BPT requested discharge envelope is likewise tree-sourced now
    # (the baseline pins it as BPT_DC_CPDReqEnergyTransferMode leaves), so the
    # builder returns the model-default skeleton, not the personality's ev_dc_v20.
    from app.shared.personality.model import EVDCLimitsV20

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
    default = EVDCLimitsV20()
    assert (
        params.ev_max_discharge_power.get_decimal_value()
        == default.bpt_max_discharge_power_w
    )
    assert (
        params.ev_max_discharge_current.get_decimal_value()
        == default.bpt_max_discharge_current_a
    )


@pytest.mark.asyncio
async def test_evcc_scheduled_se_params_retired_to_skeleton():
    # #99 retired the structured `power.schedule_exchange_v20` ISO-20 DC EVCC
    # read: ScheduleExchangeReq (a common message) is tree-sourced at the build
    # site now, so this builder returns the `ScheduleExchangeV20` model-default
    # skeleton regardless of the personality.
    from app.shared.personality.model import ScheduleExchangeV20

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
    default = ScheduleExchangeV20()
    assert params.departure_time == default.departure_time_s
    assert (
        params.ev_target_energy_request.get_decimal_value()
        == default.scheduled_target_energy_request_wh
    )
    assert (
        params.ev_max_energy_request.get_decimal_value()
        == default.scheduled_max_energy_request_wh
    )
    offer = params.ev_energy_offer
    [entry] = offer.ev_power_schedule.ev_power_schedule_entries.entries
    assert entry.duration == default.power_schedule_duration_s
    assert entry.power.get_decimal_value() == default.power_schedule_power_w
    assert offer.ev_absolute_price_schedule.currency == default.price_currency


@pytest.mark.asyncio
async def test_evcc_dynamic_se_params_retired_to_skeleton():
    # #99: the dynamic ScheduleExchangeReq params are likewise builder-skeleton
    # now, not sourced from the personality's schedule_exchange_v20.
    from app.shared.personality.model import ScheduleExchangeV20

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
    default = ScheduleExchangeV20()
    assert params.departure_time == default.departure_time_s
    assert params.min_soc == default.dynamic_min_soc_percent
    assert params.target_soc == default.dynamic_target_soc_percent
    assert (
        params.ev_target_energy_request.get_decimal_value()
        == default.dynamic_target_energy_request_wh
    )
    assert (
        params.ev_max_energy_request.get_decimal_value()
        == default.dynamic_max_energy_request_wh
    )


@pytest.mark.asyncio
async def test_evcc_dc_scheduled_loop_retired_to_skeleton():
    # #99: the scheduled DC ChargeLoop targets are allowlisted (runtime-produced),
    # so their ev_dc_v20 fallback retires to the model-default skeleton; the live
    # override (not exercised here) still wins over that fallback.
    from app.shared.personality.model import EVDCLimitsV20

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
    default = EVDCLimitsV20()
    assert params.ev_target_voltage.get_decimal_value() == default.target_voltage_v
    assert params.ev_target_current.get_decimal_value() == default.target_current_a


@pytest.mark.asyncio
async def test_evcc_dc_dynamic_loop_retired_to_skeleton():
    # #99: the dynamic DC ChargeLoop magnitudes retire to the EVDCLimitsV20
    # model-default skeleton (the DCChargeLoopReq is tree-sourced now).
    from app.shared.personality.model import EVDCLimitsV20

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
    default = EVDCLimitsV20()
    assert (
        params.ev_max_charge_power.get_decimal_value()
        == default.dynamic_max_charge_power_w
    )
    assert (
        params.ev_min_charge_power.get_decimal_value()
        == default.dynamic_min_charge_power_w
    )
    assert (
        params.ev_max_charge_current.get_decimal_value()
        == default.dynamic_max_charge_current_a
    )
    assert params.ev_max_voltage.get_decimal_value() == default.dynamic_max_voltage_v
    assert params.ev_min_voltage.get_decimal_value() == default.dynamic_min_voltage_v


@pytest.mark.asyncio
async def test_evcc_dc_bpt_dynamic_loop_discharge_retired_to_skeleton():
    # #99: the BPT dynamic DC ChargeLoop discharge envelope retires to the
    # EVDCLimitsV20 model-default skeleton.
    from app.shared.personality.model import EVDCLimitsV20

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
    default = EVDCLimitsV20()
    assert (
        params.ev_max_discharge_power.get_decimal_value()
        == default.bpt_dynamic_max_discharge_power_w
    )
    assert (
        params.ev_min_discharge_power.get_decimal_value()
        == default.bpt_dynamic_min_discharge_power_w
    )
    assert (
        params.ev_max_discharge_current.get_decimal_value()
        == default.bpt_dynamic_max_discharge_current_a
    )


@pytest.mark.asyncio
async def test_evcc_present_and_target_voltage_retired_to_skeleton():
    # #99: the ramping present / target voltage are allowlisted; their ev_dc_v20
    # fallback retires to the EVDCLimitsV20 model-default skeleton (the live
    # override, not exercised here, still wins over that fallback).
    from app.shared.personality.model import EVDCLimitsV20

    sim = _evcc_sim({"power": {"ev_dc_v20": {"target_voltage_v": 750.0}}})
    present = await sim.get_present_voltage()
    target = await sim.get_target_voltage()
    default = EVDCLimitsV20()
    assert present.get_decimal_value() == default.target_voltage_v
    assert target.get_decimal_value() == default.target_voltage_v


@pytest.mark.asyncio
async def test_evcc_iso20_live_override_beats_skeleton():
    # ADR-0004 / issue #32 precedence survives the #99 retirement: the operator's
    # live override still wins over the retired model-default skeleton fallback at
    # the ISO-20 DC ramping read sites (present voltage, scheduled/dynamic loop
    # targets), even though ev_dc_v20 no longer feeds them.
    from app.shared.live_control import LiveControl
    from app.shared.personality.model import EVDCLimitsV20

    personality = EVCCPersonality.model_validate({})
    live = LiveControl(override_voltage_v=654.0, override_current_a=321.0)
    sim = SimEVController(EVCCConfig.from_personality(personality), live_control=live)

    default = EVDCLimitsV20()
    assert default.target_voltage_v != 654.0  # guard: override is distinguishable

    present = await sim.get_present_voltage()
    assert present.get_decimal_value() == 654.0

    scheduled = await sim.get_scheduled_dc_charge_loop_params()
    assert scheduled.ev_target_voltage.get_decimal_value() == 654.0
    assert scheduled.ev_target_current.get_decimal_value() == 321.0

    dynamic = await sim.get_dynamic_dc_charge_loop_params()
    assert dynamic.ev_max_voltage.get_decimal_value() == 654.0
    assert dynamic.ev_max_charge_current.get_decimal_value() == 321.0


@pytest.mark.asyncio
async def test_evcc_ac_scheduled_loop_retired_to_skeleton():
    # #101: the scheduled AC ChargeLoop present-active-power stub is tree-sourced
    # now (allowlisted/runtime), so its ev_ac_v20 fallback retires to the
    # EVACLimitsV20 model-default skeleton.
    from app.shared.personality.model import EVACLimitsV20

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
    default = EVACLimitsV20()
    assert (
        params.ev_present_active_power.get_decimal_value()
        == default.scheduled_present_active_power_w
    )


@pytest.mark.asyncio
async def test_evcc_ac_dynamic_loop_retired_to_skeleton():
    # #101: the dynamic AC ChargeLoop magnitudes and its departure/energy requests
    # retire to the EVACLimitsV20 / ScheduleExchangeV20 model-default skeletons (the
    # ACChargeLoopReq is tree-sourced now), not the personality's ev_ac_v20 /
    # schedule_exchange_v20.
    from app.shared.personality.model import EVACLimitsV20, ScheduleExchangeV20

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
    ev_default = EVACLimitsV20()
    se_default = ScheduleExchangeV20()
    assert params.departure_time == se_default.ac_dynamic_loop_departure_time_s
    assert (
        params.ev_target_energy_request.get_decimal_value()
        == se_default.dynamic_target_energy_request_wh
    )
    assert (
        params.ev_max_charge_power.get_decimal_value()
        == ev_default.dynamic_max_charge_power_w
    )
    assert (
        params.ev_min_charge_power.get_decimal_value()
        == ev_default.dynamic_min_charge_power_w
    )
    assert (
        params.ev_present_active_power.get_decimal_value()
        == ev_default.dynamic_present_active_power_w
    )
    assert (
        params.ev_present_reactive_power.get_decimal_value()
        == ev_default.dynamic_present_reactive_power_w
    )


@pytest.mark.asyncio
async def test_evcc_ac_bpt_dynamic_loop_discharge_retired_to_skeleton():
    # #101: the BPT dynamic AC ChargeLoop discharge envelope retires to the
    # EVACLimitsV20 model-default skeleton.
    from app.shared.personality.model import EVACLimitsV20

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
    default = EVACLimitsV20()
    assert (
        params.ev_max_discharge_power.get_decimal_value()
        == default.bpt_max_discharge_power_w
    )
    assert (
        params.ev_min_discharge_power.get_decimal_value()
        == default.bpt_min_discharge_power_w
    )
