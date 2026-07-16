"""ISO 15118-20 personality fields (issue #9, slice 4).

Tests the contract that every personality-shaped field used during an ISO
15118-20 session is sourced from the personality config — see issue #9's
"What to build" / "Acceptance criteria".

Mirrors the structure of `test_iso2_slice.py`: controller-level tests
assert the simulators honour personality values when building
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

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.secc.controller.simulator import SimEVSEController
from app.shared.messages.enums import ControlMode, Protocol, ServiceV20
from app.shared.messages.iso15118_20.common_messages import (
    SelectedEnergyService,
)
from app.shared.personality.model import EVCCPersonality, SECCPersonality


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
    personality = SECCPersonality.model_validate({})
    ctrl = SimEVSEController(personality=personality)
    params = await ctrl.get_ac_charge_params_v20(ServiceV20.AC)

    # Retired EVSEACLimitsV20 skeleton defaults.
    assert params.evse_max_charge_power.get_decimal_value() == 30000.0
    assert params.evse_max_charge_power_l2.get_decimal_value() == 30000.0
    assert params.evse_min_charge_power.get_decimal_value() == 100.0
    assert params.evse_nominal_frequency.get_decimal_value() == 50.0
    assert params.max_power_asymmetry.get_decimal_value() == 0.0
    assert params.evse_power_ramp_limit.get_decimal_value() == 100.0


@pytest.mark.asyncio
async def test_secc_ac_bpt_v20_discharge_retired_to_skeleton():
    # #100: the AC-BPT discharge envelope is likewise tree-sourced now (an AC-BPT
    # device pins it as BPT_AC_CPDResEnergyTransferMode leaves), so the builder
    # returns the model-default skeleton, not the personality's evse_ac_v20.
    personality = SECCPersonality.model_validate({})
    ctrl = SimEVSEController(personality=personality)
    params = await ctrl.get_ac_charge_params_v20(ServiceV20.AC_BPT)

    # Retired EVSEACLimitsV20 skeleton defaults.
    assert params.evse_max_discharge_power.get_decimal_value() == 30000.0
    assert params.evse_min_discharge_power_l2.get_decimal_value() == 100.0


@pytest.mark.asyncio
async def test_secc_dc_v20_charge_params_retired_to_skeleton():
    # #98 retired the structured `power.evse_dc_v20` ISO-20 DC SECC read: the DC
    # envelope is now tree-sourced at the DCChargeParameterDiscoveryRes build
    # site, so this builder returns the ISO-20 DC-limit model-default *skeleton*
    # regardless of the personality's evse_dc_v20 (which no longer reaches the
    # ISO-20 wire through here).
    personality = SECCPersonality.model_validate({})
    ctrl = SimEVSEController(personality=personality)
    params = await ctrl.get_dc_charge_params_v20(ServiceV20.DC)

    # Retired EVSEDCLimitsV20 skeleton defaults.
    assert params.evse_max_charge_power.get_decimal_value() == 1000.0
    assert params.evse_min_charge_power.get_decimal_value() == 100.0
    assert params.evse_max_charge_current.get_decimal_value() == 100.0
    assert params.evse_max_voltage.get_decimal_value() == 500.0
    assert params.evse_power_ramp_limit.get_decimal_value() == 10.0


@pytest.mark.asyncio
async def test_secc_dc_bpt_v20_discharge_retired_to_skeleton():
    # #98: the DC-BPT discharge envelope is likewise tree-sourced now (the
    # baseline pins it as BPT_DC_CPDResEnergyTransferMode leaves), so the builder
    # returns the model-default skeleton, not the personality's evse_dc_v20.
    personality = SECCPersonality.model_validate({})
    ctrl = SimEVSEController(personality=personality)
    params = await ctrl.get_dc_charge_params_v20(ServiceV20.DC_BPT)

    # Retired EVSEDCLimitsV20 skeleton defaults.
    assert params.evse_max_discharge_power.get_decimal_value() == 1000.0
    assert params.evse_max_discharge_current.get_decimal_value() == 100.0


@pytest.mark.asyncio
async def test_secc_meter_info_v20_uses_tree_id_and_residual_reading():
    # #105: MeterID is tree-sourced from the {DC,AC}ChargeLoopRes MeterInfo leaf;
    # the reading start seed comes from residual.metering.
    personality = SECCPersonality.model_validate(
        {
            "residual": {"metering": {"starting_reading_wh": 78910}},
            "message_field_tree": {
                "ISO_15118_20_AC": {
                    "ACChargeLoopRes": {"MeterInfo": {"MeterID": "ACME-V20"}}
                }
            },
        }
    )
    ctrl = SimEVSEController(personality=personality)
    info = await ctrl.get_meter_info_v20(Protocol.ISO_15118_20_AC)
    assert info.meter_id == "ACME-V20"
    assert info.charged_energy_reading_wh == 78910


@pytest.mark.asyncio
async def test_secc_scheduled_se_params_retired_to_skeleton():
    # #98 retired the structured `power.evse_schedule_exchange_v20` ISO-20 SECC
    # read: ScheduleExchangeRes wire values are now tree-sourced at the build
    # site, so this builder returns the model-default skeleton regardless of the
    # personality's evse_schedule_exchange_v20.
    personality = SECCPersonality.model_validate({})
    ctrl = SimEVSEController(personality=personality)
    params = await ctrl.get_scheduled_se_params(
        selected_energy_service=None, schedule_exchange_req=None
    )
    # Retired EVSEScheduleExchangeV20 skeleton defaults.
    [tup] = params.schedule_tuples
    [entry] = tup.charging_schedule.power_schedule.schedule_entry_list.entries
    assert entry.duration == 3600
    assert entry.power.get_decimal_value() == 10000.0
    assert (
        tup.charging_schedule.power_schedule.available_energy.get_decimal_value()
        == 300000.0
    )
    [dis_entry] = tup.discharging_schedule.power_schedule.schedule_entry_list.entries
    assert dis_entry.power.get_decimal_value() == 10000.0


@pytest.mark.asyncio
async def test_secc_dynamic_se_params_retired_to_skeleton():
    # #98: the dynamic ScheduleExchangeRes params are likewise builder-skeleton
    # now, not sourced from the personality's evse_schedule_exchange_v20.
    personality = SECCPersonality.model_validate({})
    ctrl = SimEVSEController(personality=personality)
    params = await ctrl.get_dynamic_se_params(
        selected_energy_service=None, schedule_exchange_req=None
    )
    # Retired EVSEScheduleExchangeV20 skeleton defaults.
    assert params.departure_time == 7200
    assert params.min_soc == 30
    assert params.target_soc == 80


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
    sim = _evcc_sim({})
    params = await sim.get_charge_params_v20(
        SelectedEnergyService(service=ServiceV20.AC, is_free=True, parameter_set=None)
    )
    # Retired EVACLimitsV20 skeleton defaults.
    assert params.ev_max_charge_power.get_decimal_value() == 11000.0
    assert params.ev_min_charge_power.get_decimal_value() == 100.0


@pytest.mark.asyncio
async def test_evcc_ac_bpt_v20_cpd_discharge_retired_to_skeleton():
    # #101: the AC-BPT requested discharge envelope is likewise tree-sourced now
    # (an AC-BPT device pins it as BPT_AC_CPDReqEnergyTransferMode leaves), so the
    # builder returns the model-default skeleton, not the personality's ev_ac_v20.
    sim = _evcc_sim({})
    params = await sim.get_charge_params_v20(
        SelectedEnergyService(
            service=ServiceV20.AC_BPT, is_free=True, parameter_set=None
        )
    )
    # Retired EVACLimitsV20 skeleton defaults.
    assert params.ev_max_discharge_power.get_decimal_value() == 11000.0
    assert params.ev_min_discharge_power.get_decimal_value() == 1.0


@pytest.mark.asyncio
async def test_evcc_dc_v20_cpd_retired_to_skeleton():
    # #99 retired the structured `power.ev_dc_v20` ISO-20 DC EVCC read: the DC
    # requested envelope is now tree-sourced at the DCChargeParameterDiscoveryReq
    # build site, so this builder returns the `EVDCLimitsV20` model-default
    # *skeleton* regardless of the personality's ev_dc_v20 (which no longer
    # reaches the ISO-20 wire through here).
    sim = _evcc_sim({})
    params = await sim.get_charge_params_v20(
        SelectedEnergyService(service=ServiceV20.DC, is_free=True, parameter_set=None)
    )
    # Retired EVDCLimitsV20 skeleton defaults.
    assert params.ev_max_charge_power.get_decimal_value() == 300000.0
    assert params.ev_min_charge_power.get_decimal_value() == 100.0
    assert params.ev_max_charge_current.get_decimal_value() == 300.0
    assert params.ev_max_voltage.get_decimal_value() == 1000.0
    assert params.ev_min_voltage.get_decimal_value() == 10.0


@pytest.mark.asyncio
async def test_evcc_dc_bpt_v20_cpd_discharge_retired_to_skeleton():
    # #99: the DC-BPT requested discharge envelope is likewise tree-sourced now
    # (the baseline pins it as BPT_DC_CPDReqEnergyTransferMode leaves), so the
    # builder returns the model-default skeleton, not the personality's ev_dc_v20.
    sim = _evcc_sim({})
    params = await sim.get_charge_params_v20(
        SelectedEnergyService(
            service=ServiceV20.DC_BPT, is_free=True, parameter_set=None
        )
    )
    # Retired EVDCLimitsV20 skeleton defaults.
    assert params.ev_max_discharge_power.get_decimal_value() == 11000.0
    assert params.ev_max_discharge_current.get_decimal_value() == 11.0


@pytest.mark.asyncio
async def test_evcc_scheduled_se_params_retired_to_skeleton():
    # #99 retired the structured `power.schedule_exchange_v20` ISO-20 DC EVCC
    # read: ScheduleExchangeReq (a common message) is tree-sourced at the build
    # site now, so this builder returns the `ScheduleExchangeV20` model-default
    # skeleton regardless of the personality.
    sim = _evcc_sim({})
    params = await sim.get_scheduled_se_params(
        selected_energy_service=None,
    )
    # Retired ScheduleExchangeV20 skeleton defaults.
    assert params.departure_time == 7200
    assert params.ev_target_energy_request.get_decimal_value() == 10000.0
    assert params.ev_max_energy_request.get_decimal_value() == 20000.0
    offer = params.ev_energy_offer
    [entry] = offer.ev_power_schedule.ev_power_schedule_entries.entries
    assert entry.duration == 3600
    assert entry.power.get_decimal_value() == -10000.0
    assert offer.ev_absolute_price_schedule.currency == "EUR"


@pytest.mark.asyncio
async def test_evcc_dynamic_se_params_retired_to_skeleton():
    # #99: the dynamic ScheduleExchangeReq params are likewise builder-skeleton
    # now, not sourced from the personality's schedule_exchange_v20.
    sim = _evcc_sim({})
    params = await sim.get_dynamic_se_params(selected_energy_service=None)
    # Retired ScheduleExchangeV20 skeleton defaults.
    assert params.departure_time == 7200
    assert params.min_soc == 30
    assert params.target_soc == 80
    assert params.ev_target_energy_request.get_decimal_value() == 40000.0
    assert params.ev_max_energy_request.get_decimal_value() == 60000.0


@pytest.mark.asyncio
async def test_evcc_dc_scheduled_loop_retired_to_skeleton():
    # #99: the scheduled DC ChargeLoop targets are allowlisted (runtime-produced),
    # so their ev_dc_v20 fallback retires to the model-default skeleton; the live
    # override (not exercised here) still wins over that fallback.
    sim = _evcc_sim({})
    params = await sim.get_scheduled_dc_charge_loop_params()
    # Retired EVDCLimitsV20 skeleton defaults.
    assert params.ev_target_voltage.get_decimal_value() == 20000.0
    assert params.ev_target_current.get_decimal_value() == 200.0


@pytest.mark.asyncio
async def test_evcc_dc_dynamic_loop_retired_to_skeleton():
    # #99: the dynamic DC ChargeLoop magnitudes retire to the EVDCLimitsV20
    # model-default skeleton (the DCChargeLoopReq is tree-sourced now).
    sim = _evcc_sim({})
    params = await sim.get_dynamic_dc_charge_loop_params()
    # Retired EVDCLimitsV20 skeleton defaults.
    assert params.ev_max_charge_power.get_decimal_value() == 4000.0
    assert params.ev_min_charge_power.get_decimal_value() == 400.0
    assert params.ev_max_charge_current.get_decimal_value() == 40.0
    assert params.ev_max_voltage.get_decimal_value() == 400.0
    assert params.ev_min_voltage.get_decimal_value() == 40.0


@pytest.mark.asyncio
async def test_evcc_dc_bpt_dynamic_loop_discharge_retired_to_skeleton():
    # #99: the BPT dynamic DC ChargeLoop discharge envelope retires to the
    # EVDCLimitsV20 model-default skeleton.
    sim = _evcc_sim({})
    params = await sim.get_bpt_dynamic_dc_charge_loop_params()
    # Retired EVDCLimitsV20 skeleton defaults.
    assert params.ev_max_discharge_power.get_decimal_value() == 300000.0
    assert params.ev_min_discharge_power.get_decimal_value() == 300000.0
    assert params.ev_max_discharge_current.get_decimal_value() == 300000.0


@pytest.mark.asyncio
async def test_evcc_present_and_target_voltage_retired_to_skeleton():
    # #99: the ramping present / target voltage are allowlisted; their ev_dc_v20
    # fallback retires to the EVDCLimitsV20 model-default skeleton (the live
    # override, not exercised here, still wins over that fallback).
    sim = _evcc_sim({})
    present = await sim.get_present_voltage()
    target = await sim.get_target_voltage()
    # Retired EVDCLimitsV20 skeleton default (target_voltage_v=20000).
    assert present.get_decimal_value() == 20000.0
    assert target.get_decimal_value() == 20000.0


@pytest.mark.asyncio
async def test_evcc_iso20_live_override_beats_skeleton():
    # ADR-0004 / issue #32 precedence survives the #99 retirement: the operator's
    # live override still wins over the retired model-default skeleton fallback at
    # the ISO-20 DC ramping read sites (present voltage, scheduled/dynamic loop
    # targets), even though ev_dc_v20 no longer feeds them.
    from app.shared.live_control import LiveControl

    personality = EVCCPersonality.model_validate({})
    live = LiveControl(override_voltage_v=654.0, override_current_a=321.0)
    sim = SimEVController(EVCCConfig.from_personality(personality), live_control=live)

    # Retired EVDCLimitsV20 skeleton default (target_voltage_v=20000).
    assert 20000.0 != 654.0  # guard: override is distinguishable

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
    sim = _evcc_sim({})
    params = await sim.get_ac_charge_loop_params_v20(
        ControlMode.SCHEDULED, ServiceV20.AC
    )
    # Retired EVACLimitsV20 skeleton default.
    assert params.ev_present_active_power.get_decimal_value() == 200000.0


@pytest.mark.asyncio
async def test_evcc_ac_dynamic_loop_retired_to_skeleton():
    # #101: the dynamic AC ChargeLoop magnitudes and its departure/energy requests
    # retire to the EVACLimitsV20 / ScheduleExchangeV20 model-default skeletons (the
    # ACChargeLoopReq is tree-sourced now), not the personality's ev_ac_v20 /
    # schedule_exchange_v20.
    sim = _evcc_sim({})
    params = await sim.get_ac_charge_loop_params_v20(
        ControlMode.DYNAMIC, ServiceV20.AC
    )
    # Retired ScheduleExchangeV20 / EVACLimitsV20 skeleton defaults.
    assert params.departure_time == 2000
    assert params.ev_target_energy_request.get_decimal_value() == 40000.0
    assert params.ev_max_charge_power.get_decimal_value() == 300000.0
    assert params.ev_min_charge_power.get_decimal_value() == 100.0
    assert params.ev_present_active_power.get_decimal_value() == 200000.0
    assert params.ev_present_reactive_power.get_decimal_value() == 20000.0


@pytest.mark.asyncio
async def test_evcc_ac_bpt_dynamic_loop_discharge_retired_to_skeleton():
    # #101: the BPT dynamic AC ChargeLoop discharge envelope retires to the
    # EVACLimitsV20 model-default skeleton.
    sim = _evcc_sim({})
    params = await sim.get_ac_charge_loop_params_v20(
        ControlMode.DYNAMIC, ServiceV20.AC_BPT
    )
    # Retired EVACLimitsV20 skeleton defaults.
    assert params.ev_max_discharge_power.get_decimal_value() == 11000.0
    assert params.ev_min_discharge_power.get_decimal_value() == 1.0
