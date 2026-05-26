"""DIN 70121 personality fields (issue #7, slice 2).

Tests the contract that every personality-shaped field used during a DIN
session is sourced from the personality config — see issue #7's "What to
build" / "Acceptance criteria".

The model-level tests assert the new `power.evse_dc` / `power.ev_dc`
sections exist with strict validation. The controller-level tests assert
the simulators honour personality values when building DIN wire messages.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.secc.controller.simulator import SimEVSEController
from app.shared.messages.enums import EnergyTransferModeEnum, Protocol
from app.shared.personality.model import EVCCPersonality, SECCPersonality


# ---------------------------------------------------------------------------
# Model: power section grows DIN-relevant sub-blocks
# ---------------------------------------------------------------------------


def test_power_section_has_evse_and_ev_dc_subsections():
    p = SECCPersonality.model_validate({})
    assert p.power.evse_dc.max_voltage_v > 0
    assert p.power.evse_dc.max_current_a > 0
    assert p.power.evse_dc.max_power_w > 0
    assert p.power.ev_dc.max_voltage_v > 0
    assert p.power.ev_dc.max_current_a > 0
    assert p.power.ev_dc.energy_capacity_wh > 0


def test_power_evse_dc_rejects_unknown_field():
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate(
            {"power": {"evse_dc": {"max_voltage_v": 500.0, "bogus": 1}}}
        )


def test_power_ev_dc_rejects_unknown_field():
    with pytest.raises(ValidationError):
        EVCCPersonality.model_validate(
            {"power": {"ev_dc": {"max_voltage_v": 500.0, "made_up": 0}}}
        )


def test_power_evse_dc_overrides_apply():
    p = SECCPersonality.model_validate(
        {"power": {"evse_dc": {"max_voltage_v": 1000.0, "max_current_a": 250.0}}}
    )
    assert p.power.evse_dc.max_voltage_v == 1000.0
    assert p.power.evse_dc.max_current_a == 250.0


# ---------------------------------------------------------------------------
# SECC simulator: DIN wire values come from personality
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_secc_dc_charge_parameters_din_use_personality_limits():
    personality = SECCPersonality.model_validate(
        {
            "power": {
                "evse_dc": {
                    "max_voltage_v": 600.0,
                    "min_voltage_v": 10.0,
                    "max_current_a": 250.0,
                    "min_current_a": 5.0,
                    "max_power_w": 150000.0,
                    "peak_current_ripple_a": 3.0,
                }
            }
        }
    )
    ctrl = SimEVSEController(personality=personality)
    params = await ctrl.get_dc_charge_parameters_dinspec()

    assert params.evse_maximum_voltage_limit.get_decimal_value() == 600.0
    assert params.evse_minimum_voltage_limit.get_decimal_value() == 10.0
    assert params.evse_maximum_current_limit.get_decimal_value() == 250.0
    assert params.evse_minimum_current_limit.get_decimal_value() == 5.0
    assert params.evse_maximum_power_limit.get_decimal_value() == 150000.0
    assert params.evse_peak_current_ripple.get_decimal_value() == 3.0


@pytest.mark.asyncio
async def test_secc_max_power_limit_din_uses_personality():
    personality = SECCPersonality.model_validate(
        {"power": {"evse_dc": {"max_power_w": 42000.0}}}
    )
    ctrl = SimEVSEController(personality=personality)
    pmax = await ctrl.get_evse_max_power_limit(protocol=Protocol.DIN_SPEC_70121)
    assert pmax.get_decimal_value() == 42000.0


@pytest.mark.asyncio
async def test_secc_sa_schedule_dinspec_uses_personality_pmax():
    # DIN 70121's PMaxScheduleEntry.p_max is an int16 (max 32767 W), so the
    # personality field is constrained to that range as well.
    personality = SECCPersonality.model_validate(
        {"power": {"evse_dc": {"sa_schedule_pmax_w": 25000}}}
    )
    ctrl = SimEVSEController(personality=personality)
    schedules = await ctrl.get_sa_schedule_list_dinspec(None, 0)
    assert schedules is not None
    [entry] = schedules
    [details] = entry.p_max_schedule.entry_details
    assert details.p_max == 25000


@pytest.mark.asyncio
async def test_secc_supported_energy_modes_din_track_personality():
    personality = SECCPersonality.model_validate(
        {"capabilities": {"energy_transfer_mode": "DC_core"}}
    )
    ctrl = SimEVSEController(personality=personality)
    modes = await ctrl.get_supported_energy_transfer_modes(Protocol.DIN_SPEC_70121)
    assert modes == [EnergyTransferModeEnum.DC_CORE]


# ---------------------------------------------------------------------------
# EVCC simulator: DIN wire values come from personality
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evcc_dc_charge_params_din_use_personality_limits():
    personality = EVCCPersonality.model_validate(
        {
            "power": {
                "ev_dc": {
                    "max_voltage_v": 800.0,
                    "max_current_a": 120.0,
                    "max_power_w": 200000.0,
                    "energy_capacity_wh": 90000.0,
                    "target_voltage_v": 750.0,
                    "target_current_a": 17.0,
                }
            }
        }
    )
    evcc_config = EVCCConfig.from_personality(personality)
    sim = SimEVController(evcc_config)
    params = await sim.get_dc_charge_params(Protocol.DIN_SPEC_70121)

    assert params.dc_max_voltage_limit.get_decimal_value() == 800.0
    assert params.dc_max_current_limit.get_decimal_value() == 120.0
    assert params.dc_max_power_limit.get_decimal_value() == 200000.0
    assert params.dc_energy_capacity.get_decimal_value() == 90000.0
    assert params.dc_target_voltage.get_decimal_value() == 750.0
    assert params.dc_target_current.get_decimal_value() == 17.0
