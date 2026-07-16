"""ISO 15118-2 personality fields (issue #8, slice 3).

Tests the contract that every personality-shaped field used during an ISO
15118-2 session is sourced from the personality config — see issue #8's
"What to build" / "Acceptance criteria".

Mirrors the structure of `test_din_slice.py`: controller-level tests
assert the simulators honour personality values when building ISO-2 wire
messages.

Note (#96 / #97): the ISO-2 *SECC* structured reads (AC charge params, ISO-2 SA
schedule) are retired (#96) and the ISO-2 *EVCC* structured reads (AC envelope,
ISO-2 DC announcements) are retired (#97) — those wire values are now sourced
from the `message_field_tree`, so the corresponding builders return the
model-default skeleton (or omit the fields the Mach-E omits) and the tests below
assert that retirement.
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
# Model: meter section exists with strict validation
# ---------------------------------------------------------------------------


def test_meter_section_defaults():
    p = SECCPersonality.model_validate({})
    assert p.meter.meter_id
    assert p.meter.starting_reading_wh >= 0


def test_meter_section_rejects_unknown_field():
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate({"meter": {"meter_id": "X", "junk": 1}})


# ---------------------------------------------------------------------------
# SECC simulator: ISO-2 wire values come from personality
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_secc_ac_charge_params_retired_to_skeleton():
    # #96 retired the structured `power.evse_ac` ISO-2 SECC read: the AC envelope
    # is now tree-sourced at the ChargeParameterDiscoveryRes build site, so this
    # builder returns the AC-limit model-default *skeleton* regardless of the
    # personality's evse_ac (which no longer reaches the ISO-2 wire through here).
    personality = SECCPersonality.model_validate({})
    ctrl = SimEVSEController(personality=personality)
    params = await ctrl.get_ac_charge_params_v2()

    # Retired EVSEACLimits skeleton defaults.
    assert params.evse_nominal_voltage.get_decimal_value() == 400.0
    assert params.evse_max_current.get_decimal_value() == 32.0


@pytest.mark.asyncio
async def test_secc_sa_schedule_iso2_retired_to_skeleton():
    # #96 retired the structured `iso2_sa_schedule_pmax_w` / `iso2_sales_tariff_id`
    # ISO-2 SECC reads: the SAScheduleList is a tree wire value overridden at the
    # build site (or falls back to the builder skeleton). This builder now uses
    # the DC-limit model defaults regardless of the personality's values.
    personality = SECCPersonality.model_validate({})
    ctrl = SimEVSEController(personality=personality)
    schedules = await ctrl.get_sa_schedule_list(
        ev_data_context=None,
        is_free_charging_service=False,
        max_schedule_entries=None,
        departure_time=0,
    )
    assert schedules is not None
    [entry] = schedules
    # Retired EVSEDCLimits skeleton defaults (iso2_sa_schedule_pmax_w=11000,
    # iso2_sales_tariff_id=10).
    pmax_values = [
        e.p_max.get_decimal_value() for e in entry.p_max_schedule.schedule_entries
    ]
    assert all(v == float(11000) for v in pmax_values)
    assert entry.sales_tariff.sales_tariff_id == 10


@pytest.mark.asyncio
async def test_secc_meter_info_v2_uses_personality():
    personality = SECCPersonality.model_validate(
        {"meter": {"meter_id": "ACME-001", "starting_reading_wh": 99999}}
    )
    ctrl = SimEVSEController(personality=personality)
    info = await ctrl.get_meter_info_v2()
    assert info.meter_id == "ACME-001"
    assert info.meter_reading == 99999


@pytest.mark.asyncio
async def test_secc_meter_info_v20_uses_personality_meter_id():
    personality = SECCPersonality.model_validate(
        {"meter": {"meter_id": "ACME-002"}}
    )
    ctrl = SimEVSEController(personality=personality)
    info = await ctrl.get_meter_info_v20()
    assert info.meter_id == "ACME-002"


# ---------------------------------------------------------------------------
# EVCC simulator: ISO-2 wire values come from personality
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evcc_iso2_ac_charge_params_retired_to_skeleton():
    # #97 retired the structured `power.ev_ac` ISO-2 EVCC read: the AC envelope is
    # now tree-sourced at the ChargeParameterDiscoveryReq build site, so this
    # builder returns the AC-limit model-default *skeleton* regardless of the
    # personality's ev_ac (which no longer reaches the ISO-2 wire through here).
    personality = EVCCPersonality.model_validate(
        {"capabilities": {"energy_transfer_mode": "AC_three_phase_core"}}
    )
    evcc_config = EVCCConfig.from_personality(personality)
    sim = SimEVController(evcc_config)
    params = await sim.get_charge_params_v2(Protocol.ISO_15118_2)

    ac = params.ac_parameters
    assert ac is not None
    # Retired EVACLimits skeleton defaults.
    assert ac.e_amount.get_decimal_value() == 60.0
    assert ac.ev_max_voltage.get_decimal_value() == 400.0
    assert ac.ev_max_current.get_decimal_value() == 32.0
    assert ac.ev_min_current.get_decimal_value() == 10.0


@pytest.mark.asyncio
async def test_evcc_iso2_dc_charge_params_retired_to_skeleton():
    # #97 retired the structured ISO-2 DC announcements: the DC envelope maxima
    # come from the EVDCLimits model-default skeleton (the tree overrides them at
    # the build site), and the Mach-E omits EVEnergyRequest / FullSOC / BulkSOC /
    # EVEnergyCapacity / DepartureTime, so this builder leaves them unset.
    personality = EVCCPersonality.model_validate(
        {"capabilities": {"energy_transfer_mode": "DC_extended"}}
    )
    evcc_config = EVCCConfig.from_personality(personality)
    sim = SimEVController(evcc_config)
    params = await sim.get_charge_params_v2(Protocol.ISO_15118_2)

    dc = params.dc_parameters
    assert dc is not None
    # The Mach-E-omitted Optional fields are left unset (not the personality's).
    assert dc.ev_energy_request is None
    assert dc.full_soc is None
    assert dc.bulk_soc is None
    assert dc.ev_energy_capacity is None
    assert dc.departure_time is None
    # The announced maxima come from the retired EVDCLimits skeleton defaults.
    assert dc.ev_maximum_power_limit.get_decimal_value() == 80000.0
    assert dc.ev_maximum_voltage_limit.get_decimal_value() == 500.0
    assert dc.ev_maximum_current_limit.get_decimal_value() == 32.0


@pytest.mark.asyncio
async def test_evcc_iso2_energy_transfer_mode_tracks_personality():
    personality = EVCCPersonality.model_validate(
        {"capabilities": {"energy_transfer_mode": "DC_extended"}}
    )
    evcc_config = EVCCConfig.from_personality(personality)
    sim = SimEVController(evcc_config)
    mode = await sim.get_energy_transfer_mode(Protocol.ISO_15118_2)
    assert mode == EnergyTransferModeEnum.DC_EXTENDED
