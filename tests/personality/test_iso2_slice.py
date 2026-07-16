"""ISO 15118-2 personality fields (issue #8, slice 3).

Tests the contract that every personality-shaped field used during an ISO
15118-2 session is sourced from the personality config — see issue #8's
"What to build" / "Acceptance criteria".

Mirrors the structure of `test_din_slice.py`: model-level tests assert
the new sections exist with strict validation, and controller-level
tests assert the simulators honour personality values when building
ISO-2 wire messages.

Note (#96 / #97): the ISO-2 *SECC* structured reads (AC charge params, ISO-2 SA
schedule) are retired (#96) and the ISO-2 *EVCC* structured reads (AC envelope,
ISO-2 DC announcements) are retired (#97) — those wire values are now sourced
from the `message_field_tree`, so the corresponding builders return the
model-default skeleton (or omit the fields the Mach-E omits) and the tests below
assert that retirement. The personality *model* fields still exist (the
structured `power` section predates the tree and is migrated in a later slice),
so the model-level tests still assert them.
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
# Model: ISO-2 fields exist with strict validation
# ---------------------------------------------------------------------------


def test_power_section_has_ac_subsections():
    p = SECCPersonality.model_validate({})
    assert p.power.evse_ac.nominal_voltage_v > 0
    assert p.power.evse_ac.max_current_a > 0
    assert p.power.ev_ac.e_amount_wh > 0
    assert p.power.ev_ac.max_voltage_v > 0
    assert p.power.ev_ac.max_current_a > 0
    assert p.power.ev_ac.min_current_a > 0


def test_power_evse_ac_rejects_unknown_field():
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate(
            {"power": {"evse_ac": {"nominal_voltage_v": 230.0, "bogus": 1}}}
        )


def test_power_ev_ac_rejects_unknown_field():
    with pytest.raises(ValidationError):
        EVCCPersonality.model_validate(
            {"power": {"ev_ac": {"e_amount_wh": 60.0, "made_up": 0}}}
        )


def test_evse_dc_has_iso2_sa_schedule_fields():
    p = SECCPersonality.model_validate({})
    assert p.power.evse_dc.iso2_sa_schedule_pmax_w > 0
    assert 1 <= p.power.evse_dc.iso2_sales_tariff_id <= 255


def test_evse_dc_iso2_sales_tariff_id_xsd_range():
    # XSD constrains SalesTariff.SalesTariffID to unsignedByte (1..255).
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate(
            {"power": {"evse_dc": {"iso2_sales_tariff_id": 0}}}
        )
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate(
            {"power": {"evse_dc": {"iso2_sales_tariff_id": 256}}}
        )


def test_ev_dc_has_iso2_announcement_fields():
    p = EVCCPersonality.model_validate({})
    assert p.power.ev_dc.iso2_energy_request_wh > 0
    assert 0 <= p.power.ev_dc.iso2_full_soc_percent <= 100
    assert 0 <= p.power.ev_dc.iso2_bulk_soc_percent <= 100


def test_ev_dc_soc_percent_range_enforced():
    with pytest.raises(ValidationError):
        EVCCPersonality.model_validate(
            {"power": {"ev_dc": {"iso2_full_soc_percent": 101}}}
        )


def test_meter_section_defaults():
    p = SECCPersonality.model_validate({})
    assert p.meter.meter_id
    assert p.meter.starting_reading_wh >= 0


def test_meter_section_rejects_unknown_field():
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate({"meter": {"meter_id": "X", "junk": 1}})


def test_power_ac_overrides_apply():
    p = SECCPersonality.model_validate(
        {"power": {"evse_ac": {"nominal_voltage_v": 230.0, "max_current_a": 16.0}}}
    )
    assert p.power.evse_ac.nominal_voltage_v == 230.0
    assert p.power.evse_ac.max_current_a == 16.0


# ---------------------------------------------------------------------------
# SECC simulator: ISO-2 wire values come from personality
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_secc_ac_charge_params_retired_to_skeleton():
    # #96 retired the structured `power.evse_ac` ISO-2 SECC read: the AC envelope
    # is now tree-sourced at the ChargeParameterDiscoveryRes build site, so this
    # builder returns the AC-limit model-default *skeleton* regardless of the
    # personality's evse_ac (which no longer reaches the ISO-2 wire through here).
    from app.shared.personality.model import EVSEACLimits

    personality = SECCPersonality.model_validate(
        {"power": {"evse_ac": {"nominal_voltage_v": 230.0, "max_current_a": 16.0}}}
    )
    ctrl = SimEVSEController(personality=personality)
    params = await ctrl.get_ac_charge_params_v2()

    default = EVSEACLimits()
    assert params.evse_nominal_voltage.get_decimal_value() == default.nominal_voltage_v
    assert params.evse_max_current.get_decimal_value() == default.max_current_a


@pytest.mark.asyncio
async def test_secc_sa_schedule_iso2_retired_to_skeleton():
    # #96 retired the structured `iso2_sa_schedule_pmax_w` / `iso2_sales_tariff_id`
    # ISO-2 SECC reads: the SAScheduleList is a tree wire value overridden at the
    # build site (or falls back to the builder skeleton). This builder now uses
    # the DC-limit model defaults regardless of the personality's values.
    from app.shared.personality.model import EVSEDCLimits

    personality = SECCPersonality.model_validate(
        {
            "power": {
                "evse_dc": {
                    "iso2_sa_schedule_pmax_w": 50000,
                    "iso2_sales_tariff_id": 42,
                }
            }
        }
    )
    ctrl = SimEVSEController(personality=personality)
    schedules = await ctrl.get_sa_schedule_list(
        ev_data_context=None,
        is_free_charging_service=False,
        max_schedule_entries=None,
        departure_time=0,
    )
    assert schedules is not None
    [entry] = schedules
    default = EVSEDCLimits()
    pmax_values = [
        e.p_max.get_decimal_value() for e in entry.p_max_schedule.schedule_entries
    ]
    assert all(v == float(default.iso2_sa_schedule_pmax_w) for v in pmax_values)
    assert entry.sales_tariff.sales_tariff_id == default.iso2_sales_tariff_id


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
    from app.shared.personality.model import EVACLimits

    personality = EVCCPersonality.model_validate(
        {
            "capabilities": {"energy_transfer_mode": "AC_three_phase_core"},
            "power": {
                "ev_ac": {
                    "e_amount_wh": 5000.0,
                    "max_voltage_v": 230.0,
                    "max_current_a": 16.0,
                    "min_current_a": 6.0,
                }
            },
        }
    )
    evcc_config = EVCCConfig.from_personality(personality)
    sim = SimEVController(evcc_config)
    params = await sim.get_charge_params_v2(Protocol.ISO_15118_2)

    ac = params.ac_parameters
    assert ac is not None
    default = EVACLimits()
    assert ac.e_amount.get_decimal_value() == default.e_amount_wh
    assert ac.ev_max_voltage.get_decimal_value() == default.max_voltage_v
    assert ac.ev_max_current.get_decimal_value() == default.max_current_a
    assert ac.ev_min_current.get_decimal_value() == default.min_current_a


@pytest.mark.asyncio
async def test_evcc_iso2_dc_charge_params_retired_to_skeleton():
    # #97 retired the structured ISO-2 DC announcements: the DC envelope maxima
    # come from the EVDCLimits model-default skeleton (the tree overrides them at
    # the build site), and the Mach-E omits EVEnergyRequest / FullSOC / BulkSOC /
    # EVEnergyCapacity / DepartureTime, so this builder leaves them unset.
    from app.shared.personality.model import EVDCLimits

    personality = EVCCPersonality.model_validate(
        {
            "capabilities": {"energy_transfer_mode": "DC_extended"},
            "power": {
                "ev_dc": {
                    "iso2_energy_request_wh": 20000.0,
                    "iso2_full_soc_percent": 95,
                    "iso2_bulk_soc_percent": 75,
                }
            },
        }
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
    # The announced maxima come from the DC-limit model-default skeleton.
    default = EVDCLimits()
    assert dc.ev_maximum_power_limit.get_decimal_value() == default.max_power_w
    assert dc.ev_maximum_voltage_limit.get_decimal_value() == default.max_voltage_v
    assert dc.ev_maximum_current_limit.get_decimal_value() == default.max_current_a


@pytest.mark.asyncio
async def test_evcc_iso2_energy_transfer_mode_tracks_personality():
    personality = EVCCPersonality.model_validate(
        {"capabilities": {"energy_transfer_mode": "DC_extended"}}
    )
    evcc_config = EVCCConfig.from_personality(personality)
    sim = SimEVController(evcc_config)
    mode = await sim.get_energy_transfer_mode(Protocol.ISO_15118_2)
    assert mode == EnergyTransferModeEnum.DC_EXTENDED
