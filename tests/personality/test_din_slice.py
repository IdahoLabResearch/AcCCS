"""DIN 70121 personality fields (issue #7, slice 2).

Tests the contract that every personality-shaped field used during a DIN
session is sourced from the personality config — see issue #7's "What to
build" / "Acceptance criteria".

The controller-level tests assert the simulators honour personality
values when building DIN wire messages.
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
# SECC simulator: DIN wire values come from personality
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_secc_dc_charge_parameters_din_retire_evse_dc():
    """Issue #73 / ADR-0006: the DIN SECC DC envelope is no longer sourced from
    the structured `power.evse_dc` block — it comes from the message field tree
    at the ChargeParameterDiscoveryRes build site. The controller helper builds
    only a skeleton from the DC-limit model defaults, so the retirement holds
    regardless of the personality."""
    personality = SECCPersonality.model_validate({})
    ctrl = SimEVSEController(personality=personality)
    params = await ctrl.get_dc_charge_parameters_dinspec()

    # Retired EVSEDCLimits skeleton defaults, not any personality value.
    assert params.evse_maximum_voltage_limit.get_decimal_value() == 500.0
    assert params.evse_maximum_current_limit.get_decimal_value() == 400.0
    assert params.evse_maximum_power_limit.get_decimal_value() == 80000.0


@pytest.mark.asyncio
async def test_secc_dc_charge_parameters_din_tree_sourced():
    """The DIN CPD DC envelope is sourced from the message field tree. Setting
    the tree leaves surfaces them on the built ChargeParameterDiscoveryRes via
    construction-time substitution (apply_personality_tree at the build site)."""
    from app.secc.states.din_spec_states import apply_personality_tree
    from app.shared.messages.din_spec.body import (
        ChargeParameterDiscoveryRes,
        ResponseCode,
    )
    from app.shared.messages.enums import EVSEProcessing

    personality = SECCPersonality.model_validate(
        {
            "message_field_tree": {
                "DIN_SPEC_70121": {
                    "ChargeParameterDiscoveryRes": {
                        "DC_EVSEChargeParameter": {
                            "EVSEMaximumVoltageLimit": {
                                "Value": 451,
                                "Multiplier": 0,
                                "Unit": "V",
                            },
                            "EVSEMaximumCurrentLimit": {
                                "Value": 60,
                                "Multiplier": 0,
                                "Unit": "A",
                            },
                        }
                    }
                }
            }
        }
    )
    ctrl = SimEVSEController(personality=personality)
    dc_params = await ctrl.get_dc_charge_parameters_dinspec()
    res = ChargeParameterDiscoveryRes(
        response_code=ResponseCode.OK,
        evse_processing=EVSEProcessing.FINISHED,
        dc_charge_parameter=dc_params,
    )

    class _Session:
        evse_controller = ctrl

    apply_personality_tree(_Session(), res, "ChargeParameterDiscoveryRes")

    assert res.dc_charge_parameter.evse_maximum_voltage_limit.get_decimal_value() == 451
    assert res.dc_charge_parameter.evse_maximum_current_limit.get_decimal_value() == 60


@pytest.mark.asyncio
async def test_secc_max_power_limit_din_retire_evse_dc():
    """The DIN CurrentDemandRes max-power limit no longer reads `evse_dc`
    (#73); the helper returns the model default and the wire value is
    tree-sourced at the build site."""
    personality = SECCPersonality.model_validate({})
    ctrl = SimEVSEController(personality=personality)
    pmax = await ctrl.get_evse_max_power_limit(protocol=Protocol.DIN_SPEC_70121)
    # Retired EVSEDCLimits skeleton default (max_power_w=80000).
    assert pmax.get_decimal_value() == 80000.0


def test_secc_default_din_sa_schedule_list_is_constant():
    """The DIN SAScheduleList is list-nested and sourced from the message field
    tree (#81). The retired `get_sa_schedule_list_dinspec` controller scaffold
    (#86) is replaced by the SECC state's `_default_din_sa_schedule_list`
    pre-tree builder default: a fixed 1-tuple / 1-entry schedule (PMax 200)
    that a personality's `ChargeParameterDiscoveryRes -> SAScheduleList` tree
    overrides wholesale at the build site (ADR-0006 #83). It is a constant, not
    derived from any personality field."""
    from app.secc.states.din_spec_states import _default_din_sa_schedule_list

    schedule_list = _default_din_sa_schedule_list()
    [entry] = schedule_list.values
    assert entry.sa_schedule_tuple_id == 1
    assert entry.p_max_schedule.p_max_schedule_id == 0
    [details] = entry.p_max_schedule.entry_details
    # Pre-tree builder default (PMax 200), not derived from a personality.
    assert details.p_max == 200
    assert details.time_interval.start == 0


@pytest.mark.asyncio
async def test_secc_supported_energy_modes_din_track_personality():
    # The DIN energy transfer mode is tree-sourced (#105): the SECC advertises —
    # and the reject-gate accepts — the ServiceDiscoveryRes -> ChargeService ->
    # EnergyTransferType leaf. Pinning DC_core here (the builder fallback is
    # DC_extended) proves the value comes from the tree.
    personality = SECCPersonality.model_validate(
        {
            "capabilities": {"supported_protocols": ["DIN_SPEC_70121"]},
            "message_field_tree": {
                "DIN_SPEC_70121": {
                    "ServiceDiscoveryRes": {
                        "PaymentOptions": {"PaymentOption": ["ExternalPayment"]},
                        "ChargeService": {
                            "ServiceTag": {
                                "ServiceID": 1,
                                "ServiceCategory": "EVCharging",
                            },
                            "FreeService": False,
                            "EnergyTransferType": "DC_core",
                        },
                    }
                }
            },
        }
    )
    ctrl = SimEVSEController(personality=personality)
    modes = await ctrl.get_supported_energy_transfer_modes(Protocol.DIN_SPEC_70121)
    assert modes == [EnergyTransferModeEnum.DC_CORE]


@pytest.mark.asyncio
async def test_secc_supported_energy_modes_din_default_fallback():
    # An empty-tree personality falls back to DC_extended (the retired
    # `capabilities.energy_transfer_mode` seam is gone, #105).
    personality = SECCPersonality.model_validate(
        {"capabilities": {"supported_protocols": ["DIN_SPEC_70121"]}}
    )
    ctrl = SimEVSEController(personality=personality)
    modes = await ctrl.get_supported_energy_transfer_modes(Protocol.DIN_SPEC_70121)
    assert modes == [EnergyTransferModeEnum.DC_EXTENDED]


def test_secc_rejects_mistyped_energy_transfer_type_leaf():
    """Issue #76: the DIN ServiceDiscoveryRes -> ChargeService ->
    EnergyTransferType leaf encodes as a restricted EXI enumeration, so the codec
    accepts *only* the EnergyTransferModeEnum wire values. A value that is not one
    of them — e.g. the enum *name* ``DC_EXTENDED`` instead of the wire *value*
    ``DC_extended`` — can never reach the wire (value-raw is vacuous for an
    enum-restricted field). It must fail at load with a message that names the
    fix, not detonate later as an opaque ValidationError / EXIEncodingError at
    ServiceDiscovery."""
    with pytest.raises(ValidationError, match="DC_extended"):
        SECCPersonality.model_validate(
            {
                "message_field_tree": {
                    "DIN_SPEC_70121": {
                        "ServiceDiscoveryRes": {
                            "PaymentOptions": {"PaymentOption": ["ExternalPayment"]},
                            "ChargeService": {
                                "ServiceTag": {
                                    "ServiceID": 1,
                                    "ServiceCategory": "EVCharging",
                                },
                                "FreeService": False,
                                # The field under test: an enum *name* rather than
                                # its wire *value* — the rest of the message is
                                # complete so only the #76 gate can reject.
                                "EnergyTransferType": "DC_EXTENDED",
                            },
                        }
                    }
                }
            }
        )


def test_secc_accepts_valid_energy_transfer_type_leaf():
    """The #76 load-time check must not over-reject: a real wire value on the
    same leaf loads cleanly."""
    personality = SECCPersonality.model_validate(
        {
            "message_field_tree": {
                "DIN_SPEC_70121": {
                    "ServiceDiscoveryRes": {
                        "PaymentOptions": {"PaymentOption": ["ExternalPayment"]},
                        "ChargeService": {
                            "ServiceTag": {
                                "ServiceID": 1,
                                "ServiceCategory": "EVCharging",
                            },
                            "FreeService": False,
                            "EnergyTransferType": "DC_extended",
                        },
                    }
                }
            }
        }
    )
    charge_service = personality.message_field_tree["DIN_SPEC_70121"][
        "ServiceDiscoveryRes"
    ]["ChargeService"]
    assert charge_service["EnergyTransferType"] == "DC_extended"


# ---------------------------------------------------------------------------
# EVCC simulator: DIN wire values come from personality
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evcc_dc_charge_params_din_retire_ev_dc_maxima():
    """Issue #74 / ADR-0006: the DIN EVCC announced maxima + capacity are no
    longer sourced from the structured `power.ev_dc` block — they come from the
    message field tree at each `*Req` build site. The controller builds only a
    skeleton from the EV DC-limit model defaults, so a `power.ev_dc` set to
    distinctive maxima does NOT surface here (the retirement). The `target_*`
    fields are the issue's carve-out and DO still come from config, because they
    ramp and are not static baseline tree values."""
    personality = EVCCPersonality.model_validate(
        {"residual": {"charge_ramp": {"target_voltage_v": 750.0, "target_current_a": 17.0}}}
    )
    evcc_config = EVCCConfig.from_personality(personality)
    sim = SimEVController(evcc_config)
    params = await sim.get_dc_charge_params(Protocol.DIN_SPEC_70121)

    # Retired EVDCLimits skeleton defaults for the announced maxima.
    assert params.dc_max_voltage_limit.get_decimal_value() == 500.0
    assert params.dc_max_current_limit.get_decimal_value() == 32.0
    assert params.dc_max_power_limit.get_decimal_value() == 80000.0
    assert params.dc_energy_capacity.get_decimal_value() == 70000.0
    # Targets stay config-sourced (computed/start-value carve-out).
    assert params.dc_target_voltage.get_decimal_value() == 750.0
    assert params.dc_target_current.get_decimal_value() == 17.0


@pytest.mark.asyncio
async def test_evcc_dc_charge_params_iso2_retire_ev_dc_maxima():
    """Issue #97 / ADR-0006: the ISO-2 EVCC announced maxima + capacity are now
    retired too (the #74 DIN retirement extended to ISO-2) — they come from the
    message field tree at each `*Req` build site, so the controller builds only a
    skeleton from the EV DC-limit model defaults. A `power.ev_dc` set to
    distinctive maxima does NOT surface here. The `target_*` carve-out DOES still
    come from config (it ramps, and is not a static baseline tree value)."""
    personality = EVCCPersonality.model_validate(
        {"residual": {"charge_ramp": {"target_voltage_v": 750.0, "target_current_a": 17.0}}}
    )
    evcc_config = EVCCConfig.from_personality(personality)
    sim = SimEVController(evcc_config)
    params = await sim.get_dc_charge_params(Protocol.ISO_15118_2)

    # Retired EVDCLimits skeleton defaults for the announced maxima.
    assert params.dc_max_voltage_limit.get_decimal_value() == 500.0
    assert params.dc_max_current_limit.get_decimal_value() == 32.0
    assert params.dc_max_power_limit.get_decimal_value() == 80000.0
    assert params.dc_energy_capacity.get_decimal_value() == 70000.0
    # Targets stay config-sourced (computed/start-value carve-out).
    assert params.dc_target_voltage.get_decimal_value() == 750.0
    assert params.dc_target_current.get_decimal_value() == 17.0


@pytest.mark.asyncio
async def test_evcc_din_current_demand_req_tree_sourced():
    """The DIN EVCC wire values are sourced from the message field tree. Setting
    the CurrentDemandReq leaves surfaces them on the built message via
    construction-time substitution (apply_personality_tree at the build site)."""
    from app.evcc.states.din_spec_states import apply_personality_tree
    from app.shared.messages.din_spec.body import CurrentDemandReq
    from app.shared.messages.datatypes import (
        PVEVMaxCurrentLimitDin,
        PVEVMaxVoltageLimitDin,
        PVEVTargetCurrentDin,
        PVEVTargetVoltageDin,
    )
    from app.shared.messages.enums import DCEVErrorCode, UnitSymbol
    from app.shared.messages.din_spec.datatypes import DCEVStatus

    personality = EVCCPersonality.model_validate(
        {
            "message_field_tree": {
                "DIN_SPEC_70121": {
                    "CurrentDemandReq": {
                        "EVMaximumCurrentLimit": {"Value": 500, "Multiplier": 0},
                        "EVMaximumVoltageLimit": {"Value": 410, "Multiplier": 0},
                        "BulkChargingComplete": True,
                        "DC_EVStatus": {"EVRESSSOC": 88},
                    }
                }
            }
        }
    )
    config = EVCCConfig.from_personality(personality)

    class _Session:
        pass

    session = _Session()
    session.config = config

    req = CurrentDemandReq(
        dc_ev_status=DCEVStatus(
            ev_ready=True, ev_error_code=DCEVErrorCode.NO_ERROR, ev_ress_soc=10
        ),
        ev_target_current=PVEVTargetCurrentDin(multiplier=0, value=1, unit=UnitSymbol.AMPERE),
        ev_target_voltage=PVEVTargetVoltageDin(multiplier=0, value=400, unit=UnitSymbol.VOLTAGE),
        ev_max_current_limit=PVEVMaxCurrentLimitDin(multiplier=0, value=32, unit=UnitSymbol.AMPERE),
        ev_max_voltage_limit=PVEVMaxVoltageLimitDin(multiplier=0, value=500, unit=UnitSymbol.VOLTAGE),
        charging_complete=False,
    )
    apply_personality_tree(session, req)

    assert req.ev_max_current_limit.get_decimal_value() == 500
    assert req.ev_max_voltage_limit.get_decimal_value() == 410
    assert req.bulk_charging_complete is True
    assert req.dc_ev_status.ev_ress_soc == 88
