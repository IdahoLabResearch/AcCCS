"""
    Copyright 2025, Ford Motor Company
    Copyright 2022, Switch
"""

import logging
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator

from app.shared.messages.enums import (
    UINT_16_MAX,
    AuthEnum,
    EnergyTransferModeEnum,
    Protocol,
    ServiceV20,
)
from app.shared.personality.model import EVCCPersonality

logger = logging.getLogger(__name__)


class EVCCConfig(BaseModel):
    """Per-session EVCC capabilities and posture.

    Slice 1 of ADR-0001: this model is now built from an `EVCCPersonality`
    via `EVCCConfig.from_personality()`. The on-disk JSON config files
    under `app/shared/examples/evcc/` are gone (deleted in the hard cutover).
    The field surface is unchanged so the rest of the codebase doesn't move.
    """

    # The order in which the protocols are listed here determines the
    # priority (i.e. first list entry has higher priority than second
    # list entry).
    raw_supported_protocols: Optional[List[str]] = None
    supported_protocols: Optional[List[Protocol]] = None

    raw_supported_energy_services: Optional[List[str]] = None
    supported_energy_services: Optional[List[ServiceV20]] = None

    raw_supported_auth_modes: Optional[List[str]] = None
    supported_auth_modes: Optional[List[AuthEnum]] = None

    energy_transfer_mode: Optional[EnergyTransferModeEnum] = None

    is_cert_install_needed: bool = False
    use_tls: Optional[bool] = True
    sdp_retry_cycles: Optional[int] = 1
    # ISO 15118-20 only.
    max_contract_certs: Optional[int] = 3
    enforce_tls: bool = False
    max_supporting_points: Optional[int] = 1024

    charge_loop_cycle: Optional[int] = 10
    charge_loop_delay_time: Optional[int] = 0

    # Identity surfaced for protocol layers that need it at session-build
    # time (ISO 15118-20 EVCCID). Populated from `personality.identity`.
    evcc_id: Optional[str] = None

    # DC charge envelope advertised in DIN ChargeParameterDiscoveryReq /
    # CurrentDemandReq. Sourced from `personality.power.ev_dc`. See
    # ADR-0001 / issue #7 (DIN personality slice).
    ev_dc_max_voltage_v: float = 500.0
    ev_dc_max_current_a: float = 32.0
    ev_dc_max_power_w: float = 80000.0
    ev_dc_energy_capacity_wh: float = 70000.0
    ev_dc_target_voltage_v: float = 500.0
    ev_dc_target_current_a: float = 1.0
    ev_dc_remaining_time_to_full_soc_s: int = 100
    ev_dc_remaining_time_to_bulk_soc_s: int = 80
    # ISO 15118-2 DCEVChargeParameter (no DIN equivalent on the wire).
    # See issue #8 (ISO-2 personality slice).
    ev_dc_iso2_energy_request_wh: float = 6000.0
    ev_dc_iso2_full_soc_percent: int = 90
    ev_dc_iso2_bulk_soc_percent: int = 80

    # AC charge envelope advertised in ISO 15118-2 ACEVChargeParameter.
    # Sourced from `personality.power.ev_ac`.
    ev_ac_e_amount_wh: float = 60.0
    ev_ac_max_voltage_v: float = 400.0
    ev_ac_max_current_a: float = 32.0
    ev_ac_min_current_a: float = 10.0

    @classmethod
    def from_personality(cls, personality: EVCCPersonality) -> "EVCCConfig":
        caps = personality.capabilities
        tls = personality.tls
        certs = personality.certificates
        cp = personality.charge_profile
        ev_dc = personality.power.ev_dc
        ev_ac = personality.power.ev_ac

        ev_config = cls(
            raw_supported_protocols=list(caps.supported_protocols),
            supported_protocols=caps.resolved_protocols(),
            raw_supported_energy_services=list(caps.supported_energy_services),
            supported_energy_services=caps.resolved_energy_services(),
            raw_supported_auth_modes=list(caps.supported_auth_modes),
            supported_auth_modes=caps.resolved_auth_modes(),
            energy_transfer_mode=caps.resolved_energy_transfer_mode(),
            is_cert_install_needed=caps.is_cert_install_needed,
            use_tls=tls.use_tls,
            sdp_retry_cycles=tls.sdp_retry_cycles,
            enforce_tls=tls.enforce_tls,
            max_contract_certs=certs.max_contract_certs,
            max_supporting_points=caps.max_supporting_points,
            charge_loop_cycle=cp.cycle,
            charge_loop_delay_time=cp.delay_seconds,
            evcc_id=personality.identity.evcc_id,
            ev_dc_max_voltage_v=ev_dc.max_voltage_v,
            ev_dc_max_current_a=ev_dc.max_current_a,
            ev_dc_max_power_w=ev_dc.max_power_w,
            ev_dc_energy_capacity_wh=ev_dc.energy_capacity_wh,
            ev_dc_target_voltage_v=ev_dc.target_voltage_v,
            ev_dc_target_current_a=ev_dc.target_current_a,
            ev_dc_remaining_time_to_full_soc_s=ev_dc.remaining_time_to_full_soc_s,
            ev_dc_remaining_time_to_bulk_soc_s=ev_dc.remaining_time_to_bulk_soc_s,
            ev_dc_iso2_energy_request_wh=ev_dc.iso2_energy_request_wh,
            ev_dc_iso2_full_soc_percent=ev_dc.iso2_full_soc_percent,
            ev_dc_iso2_bulk_soc_percent=ev_dc.iso2_bulk_soc_percent,
            ev_ac_e_amount_wh=ev_ac.e_amount_wh,
            ev_ac_max_voltage_v=ev_ac.max_voltage_v,
            ev_ac_max_current_a=ev_ac.max_current_a,
            ev_ac_min_current_a=ev_ac.min_current_a,
        )

        logger.info("EVCC Settings (from personality):")
        for key, value in ev_config.model_dump().items():
            if key in (
                "supported_energy_services",
                "supported_protocols",
                "supported_auth_modes",
            ) and value:
                logger.info(f"{key:30}: {[item.name for item in value]}")
            elif key == "energy_transfer_mode" and value is not None:
                logger.info(f"{key:30}: {value.name}")
            elif not key.startswith("raw"):
                logger.info(f"{key:30}: {value}")

        return ev_config

    @field_validator("max_supporting_points", mode="before")
    @classmethod
    def check_max_supporting_points(cls, value):
        if value is None:
            return value
        if not 0 <= value <= 1024:
            raise ValueError(
                "Wrong range for max_supporting_points. Should be in [0..1024]"
            )
        return value

    @field_validator("sdp_retry_cycles", mode="before")
    @classmethod
    def check_sdp_retry_cycle(cls, value):
        if value is None:
            return value
        if value < 0:
            raise ValueError("Wrong range for sdp_retry_cycles. Should be in [0..]")
        return value

    @field_validator("max_contract_certs", mode="before")
    @classmethod
    def check_max_contract_certs(cls, value):
        if value is None:
            return value
        if not 1 < value < UINT_16_MAX:
            raise ValueError(
                "Wrong range for max_contract_certs. Should be in [1..UINT_16_MAX]"
            )
        return value
