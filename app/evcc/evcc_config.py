"""
    Copyright 2025, Ford Motor Company
    Copyright 2022, Switch
"""

import logging
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from app.shared.messages.enums import (
    UINT_16_MAX,
    AuthEnum,
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
    supported_protocols: Optional[List[Protocol]] = None
    supported_energy_services: Optional[List[ServiceV20]] = None
    supported_auth_modes: Optional[List[AuthEnum]] = None

    is_cert_install_needed: bool = False
    use_tls: Optional[bool] = True
    sdp_retry_cycles: Optional[int] = 1
    # ISO 15118-20 only.
    max_contract_certs: Optional[int] = 3
    enforce_tls: bool = False
    max_supporting_points: Optional[int] = 1024

    charge_loop_cycle: Optional[int] = 10
    charge_loop_delay_time: Optional[int] = 0

    # EV DC charge-ramp start seeds (ADR-0006 residual, relocated from the
    # retired `power.ev_dc` block in #102): the initial PreCharge / CurrentDemand
    # target voltage & current the EV requests before the runtime charge
    # controller (or a live-override) takes over the ramp, plus the EV-supplied
    # remaining-time estimates. Sourced from `personality.residual.charge_ramp`.
    # The announced DC/AC maxima and ISO-20 envelopes are no longer carried here
    # — they are wire-owned by the message field tree at each `*Req` build site
    # (#74/#97/#99/#101), so the simulator sources those from the message-model
    # skeletons the tree overrides, not from this config.
    ev_dc_target_voltage_v: float = 500.0
    ev_dc_target_current_a: float = 1.0
    ev_dc_remaining_time_to_full_soc_s: int = 100
    ev_dc_remaining_time_to_bulk_soc_s: int = 80

    # The [[message field tree]] (ADR-0006): per-message, per-field emitted wire
    # values, carried through from the personality so the EVCC DIN states can
    # apply construction-time substitution onto each outbound `*Req` (#74, the
    # vehicle-side mirror of the SECC's controller-held tree). Empty by default,
    # so a leaf set nowhere falls back to whatever the message builder computes.
    message_field_tree: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"arbitrary_types_allowed": True}

    @classmethod
    def from_personality(cls, personality: EVCCPersonality) -> "EVCCConfig":
        caps = personality.capabilities
        tls = personality.residual.tls
        certs = personality.residual.certificates
        cp = personality.residual.charge_profile
        ramp = personality.residual.charge_ramp

        ev_config = cls(
            supported_protocols=caps.resolved_protocols(),
            supported_energy_services=caps.resolved_energy_services(),
            supported_auth_modes=caps.resolved_auth_modes(),
            is_cert_install_needed=caps.is_cert_install_needed,
            use_tls=tls.use_tls,
            sdp_retry_cycles=tls.sdp_retry_cycles,
            enforce_tls=tls.enforce_tls,
            max_contract_certs=certs.max_contract_certs,
            max_supporting_points=caps.max_supporting_points,
            charge_loop_cycle=cp.cycle,
            charge_loop_delay_time=cp.delay_seconds,
            ev_dc_target_voltage_v=ramp.target_voltage_v,
            ev_dc_target_current_a=ramp.target_current_a,
            ev_dc_remaining_time_to_full_soc_s=ramp.remaining_time_to_full_soc_s,
            ev_dc_remaining_time_to_bulk_soc_s=ramp.remaining_time_to_bulk_soc_s,
            message_field_tree=personality.message_field_tree,
        )

        logger.info("EVCC Settings (from personality):")
        for key, value in ev_config.model_dump().items():
            if key in (
                "supported_energy_services",
                "supported_protocols",
                "supported_auth_modes",
            ) and value:
                logger.info(f"{key:30}: {[item.name for item in value]}")
            elif key == "message_field_tree":
                # The tree can be a large nested dict (the full DIN baseline);
                # log only its message keys, not every leaf, to keep the
                # startup summary readable.
                logger.info(f"{key:30}: {sorted(value)}")
            else:
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
