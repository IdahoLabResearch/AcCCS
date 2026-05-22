"""
    Copyright 2025, Ford Motor Company
    Copyright 2022, Switch
"""

import logging
from dataclasses import dataclass
from typing import Optional

from app.shared.network import validate_nic
from app.shared.personality.model import EVCCPersonality, Runtime
from app.shared.settings import init_shared_settings, shared_settings

logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Per-process configuration for the EVCC.

    Slice 1 of ADR-0001: this dataclass is now built from a personality +
    runtime pair, not from a `.env` file. The field surface is unchanged so
    downstream consumers (PEV controller, EVCCHandler) don't move.
    """

    iface: Optional[str] = None
    console_log_level: Optional[str] = None
    file_log_level: Optional[str] = None
    virtual: bool = False

    @classmethod
    def from_personality(
        cls, personality: EVCCPersonality, runtime: Runtime
    ) -> "Config":
        validate_nic(personality.network.interface)
        init_shared_settings(personality, runtime)

        cfg = cls(
            iface=personality.network.interface,
            console_log_level=runtime.log.console_level,
            file_log_level=runtime.log.file_level,
            virtual=runtime.virtual,
        )

        logger.info("EVCC environment settings:")
        for key, value in shared_settings.items():
            logger.info(f"{key:30}: {value}")
        return cfg


RESUME_SELECTED_AUTH_OPTION = None
RESUME_SESSION_ID = None
RESUME_REQUESTED_ENERGY_MODE = None
