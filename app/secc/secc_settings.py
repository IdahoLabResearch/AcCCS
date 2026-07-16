"""
    Copyright 2025, Ford Motor Company
    Copyright 2022, Switch
"""

import logging
from dataclasses import dataclass, field
from typing import List, Optional, Type

from app.secc.controller.interface import EVSEControllerInterface
from app.shared.messages.enums import AuthEnum, Namespace, Protocol
from app.shared.personality.model import Runtime, SECCPersonality
from app.shared.settings import init_shared_settings, shared_settings

logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Per-process configuration for the SECC.

    Slice 1 of ADR-0001: this dataclass is now built from a personality +
    runtime pair, not from a `.env` file. Field surface preserved so the
    EVSE controller and SECCHandler keep working unchanged.
    """

    iface: Optional[str] = None
    console_log_level: Optional[str] = None
    file_log_level: Optional[str] = None
    evse_controller: Type[EVSEControllerInterface] = None
    enforce_tls: bool = False
    free_charging_service: bool = False
    free_cert_install_service: bool = True
    allow_cert_install_service: bool = True
    use_cpo_backend: bool = False
    supported_protocols: Optional[List[Protocol]] = None
    supported_auth_options: Optional[List[AuthEnum]] = None
    standby_allowed: bool = False
    virtual: bool = False
    env_dump: Optional[dict] = field(default_factory=dict)

    @classmethod
    def from_personality(
        cls, personality: SECCPersonality, runtime: Runtime
    ) -> "Config":
        init_shared_settings(personality, runtime)
        caps = personality.capabilities
        tls = personality.residual.tls

        cfg = cls(
            iface=personality.residual.network.interface,
            console_log_level=runtime.log.console_level,
            file_log_level=runtime.log.file_level,
            enforce_tls=tls.enforce_tls,
            free_charging_service=caps.free_charging_service,
            free_cert_install_service=caps.free_cert_install_service,
            allow_cert_install_service=caps.allow_cert_install_service,
            use_cpo_backend=personality.residual.behavior.use_cpo_backend,
            supported_protocols=caps.resolved_protocols(),
            supported_auth_options=caps.resolved_auth_modes(),
            standby_allowed=caps.standby_allowed,
            virtual=runtime.virtual,
        )

        # ADR-0001's hard rule that ISO 15118-20 requires TLS 1.3 stays
        # enforced: refuse to start if a -20 protocol is configured but
        # TLS 1.3 is off.
        if not personality.residual.tls.enable_tls_1_3:
            for protocol in cfg.supported_protocols or []:
                if protocol.ns.startswith(Namespace.ISO_V20_BASE):
                    raise Exception(
                        "ISO 15118-20 does not allow TLS version lower than "
                        "1.3. Either set residual.tls.enable_tls_1_3 to true "
                        "in the personality or remove ISO 15118-20 protocols "
                        "from capabilities.supported_protocols."
                    )

        cfg.env_dump = dict(shared_settings)
        cfg.print_settings()
        return cfg

    def print_settings(self):
        logger.info("SECC settings:")
        for key, value in self.env_dump.items():
            logger.info(f"{key:30}: {value}")
