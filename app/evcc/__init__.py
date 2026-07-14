"""
    Copyright 2025, Ford Motor Company
    Copyright 2022, Switch
"""

import logging
from typing import Optional

from app import __version__
from app.evcc.comm_session_handler import (
    DEFAULT_ONGOING_POLL_INTERVAL,
    CommunicationSessionHandler,
)
from app.evcc.controller.interface import EVControllerInterface
from app.evcc.evcc_config import EVCCConfig
from app.evcc.evcc_settings import Config
from app.shared.expy_exi_codec import EXPyEXICodec
from app.shared.live_control import LiveControl
from app.shared.logging import _init_logger

logger = logging.getLogger(__name__)

class EVCCHandler(CommunicationSessionHandler):
    def __init__(
        self,
        evcc_config: EVCCConfig,
        iface: str,
        exi_codec: EXPyEXICodec,
        ev_controller: EVControllerInterface,
        live_control: Optional[LiveControl] = None,
        ongoing_poll_interval: float = DEFAULT_ONGOING_POLL_INTERVAL,
    ):
        CommunicationSessionHandler.__init__(
            self,
            evcc_config,
            iface,
            exi_codec,
            ev_controller,
            live_control,
            ongoing_poll_interval,
        )

    async def start(self):
        try:
            logger.info(f"Starting 15118 version: {__version__}")
            await self.start_session_handler()
        except Exception as exc:
            logger.error(f"EVCC terminated: {exc}")
            # Re-raise so the controller's per-cycle lifecycle guard can log the
            # failure and return the EVCC to idle for re-arming (ADR-0005); the
            # process exits only on an operator quit, not on a session failure.
            raise
