"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
    Copyright 2025, Ford Motor Company
    Copyright 2022, Switch

    This class is used to emulate a EVSE when talking to an PEV. Handles level 2 SLAC communications
    and level 3 UDP and TCP communications to the electric vehicle.
"""

import asyncio
import logging

from app.secc import SECCHandler
from app.secc.controller.interface import ServiceStatus
from app.secc.controller.simulator import SimEVSEController
from app.secc.secc_settings import Config
from app.secc.transport.slac import SLACHandler
from app.shared.console import resolve_console_enabled, run_with_console
from app.shared.expy_exi_codec import EXPyEXICodec
from app.shared.live_control import LiveControl
from app.shared.logging import _init_logger
from app.shared.network import (
    get_link_local_addr,
    get_nic_mac_address,
    get_tcp_port,
)
from app.shared.personality import (
    SECCPersonality,
    apply_runtime_overrides,
    load_personality,
    load_runtime,
)

logger = logging.getLogger(__name__)


class EVSE:

    def __init__(self, args):
        personality = load_personality(args.config, role="secc")
        assert isinstance(personality, SECCPersonality)
        runtime = apply_runtime_overrides(load_runtime(args.runtime), args)
        _init_logger(
            source="SECC",
            console_level=runtime.log.console_level,
            file_level=runtime.log.file_level,
        )

        self.personality = personality
        self.runtime = runtime
        self.config = Config.from_personality(personality, runtime)

        self.iface = self.config.iface
        self.sourceMAC = get_nic_mac_address(self.iface)
        self.sourceIP = str(get_link_local_addr(self.iface))
        self.sourcePort = runtime.source_port if runtime.source_port else 25565

        # NID/NMK come from `personality.slac` per ADR-0001. The historical
        # `--NID` / `--NMK` CLI flags are gone (personality fields are not
        # CLI-overridable).
        self.NID = bytes.fromhex(personality.slac.nid_hex)
        self.NMK = bytes.fromhex(personality.slac.nmk_hex)
        self.modified_cordset = runtime.modified_cordset

        # Operator console (ADR-0004). The SECC owns the ISO-2 authorization
        # gate, so `stall_authorization` is the stall this role actually
        # consumes; `stall_charge_loop` is carried for the shared LiveControl
        # shape but never read on the SECC side.
        self.live_control = LiveControl(
            console_enabled=resolve_console_enabled(runtime.console.mode),
            stall_charge_loop=runtime.stall.charge_loop,
            stall_authorization=runtime.stall.authorization,
        )

        self.destinationMAC = None
        self.destinationIP = None
        self.destinationPort = None
        self.slac = None

        # Operator 'q' quit must stop the SLAC handler, whose blocking recv()
        # and timeout thread run in a thread pool that asyncio cancellation
        # can't reach (issue #40). Late-binds to the current `self.slac` so a
        # future re-armed cycle's handler is the one torn down.
        self.live_control.register_quit_hook(self._teardown_slac)

        self.virtual = self.config.virtual

        if not self.virtual:
            from smbus import SMBus

            # I2C bus for relays
            self.bus = SMBus(1)

            # Constants for i2c controlled relays
            self.I2C_ADDR = 0x20
            self.CONTROL_REG = 0x9
            self.EVSE_CP = 0b1
            self.EVSE_PP = 0b1000
            self.ALL_OFF = 0b0

    # Start the emulator
    def _teardown_slac(self) -> None:
        """Stop the in-flight SLAC handler on operator quit (issue #40)."""
        if self.slac is not None:
            self.slac.stop_handler()

    async def start(self):
        if not self.virtual:
            # Initialize the smbus for I2C commands
            self.bus.write_byte_data(self.I2C_ADDR, 0x00, 0x00)
            self.toggleProximity()

        self.iface = self.config.iface
        self.slac = SLACHandler(self)

        logger.info(f"SECC MAC address: {self.sourceMAC}")

        async def _run():
            # Phase indicator: console is already live when SLAC begins.
            self.live_control.phase = "Waiting for SLAC"
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self.doSLAC)
            self.live_control.phase = "Session active"
            sim_evse_controller = SimEVSEController(
                personality=self.personality, live_control=self.live_control
            )
            await sim_evse_controller.set_status(ServiceStatus.STARTING)
            session = SECCHandler(
                exi_codec=EXPyEXICodec(),
                evse_controller=sim_evse_controller,
                config=self.config,
            ).start(self.config.iface)
            await session

        if self.live_control.console_enabled:
            await run_with_console(self.live_control, _run(), source="SECC")
        else:
            await _run()

    def doSLAC(self):
        self.slac.start()
        logger.info("Done SLAC")

    def closeProximity(self):
        if self.modified_cordset:
            logger.info("Closing CP/PP relay connections")
            if not self.virtual:
                self.bus.write_byte_data(
                    self.I2C_ADDR, self.CONTROL_REG, self.EVSE_PP | self.EVSE_CP
                )
        else:
            logger.info("Closing CP relay connection")
            if not self.virtual:
                self.bus.write_byte_data(
                    self.I2C_ADDR, self.CONTROL_REG, self.EVSE_CP
                )

    def openProximity(self):
        logger.info("Opening CP/PP relay connections")
        if not self.virtual:
            self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.ALL_OFF)

    def toggleProximity(self, t: int = 5):
        import time

        self.openProximity()
        time.sleep(t)
        self.closeProximity()
