"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
    Copyright 2025, Ford Motor Company
    Copyright 2022, Switch

    This class is used to emulate a EVSE when talking to an PEV. Handles level 2 SLAC communications
    and level 3 UDP and TCP communications to the electric vehicle.
"""

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

        # Operator console (ADR-0004). Slice 1 wires the footer plumbing on
        # both roles; the SECC authorization-gate stall is a later slice, so
        # the footer's stall toggle is carried but not yet consumed here.
        self.live_control = LiveControl(
            console_enabled=resolve_console_enabled(runtime.console.mode),
            stall_charge_loop=runtime.stall.charge_loop,
        )

        self.destinationMAC = None
        self.destinationIP = None
        self.destinationPort = None
        self.slac = None

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
    async def start(self):
        if not self.virtual:
            # Initialize the smbus for I2C commands
            self.bus.write_byte_data(self.I2C_ADDR, 0x00, 0x00)
            self.toggleProximity()

        self.iface = self.config.iface
        self.slac = SLACHandler(self)

        logger.info(f"SECC MAC address: {self.sourceMAC}")

        self.doSLAC()

        sim_evse_controller = SimEVSEController(personality=self.personality)
        await sim_evse_controller.set_status(ServiceStatus.STARTING)
        session = SECCHandler(
            exi_codec=EXPyEXICodec(),
            evse_controller=sim_evse_controller,
            config=self.config,
        ).start(self.config.iface)

        if self.live_control.console_enabled:
            await run_with_console(self.live_control, session, source="SECC")
        else:
            await session

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
