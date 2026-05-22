"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
    Copyright 2025, Ford Motor Company
    Copyright 2022, Switch

    This class is used to emulate a PEV when talking to an EVSE. Handles level 2 SLAC communications
    and level 3 UDP and TCP communications to the charging station.
"""

import logging
import time

from app.evcc import Config, EVCCHandler
from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.evcc.transport.slac import SLACHandler
from app.shared.EmulatorEnum import PEVState
from app.shared.exificient_exi_codec import ExificientEXICodec
from app.shared.logging import _init_logger
from app.shared.network import (
    get_link_local_addr,
    get_nic_mac_address,
    get_tcp_port,
)
from app.shared.personality import (
    EVCCPersonality,
    Runtime,
    apply_runtime_overrides,
    load_personality,
    load_runtime,
)

logger = logging.getLogger(__name__)


class PEV:

    def __init__(self, args):
        # Load personality + runtime first so the logger can pick up the
        # operator's chosen levels before we emit anything.
        personality = load_personality(args.config, role="evcc")
        assert isinstance(personality, EVCCPersonality)
        runtime = apply_runtime_overrides(load_runtime(args.runtime), args)
        _init_logger(
            source="EVCC",
            console_level=runtime.log.console_level,
            file_level=runtime.log.file_level,
        )

        self.personality = personality
        self.runtime = runtime
        self.config = Config.from_personality(personality, runtime)
        self.evcc_config = EVCCConfig.from_personality(personality)

        self.iface = self.config.iface
        self.sourceMAC = get_nic_mac_address(self.iface)
        self.sourceIP = str(get_link_local_addr(self.iface))
        self.sourcePort = runtime.source_port if runtime.source_port else get_tcp_port()
        self.slacSoundTimeout = personality.slac.sound_timeout_ms

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
            self.PEV_CP1 = 0b10
            self.PEV_CP2 = 0b100
            self.PEV_PP = 0b10000
            self.ALL_OFF = 0b0

    async def start(self):
        if not self.virtual:
            # Initialize the smbus for I2C commands
            self.bus.write_byte_data(self.I2C_ADDR, 0x00, 0x00)
            self.toggleProximity()

        self.slac = SLACHandler(self)

        logger.info(f"EVCC MAC address: {self.sourceMAC}")

        self.doSLAC()

        await EVCCHandler(
            evcc_config=self.evcc_config,
            iface=self.config.iface,
            exi_codec=ExificientEXICodec(),
            ev_controller=SimEVController(self.evcc_config),
        ).start()

    def doSLAC(self):
        logger.info("Starting SLAC")
        self.slac.start()
        logger.info("Done SLAC")

    def closeProximity(self):
        self.setState(PEVState.B)

    def openProximity(self):
        self.setState(PEVState.A)

    def setState(self, state: PEVState):
        if state == PEVState.A:
            logger.info("Going to state A")
            if self.virtual:
                return
            else:
                self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.ALL_OFF)
        elif state == PEVState.B:
            logger.info("Going to state B")
            if self.virtual:
                return
            else:
                self.bus.write_byte_data(
                    self.I2C_ADDR, self.CONTROL_REG, self.PEV_PP | self.PEV_CP1
                )
        elif state == PEVState.C:
            logger.info("Going to state C")
            if self.virtual:
                return
            else:
                self.bus.write_byte_data(
                    self.I2C_ADDR,
                    self.CONTROL_REG,
                    self.PEV_PP | self.PEV_CP1 | self.PEV_CP2,
                )

    def toggleProximity(self, t: int = 5):
        self.openProximity()
        time.sleep(t)
        self.closeProximity()
