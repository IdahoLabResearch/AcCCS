"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

    This class is used to emulate a PEV when talking to an EVSE. Handles level 2 SLAC communications
    and level 3 UDP and TCP communications to the charging station.
"""

# need to do this to import the custom SECC and V2G scapy layer
import time
import json
import logging

from smbus import SMBus

from app.shared.EmulatorEnum import RunMode, PEVState

from app.evcc.transport.slac import SLACHandler

from app.evcc import Config, EVCCHandler
from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import load_from_file
from app.shared.exificient_exi_codec import ExificientEXICodec
from app.shared.network import (
    get_link_local_addr,
    get_nic_mac_address,
    get_tcp_port
)
from app.shared.logging import _init_logger

_init_logger(source="EVCC")
logger = logging.getLogger(__name__)

class PEV:

    def __init__(self, args):
        self.config = Config()
        self.config.load_envs()
        
        self.iface = self.config.iface
        self.sourceMAC = get_nic_mac_address(self.iface)
        self.sourceIP = str(get_link_local_addr(self.iface))
        self.sourcePort = args.source_port[0] if args.source_port else get_tcp_port()
        self.protocols = args.protocols.split(",") if args.protocols else ["ISO_15118_2", "DIN_SPEC_70121"]
        self.authModes = args.authmodes.split(",") if args.authmodes else ["PNC", "EIM"]
        self.energyMode = args.energymode if args.energymode else "DC"
        self.useTLS = args.useTLS if args.useTLS else "True"
        self.slacSoundTimeout = args.slacSoundTimeout if args.slacSoundTimeout else 1000

        self.destinationMAC = None
        self.destinationIP = None
        self.destinationPort = None
        self.slac = None
        
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
        # Initialize the smbus for I2C commands
        self.bus.write_byte_data(self.I2C_ADDR, 0x00, 0x00)
        self.toggleProximity()
        
        evcc_config = {
            "supportedProtocols": self.protocols,
            "supportedAuthModes": self.authModes,
            "supportedEnergyServices": [self.energyMode],
            "useTls": self.useTLS,
        }
        self.config.ev_config_file_path = "app/shared/examples/evcc/evcc_settings.json"
        with open(self.config.ev_config_file_path, "w") as f:
            json.dump(evcc_config, f, indent=4)
        
        evcc_config = await load_from_file(self.config.ev_config_file_path)
        self.slac = SLACHandler(self)
        
        self.doSLAC()
        
        await EVCCHandler(
            evcc_config=evcc_config,
            iface=self.config.iface,
            exi_codec=ExificientEXICodec(),
            ev_controller=SimEVController(evcc_config),
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
            self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.ALL_OFF)
        elif state == PEVState.B:
            logger.info("Going to state B")
            self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.PEV_PP | self.PEV_CP1)
        elif state == PEVState.C:
            logger.info("Going to state C")
            self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.PEV_PP | self.PEV_CP1 | self.PEV_CP2)

    def toggleProximity(self, t: int = 5):
        self.openProximity()
        time.sleep(t)
        self.closeProximity()
