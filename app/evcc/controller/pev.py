"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

    This class is used to emulate a PEV when talking to an EVSE. Handles level 2 SLAC communications
    and level 3 UDP and TCP communications to the charging station.
"""

# need to do this to import the custom SECC and V2G scapy layer
import random, time
import logging

from smbus import SMBus

from app.shared.EmulatorEnum import RunMode, PEVState

from app.evcc.transport.slac import SLACHandler

from app.evcc import Config, EVCCHandler
from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import load_from_file
from app.shared.exificient_exi_codec import ExificientEXICodec
from app.shared.logging import _init_logger

_init_logger(source="EVCC")
logger = logging.getLogger(__name__)

class PEV:

    def __init__(self, args):
        self.mode = RunMode(args.mode[0]) if args.mode else RunMode.FULL
        self.sourceMAC = args.source_mac[0] if args.source_mac else "20:7b:d2:a6:8b:36"
        self.sourceIP = args.source_ip[0] if args.source_ip else "fe80::8280:f77f:d5be:8fbe"
        self.sourcePort = args.source_port[0] if args.source_port else random.randint(49152, 65534)
        self.nmapMAC = args.nmap_mac[0] if args.nmap_mac else ""
        self.nmapIP = args.nmap_ip[0] if args.nmap_ip else ""
        self.nmapPorts = []
        if args.nmap_ports:
            for arg in args.nmap_port[0].split(','):
                if "-" in arg:
                    i1,i2 = arg.split("-")
                    for i in range(int(i1), int(i2)+1):
                        self.nmapPorts.append(i)
                else:
                    self.nmapPorts.append(int(arg))

        self.iface = "eth1"
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
        
        config = Config()
        config.load_envs()
        evcc_config = await load_from_file(config.ev_config_file_path)
        self.iface = config.iface
        self.slac = SLACHandler(self)
        
        self.doSLAC()
        
        await EVCCHandler(
            evcc_config=evcc_config,
            iface=config.iface,
            exi_codec=ExificientEXICodec(),
            ev_controller=SimEVController(evcc_config),
        ).start()

    def doSLAC(self):
        logger.info("Starting SLAC")
        self.slac.start()
        self.slac.sniffThread.join()
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
