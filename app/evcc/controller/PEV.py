"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

    This class is used to emulate a PEV when talking to an EVSE. Handles level 2 SLAC communications
    and level 3 UDP and TCP communications to the charging station.
"""

# need to do this to import the custom SECC and V2G scapy layer
import random, time
import logging

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
        self.iface = args.interface[0] if args.interface else "eth0"
        self.sourceMAC = args.source_mac[0] if args.source_mac else "00:15:5d:d0:d0:ee"
        self.sourceIP = args.source_ip[0] if args.source_ip else "fe80::215:5dff:fed0:d0ee"
        self.sourcePort = args.source_port[0] if args.source_port else random.randint(1025, 65534)
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

        self.destinationMAC = None
        self.destinationIP = None
        self.destinationPort = None
        
        self.pnc = False
        self.tls = False
        self.complete =False

        self.slac = SLACHandler(self)

        # Constants for i2c controlled relays
        self.I2C_ADDR = 0x20
        self.CONTROL_REG = 0x9
        self.PEV_CP1 = 0b10
        self.PEV_CP2 = 0b100
        self.PEV_PP = 0b10000
        self.ALL_OFF = 0b0

    async def start(self):
        self.toggleProximity()
        
        config = Config()
        config.load_envs()
        evcc_config = await load_from_file(config.ev_config_file_path)
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
        elif state == PEVState.B:
            logger.info("Going to state B")
        elif state == PEVState.C:
            logger.info("Going to state C")

    def toggleProximity(self, t: int = 5):
        self.openProximity()
        time.sleep(t)
        self.closeProximity()
