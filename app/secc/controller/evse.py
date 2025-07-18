"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
    
    This class is used to emulate a EVSE when talking to an PEV. Handles level 2 SLAC communications
    and level 3 UDP and TCP communications to the electric vehicle.
"""

# need to do this to import the custom SECC and V2G scapy layer
import time, logging
import netifaces

from smbus import SMBus

from app.shared.EmulatorEnum import RunMode

from app.secc.transport.slac import SLACHandler

from app.secc import SECCHandler
from app.secc.controller.interface import ServiceStatus
from app.secc.controller.simulator import SimEVSEController
from app.secc.secc_settings import Config
from app.shared.exificient_exi_codec import ExificientEXICodec
from app.shared.logging import _init_logger

_init_logger(source="SECC")
logger = logging.getLogger(__name__)

class EVSE:

    def __init__(self, args):
        self.mode = RunMode(args.mode[0]) if args.mode else RunMode.FULL
        self.iface = "eth2"

        # Scan eth2 for MAC and link-local IPv6 if not provided
        if args.source_mac:
            self.sourceMAC = args.source_mac[0]
        else:
            self.sourceMAC = netifaces.ifaddresses(self.iface)[netifaces.AF_LINK][0]['addr']

        if args.source_ip:
            self.sourceIP = args.source_ip[0]
        else:
            ipv6_addrs = netifaces.ifaddresses(self.iface).get(netifaces.AF_INET6, [])
            self.sourceIP = next((a['addr'] for a in ipv6_addrs if a['addr'].startswith('fe80')), None)

        self.sourcePort = args.source_port[0] if args.source_port else 25565
        self.NID = args.NID[0] if args.NID else b"\x9c\xb0\xb2\xbb\xf5\x6c\x0e"
        self.NMK = args.NMK[0] if args.NMK else b"\x48\xfe\x56\x02\xdb\xac\xcd\xe5\x1e\xda\xdc\x3e\x08\x1a\x52\xd1"
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
        if args.modified_cordset:
            self.modified_cordset = True
        else:
            self.modified_cordset = False
            
        self.destinationMAC = None
        self.destinationIP = None
        self.destinationPort = None
        self.slac = None
        
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
        # Initialize the I2C bus for wwrite
        self.bus.write_byte_data(self.I2C_ADDR, 0x00, 0x00)
        self.toggleProximity()
        
        config = Config()
        config.load_envs()
        self.iface = config.iface
        self.slac = SLACHandler(self)
        
        self.doSLAC()

        sim_evse_controller = SimEVSEController()
        await sim_evse_controller.set_status(ServiceStatus.STARTING)
        await SECCHandler(
            exi_codec=ExificientEXICodec(),
            evse_controller=sim_evse_controller,
            config=config,
        ).start(config.iface)

    # Close the circuit for the proximity pins
    def closeProximity(self):
        if self.modified_cordset:
            logger.info("Closing CP/PP relay connections")
            self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.EVSE_PP | self.EVSE_CP)
        else:
            logger.info("Closing CP relay connection")
            self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.EVSE_CP)

    # Close the circuit for the proximity pins
    def openProximity(self):
        logger.info("Opening CP/PP relay connections")
        self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.ALL_OFF)

    # Opens and closes proximity circuit with a delay
    def toggleProximity(self, t: int = 5):
        self.openProximity()
        time.sleep(t)
        self.closeProximity()

    # Starts SLAC thread that handles layer 2 comms
    def doSLAC(self):
        self.slac.start()
        self.slac.sniffThread.join()
        logger.info("Done SLAC")
