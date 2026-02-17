"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
    Copyright 2025, Ford Motor Company
    Copyright 2022, Switch
    
    This class is used to emulate a EVSE when talking to an PEV. Handles level 2 SLAC communications
    and level 3 UDP and TCP communications to the electric vehicle.
"""

# need to do this to import the custom SECC and V2G scapy layer
import time, logging
import netifaces

from app.shared.EmulatorEnum import RunMode

from app.secc.transport.slac import SLACHandler

from app.secc import SECCHandler
from app.secc.controller.interface import ServiceStatus
from app.secc.controller.simulator import SimEVSEController
from app.secc.secc_settings import Config
from app.shared.exificient_exi_codec import ExificientEXICodec
from app.shared.network import (
    get_link_local_addr,
    get_nic_mac_address,
    get_tcp_port
)
from app.shared.logging import _init_logger

_init_logger(source="SECC")
logger = logging.getLogger(__name__)

class EVSE:

    def __init__(self, args):
        self.config = Config()
        self.config.load_envs()
        
        self.iface = self.config.iface
        self.sourceMAC = get_nic_mac_address(self.iface)
        self.sourceIP = str(get_link_local_addr(self.iface))
        self.sourcePort = args.source_port[0] if args.source_port else get_tcp_port()
        self.NID = args.NID[0] if args.NID else b"\x9c\xb0\xb2\xbb\xf5\x6c\x0e"
        self.NMK = args.NMK[0] if args.NMK else b"\x48\xfe\x56\x02\xdb\xac\xcd\xe5\x1e\xda\xdc\x3e\x08\x1a\x52\xd1"
        if args.modified_cordset:
            self.modified_cordset = True
        else:
            self.modified_cordset = False
            
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

        sim_evse_controller = SimEVSEController()
        await sim_evse_controller.set_status(ServiceStatus.STARTING)
        await SECCHandler(
            exi_codec=ExificientEXICodec(),
            evse_controller=sim_evse_controller,
            config=self.config,
        ).start(self.config.iface)

    # Close the circuit for the proximity pins
    def closeProximity(self):
        if self.modified_cordset:
            logger.info("Closing CP/PP relay connections")
            if not self.virtual:
                self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.EVSE_PP | self.EVSE_CP)
        else:
            logger.info("Closing CP relay connection")
            if not self.virtual:
                self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.EVSE_CP)

    # Close the circuit for the proximity pins
    def openProximity(self):
        logger.info("Opening CP/PP relay connections")
        if not self.virtual:
            self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.ALL_OFF)

    # Opens and closes proximity circuit with a delay
    def toggleProximity(self, t: int = 5):
        self.openProximity()
        time.sleep(t)
        self.closeProximity()

    # Starts SLAC thread that handles layer 2 comms
    def doSLAC(self):
        self.slac.start()
        logger.info("Done SLAC")
