"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
    
    This class is used to emulate a EVSE when talking to an PEV. Handles level 2 SLAC communications
    and level 3 UDP and TCP communications to the electric vehicle.
"""

# need to do this to import the custom SECC and V2G scapy layer
import os, time, argparse, logging

from app.shared.EmulatorEnum import Protocol, RunMode

from app.secc.transport.slac import SLACHandler

from app.secc import SECCHandler
from app.secc.controller.interface import ServiceStatus
from app.secc.controller.simulator import SimEVSEController
from app.secc.secc_settings import Config
from app.shared.exificient_exi_codec import ExificientEXICodec
from app.shared.logging import _init_logger

_init_logger(source="SECC")
logger = logging.getLogger(__name__)
# fileHandler = logging.FileHandler("logs/SECC_"+datetime.now().strftime("%d-%m-%Y_%H-%M-%S")+".log")
# consoleHandler = logging.StreamHandler()
# logging.basicConfig(format="%(asctime)s (%(name)s) %(levelname)s: %(message)s",
#                     handlers=[fileHandler, consoleHandler],
#                     level=logging.INFO)

class EVSE:

    def __init__(self, args):
        self.mode = RunMode(args.mode[0]) if args.mode else RunMode.FULL
        self.iface = args.interface[0] if args.interface else "eth0"
        self.sourceMAC = args.source_mac[0] if args.source_mac else "00:15:5d:d0:d0:ee"
        self.sourceIP = args.source_ip[0] if args.source_ip else "fe80::215:5dff:fed0:d0ee"
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

        self.slac = SLACHandler(self)
        # self.udp = UDPHandler(self)
        # self.tcp = TCPHandler(self)

        # Constants for i2c controlled relays
        self.I2C_ADDR = 0x20
        self.CONTROL_REG = 0x9
        self.EVSE_CP = 0b1
        self.EVSE_PP = 0b1000
        self.ALL_OFF = 0b0

    # Start the emulator
    async def start(self):
        self.toggleProximity()
        
        config = Config()
        config.load_envs()
        config.print_settings()

        sim_evse_controller = SimEVSEController()
        await sim_evse_controller.set_status(ServiceStatus.STARTING)
        await SECCHandler(
            exi_codec=ExificientEXICodec(),
            evse_controller=sim_evse_controller,
            config=config,
        ).start(config.iface)
        
        # self.doUDP()
        # self.doTCP()

    # Close the circuit for the proximity pins
    def closeProximity(self):
        if self.modified_cordset:
            logger.info("Closing CP/PP relay connections")
        else:
            logger.info("Closing CP relay connection")

    # Close the circuit for the proximity pins
    def openProximity(self):
        logger.info("Opening CP/PP relay connections")

    # Opens and closes proximity circuit with a delay
    def toggleProximity(self, t: int = 5):
        self.openProximity()
        time.sleep(t)
        self.closeProximity()

    # Starts TCP/IPv6 thread that handles layer 3 comms after SDP
    def doTCP(self):
        self.tcp.start()
        logger.info("Done TCP")

    # Starts SLAC thread that handles layer 2 comms
    def doSLAC(self):
        self.slac.start()
        self.slac.sniffThread.join()
        logger.info("Done SLAC")

    # Starts UDP thread that handles layer 3 for SDP
    def doUDP(self):
        self.udp.start()
        self.udp.timeoutThread.join()
        logger.info("Done UDP")

if __name__ == "__main__":
    # Parse arguements from command line
    parser = argparse.ArgumentParser(description="EVSE emulator for AcCCS")
    parser.add_argument(
        "-M",
        "--mode",
        nargs=1,
        type=int,
        help="Mode for emulator to run in: 0 for full conversation, 1 for stalling the conversation, 2 for portscanning (default: 0)",
    )
    parser.add_argument("-I", "--interface", nargs=1, help="Ethernet interface to send/recieve packets on (default: eth1)")
    parser.add_argument("--source-mac", nargs=1, help="Source MAC address of packets (default: 00:1e:c0:f2:6c:a0)")
    parser.add_argument("--source-ip", nargs=1, help="Source IP address of packets (default: fe80::21e:c0ff:fef2:72f3)")
    parser.add_argument("--source-port", nargs=1, type=int, help="Source port of packets (default: 25565)")
    parser.add_argument("--NID", nargs=1, help="Network ID of the HomePlug GreenPHY AVLN (default: \\x9c\\xb0\\xb2\\xbb\\xf5\\x6c\\x0e)")
    parser.add_argument(
        "--NMK",
        nargs=1,
        help="Network Membership Key of the HomePlug GreenPHY AVLN (default: \\x48\\xfe\\x56\\x02\\xdb\\xac\\xcd\\xe5\\x1e\\xda\\xdc\\x3e\\x08\\x1a\\x52\\xd1)",
    )
    parser.add_argument("-p", "--protocol", nargs=1, help="Protocol for EXI encoding/decoding: DIN, ISO-2, ISO-20 (default: DIN)")
    parser.add_argument("--nmap-mac", nargs=1, help="The MAC address of the target device to NMAP scan (default: EVCC MAC address)")
    parser.add_argument("--nmap-ip", nargs=1, help="The IP address of the target device to NMAP scan (default: EVCC IP address)")
    parser.add_argument("--nmap-ports", nargs=1, help="List of ports to scan seperated by commas (ex. 1,2,5-10,19,...) (default: Top 8000 common ports)")
    parser.add_argument("--modified-cordset", action="store_true", help="Set this option when using a modified cordset during testing of a target vehicle. The AcCCS system will provide a 150 ohm ground on the proximity line to reset the connection. (default: False)")
    args = parser.parse_args()

    evse = EVSE(args)
    try:
        evse.start()
    except KeyboardInterrupt:
        logger.info("Shutting down emulator")
    except Exception as e:
        raise e
        logger.error(e)
    finally:
        evse.openProximity()
        del evse
