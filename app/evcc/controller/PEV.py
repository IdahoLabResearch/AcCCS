"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

    This class is used to emulate a PEV when talking to an EVSE. Handles level 2 SLAC communications
    and level 3 UDP and TCP communications to the charging station.
"""

# need to do this to import the custom SECC and V2G scapy layer
import os, random, time
import argparse, logging

from datetime import datetime

from app.shared.EXIProcessor import EXIProcessor
from app.shared.EmulatorEnum import RunMode, PEVState, Protocol

from app.evcc.transport.slac import SLACHandler
from app.evcc.transport.udp import UDPHandler
from app.evcc.transport.tcp import TCPHandler

if not os.path.isdir("logs"):
    os.makedirs("logs")

logger = logging.getLogger("EVCC")
fileHandler = logging.FileHandler("logs/EVCC_"+datetime.now().strftime("%d-%m-%Y_%H-%M-%S")+".log")
consoleHandler = logging.StreamHandler()
logging.basicConfig(format="%(asctime)s (%(name)s) %(levelname)s: %(message)s",
                    handlers=[fileHandler, consoleHandler],
                    level=logging.INFO)

class PEV:

    def __init__(self, args):
        self.mode = RunMode(args.mode[0]) if args.mode else RunMode.FULL
        self.iface = args.interface[0] if args.interface else "lo"
        self.sourceMAC = args.source_mac[0] if args.source_mac else "00:00:00:00:00:00"
        self.sourceIP = args.source_ip[0] if args.source_ip else "::1"
        self.sourcePort = args.source_port[0] if args.source_port else random.randint(1025, 65534)
        self.protocol = Protocol(args.protocol[0]) if args.protocol else Protocol.DIN
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
        
        self.exi = EXIProcessor(self.protocol)

        self.slac = SLACHandler(self)
        self.udp = UDPHandler(self)
        self.tcp = TCPHandler(self)

        # Constants for i2c controlled relays
        self.I2C_ADDR = 0x20
        self.CONTROL_REG = 0x9
        self.PEV_CP1 = 0b10
        self.PEV_CP2 = 0b100
        self.PEV_PP = 0b10000
        self.ALL_OFF = 0b0

    def start(self):
        self.toggleProximity()
        time.sleep(1)
        self.doUDP()
        time.sleep(1)
        self.doTCP()

    def doTCP(self):
        self.tcp.start()
        logger.info("Done TCP")

    def doSLAC(self):
        logger.info("Starting SLAC")
        self.slac.start()
        self.slac.sniffThread.join()
        logger.info("Done SLAC")

    # Starts UDP thread that handles layer 3 for SDP
    def doUDP(self):
        self.udp.start()
        self.udp.timeoutThread.join()
        logger.info("Done UDP")

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

if __name__ == "__main__":
    # Parse arguements from command line
    parser = argparse.ArgumentParser(description="PEV emulator for AcCCS")
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
    parser.add_argument("-p", "--protocol", nargs=1, help="Protocol for EXI encoding/decoding: DIN, ISO-2, ISO-20 (default: DIN)")
    parser.add_argument("--nmap-mac", nargs=1, help="The MAC address of the target device to NMAP scan (default: SECC MAC address)")
    parser.add_argument("--nmap-ip", nargs=1, help="The IP address of the target device to NMAP scan (default: SECC IP address)")
    parser.add_argument("--nmap-ports", nargs=1, help="List of ports to scan seperated by commas (ex. 1,2,5-10,19,...) (default: Top 8000 common ports)")
    args = parser.parse_args()

    pev = PEV(args)
    try:
        pev.start()
    except KeyboardInterrupt:
        logger.info("Shutting down emulator")
    except Exception as e:
        raise e
        logger.error(e)
    finally:
        pev.setState(PEVState.A)
        del pev
