"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
    
    This class is used to emulate a EVSE when talking to an PEV. Handles level 2 SLAC communications
    and level 3 UDP and TCP communications to the electric vehicle.
"""

# need to do this to import the custom SECC and V2G scapy layer
import sys, os

sys.path.append("./external_libs/HomePlugPWN")
sys.path.append("./external_libs/V2GInjector/core")
sys.path.append("./external_libs/EXPy/")

from AppHandshakeProcessor import AppHandshakeProcessor
from DINProcessor import DINProcessor
from EmulatorEnum import *
from NMAPScanner import NMAPScanner
from Packets import *
from V2Gjson import *
from EmulatorStateMachine import EmulatorStateMachine

from threading import Thread
import random
import argparse
import logging
import time
import ipaddress

class Emulator:
    def __init__(self, args):
        self.emulatorType = EmulatorType(args.type[0]) if args.type else EmulatorType.EVSE

        self.mode = RunMode(args.mode[0]) if args.mode else RunMode.FULL
        self.protocol = EXIProtocol(args.protocol[0].upper()) if args.protocol else EXIProtocol.DIN
        self.modified_cordset = True if args.modified_cordset else False
        self.virtual = True if args.virtual else False
        self.debug = True if args.debug else False
        self.timeout = args.timeout if args.timeout else 15
        self.running = True

        self.sourceMAC = args.source_mac[0] if args.source_mac else self.getRandomMAC()
        self.sourceIP = args.source_ip[0] if args.source_ip else self.getLinkLocalIP(self.sourceMAC)

        self.scanning = False
        self.portscanIP = args.portscan_IP[0] if args.portscan_IP else None
        self.portscanMAC = args.portscan_MAC[0] if args.portscan_MAC else None
        self.portscanPorts = []
        if args.portscan_ports:
            for arg in args.portscan_ports[0].split(','):
                if "-" in arg:
                    i1,i2 = arg.split("-")
                    for i in range(int(i1), int(i2)+1):
                        self.portscanPorts.append(i)
                else:
                    self.portscanPorts.append(int(arg))

        # TODO: generate random NID and NMK (do they need be generated from each other?)
        if self.emulatorType == EmulatorType.EVSE:
            self.iface = args.interface[0] if args.interface else "ethevse"
            self.sourcePort = args.source_port[0] if args.source_port else 25565
            self.NID = args.NID[0] if args.NID else b"\x9c\xb0\xb2\xbb\xf5\x6c\x0e"
            self.NMK = args.NMK[0] if args.NMK else b"\x48\xfe\x56\x02\xdb\xac\xcd\xe5\x1e\xda\xdc\x3e\x08\x1a\x52\xd1"
        else:
            self.iface = args.interface[0] if args.interface else "ethpev"
            self.sourcePort = args.source_port[0] if args.source_port else random.randint(1025, 65534)
            self.runID = os.urandom(8)

        self.destinationMAC = None
        self.destinationIP = None
        self.destinationPort = None

        self.seq = random.randint(1000, 9999)
        self.ack = 0
        self.sessionID = "00"

        self.remainingSounds = 10

        self.appHandshake = AppHandshakeProcessor()

        if self.protocol == EXIProtocol.DIN:
            self.EXIProcessor = DINProcessor()
        elif self.protocol == EXIProtocol.ISO_2:
            raise NotImplementedError("ISO-2 EXI Protocol is not implemented yet")
        elif self.protocol == EXIProtocol.ISO_20:
            raise NotImplementedError("ISO-20 EXI Protocol is not implemented yet")
        else:
            raise ValueError(f"Unsupported EXI Protocol: {self.protocol.value}")

        if self.emulatorType == EmulatorType.EVSE:
            # TODO: Implement EVSE state machine
            pass
        elif self.emulatorType == EmulatorType.PEV:
            self.stateMachine = EmulatorStateMachine(self)

        if self.mode == RunMode.SCAN:
            if not self.portscanMAC :
                raise ValueError("Port scan MAC address is required in scan mode")
            if not self.portscanIP :
                raise ValueError("Port scan IP address is required in scan mode")
            self.scanner = NMAPScanner(self.portscanPorts, self.iface, self.sourceMAC, self.sourceIP, self.portscanMAC, self.portscanIP)

        if not self.virtual:
            from smbus import SMBus
            # I2C bus configuration
            self.bus = SMBus(1)
            self.I2C_ADDR    = 0x20
            self.I2C_REG     = 0x9
            self.I2C_EVSE_CP = 0b1
            self.I2C_PEV_CP1 = 0b10
            self.I2C_PEV_CP2 = 0b100
            self.I2C_EVSE_PP = 0b1000
            self.I2C_PEV_PP  = 0b10000
            self.I2C_ALL_OFF = 0b0

        # Logging
        logging.basicConfig(
            level=logging.DEBUG if self.debug else logging.INFO,
            format=f"%(asctime)s.%(msecs)03d | %(levelname)-7s | {self.emulatorType.value.upper():<4} -- %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        logging.info("Emulator Initialized")

    def getRandomMAC(self):
        mac_end = [random.randint(0x00, 0x7f) for _ in range(3)]
        mac_end_joined = ":".join(f"{x:02x}" for x in mac_end)
        return f"00:1e:c0:{mac_end_joined}"

    def getLinkLocalIP(self, mac_address=None):
            mac_int = int(mac_address.replace(":", ""), 16)

            first_byte = (mac_int >> 40) & 0xFF
            modified_first_byte = first_byte ^ 0x02
            mac_int = (mac_int & 0xFFFFFFFFFF0000) | (modified_first_byte << 40) | (mac_int & 0xFFFFFFFFFF)

            upper_mac = (mac_int >> 24) & 0xFFFFFF
            lower_mac = mac_int & 0xFFFFFF

            eui64_int = (upper_mac << 40) | (0xFFFE << 24) | lower_mac

            ipv6_address = ipaddress.IPv6Address(0xfe800000000000000000000000000000 | eui64_int)

            return str(ipv6_address)

    def start(self):
        print(r"""
+===================================================================================================+
|                   ___           ___           ___           ___           ___                     |
|                  /\  \         /\  \         /\  \         /\  \         /\  \                    |
|                 /::\  \       /::\  \       /::\  \       /::\  \       /::\  \                   |
|                /:/\:\  \     /:/\:\  \     /:/\:\  \     /:/\:\  \     /:/\ \  \                  |
|               /::\~\:\  \   /:/  \:\  \   /:/  \:\  \   /:/  \:\  \   _\:\~\ \  \                 |
|              /:/\:\ \:\__\ /:/__/ \:\__\ /:/__/ \:\__\ /:/__/ \:\__\ /\ \:\ \ \__\                |
|              \/__\:\/:/  / \:\  \  \/__/ \:\  \  \/__/ \:\  \  \/__/ \:\ \:\ \/__/                |
|                   \::/  /   \:\  \        \:\  \        \:\  \        \:\ \:\__\                  |
|                   /:/  /     \:\  \        \:\  \        \:\  \        \:\/:/  /                  |
|                  /:/  /       \:\__\        \:\__\        \:\__\        \::/  /                   |
|                  \/__/         \/__/         \/__/         \/__/         \/__/                    |
|                                                                                                   |
|                                  _______ _                           _        _____ _____  _____  |
|     /\                          |__   __| |                         | |      / ____/ ____|/ ____| |
|    /  \   ___ ___ ___  ___ ___     | |  | |__  _ __ ___  _   _  __ _| |__   | |   | |    | (___   |
|   / /\ \ / __/ __/ _ \/ __/ __|    | |  | '_ \| '__/ _ \| | | |/ _` | '_ \  | |   | |     \___ \  |
|  / ____ \ (_| (_|  __/\__ \__ \    | |  | | | | | | (_) | |_| | (_| | | | | | |___| |____ ____) | |
| /_/    \_\___\___\___||___/___/    |_|  |_| |_|_|  \___/ \__,_|\__, |_| |_|  \_____\_____|_____/  |
|                                                                 __/ |                             |
|                                                                |___/                              |
|                                                                                                   |
+===================================================================================================+
""")

        logging.info("Starting Emulator")
        logging.info(f"Emulator Type:     {self.emulatorType.value.upper()}")
        logging.info(f"Emulator Mode:     {self.mode.value} [{RunMode(self.mode).name}]")
        logging.info(f"Emulator Protocol: {self.protocol.value}")
        logging.info(f"Interface:         {self.iface}")

        # Initialize I2C Bus
        if not self.virtual:
            self.bus.write_byte_data(self.I2C_ADDR, 0x00, 0x00)
        logging.debug("GPIO Expander Initialized")
        self.setState(EmulatorState.A)

        # Start threads
        # Sniffing thread
        logging.debug("Starting Sniffing Thread")
        self.sniffingThread = AsyncSniffer(iface=self.iface, prn=self.handlePacket, started_callback=lambda: logging.debug("Sniffing Thread Started"), lfilter=lambda x: x.haslayer("Ethernet") and not x[Ether].src == self.sourceMAC)
        self.sniffingThread.start()

        # Timeout thread
        logging.debug("Starting Timeout Thread")
        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()

        # State Machine
        self.stateMachine.start()

    def expandPacketLayers(self, pkt):
        res = []
        res.append(pkt.name)
        while pkt.payload:
            pkt = pkt.payload
            res.append(pkt.name)
        return res

    def handlePacket(self, pkt):
        if hasattr(self, "lastPkt") and self.lastPkt == pkt:
            return
        
        self.lastPkt = pkt

        resPkt = self.stateMachine.handlePacket(pkt)
        if resPkt is None:
            return
        self.sendPacket(resPkt)

        self.lastMessageTime = time.time()
    
    def killall(self):
        self.running = False
        self.sniffingThread.stop()
        self.timeoutThread.stop()
        self.bus.write_byte_data(self.I2C_ADDR, self.I2C_REG, self.I2C_ALL_OFF)
        logging.info("Emulator Stopped")

    def sendPacket(self, pkt):
        if type(pkt) is list:
            for p in pkt:
                logging.debug(f"Sending packet: {p.summary()}")
        else:
            logging.debug(f"Sending packet: {pkt.summary()}")
        self.lastMessageTime = time.time()
        sendp(pkt, iface=self.iface, verbose=False)

    # Check if any messages have been recieved within timeout period and resets connection if not
    def checkForTimeout(self):
        logging.info("Timeout Thread Started")
        self.lastMessageTime = time.time()
        while self.running:
            if time.time() - self.lastMessageTime > self.timeout:
                logging.warning("Connection timed out, reseting connection")
                if self.scanning:
                    self.scanning = False
                    self.scanner.stop()
                    logging.info("Port Scanner Stopped")
                self.setState(EmulatorState.A)
                self.stateMachine.stop()
                time.sleep(3)
                self.setState(EmulatorState.B)
                self.remainingSounds = 10
                self.stateMachine.start()

                self.lastMessageTime = time.time()
            time.sleep(.1)
        logging.info("Timeout Thread Stopped")

    # Sets the relays connected to the proximity and control pilot pins based on the emulator's CCS state
    def setState(self, state: EmulatorState):
        if self.virtual:
            logging.info(f"Setting (virtual) CCS State: {state.value.upper()}")
            return

        currentI2C = self.bus.read_byte_data(self.I2C_ADDR, self.I2C_REG)
        newI2C = 0b0

        if self.emulatorType == EmulatorType.EVSE:
            if state == EmulatorState.A:
                newI2C = currentI2C & ~(self.I2C_EVSE_PP | self.I2C_EVSE_CP)
            elif state == EmulatorState.B or state == EmulatorState.C:
                newI2C = currentI2C | self.I2C_EVSE_PP | self.I2C_EVSE_CP
            else:
                logging.warning(f"Unable to set state, invalid state: {state.value}")
        
        elif self.emulatorType == EmulatorType.PEV:
            if state == EmulatorState.A:
                newI2C = currentI2C & ~(self.I2C_PEV_PP | self.I2C_PEV_CP1 | self.I2C_PEV_CP2)
            elif state == EmulatorState.B:
                newI2C = currentI2C | self.I2C_PEV_PP | self.I2C_PEV_CP1 & ~self.I2C_PEV_CP2
            elif state == EmulatorState.C:
                newI2C = currentI2C | self.I2C_PEV_PP | self.I2C_PEV_CP1 | self.I2C_PEV_CP2
            else:
                logging.warning(f"Unable to set state, invalid state: {state.value}")

        else:
            logging.warning("Unable to set state, invalid emulator type")

        logging.info(f"Setting CCS State: {state.value.upper()}")
        self.bus.write_byte_data(self.I2C_ADDR, self.I2C_REG, newI2C)
        logging.info(f"Set CCS State: {state.value.upper()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AcCCS (Access Through CCS): Emulate a PEV or EVSE -- Default values shown in [square brackets]")
    parser.add_argument("-M", "--mode", type=int, nargs=1, choices=[0, 1, 2], help="Emulator mode: [0=Full], 1=Stall, 2=Scan")
    parser.add_argument("-T", "--type", type=str, nargs=1, choices=["pev", "evse"], help="Emulator type: [EVSE] or PEV")
    parser.add_argument("-P", "--protocol", type=str, nargs=1, choices=["DIN", "ISO-2", "ISO-20"], help="Protocol to use for EXI encoding: [DIN], ISO-2, ISO-20")
    parser.add_argument("-I", "--interface", type=str, nargs=1, help="Interface to listen on: [ethevse], ethpev, etc.")
    parser.add_argument("--modified-cordset", action="store_true", help="Enable modified cordset: [false]")
    parser.add_argument("-V", "--virtual", action="store_true", help="Enable virtual mode: [false]")
    parser.add_argument("--source-mac", type=str, nargs=1, help="Specify source MAC address (optional)")
    parser.add_argument("--source-ip", type=str, nargs=1, help="Specify source IP address (optional)")
    parser.add_argument("--source-port", type=int, nargs=1, help="Specify source port (optional)")
    parser.add_argument("--NID", type=str, nargs=1, help="Specify Network ID (optional)")
    parser.add_argument("--NMK", type=str, nargs=1, help="Specify Network Membership Key (optional)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode: [false]")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for connection reset in seconds: [5]")
    parser.add_argument("--portscan-MAC", type=str, nargs=1, help="MAC address for port scanning (required if in mode 2)")
    parser.add_argument("--portscan-IP", type=str, nargs=1, help="IP address for port scanning (required if in mode 2)")
    parser.add_argument("--portscan-ports", type=str, nargs=1, help="List of ports to scan separated by commas (ex. 1,2,5-10,19,...) (default: Top 8000 common ports)")

    args = parser.parse_args()

    emulator = Emulator(args)
    emulator.start()