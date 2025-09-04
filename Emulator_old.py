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
        self.timeout = args.timeout if args.timeout else 5
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
        self.sessionActive = False
        self.appHandshakeComplete = False

        self.firstTime = False

        self.appHandshake = AppHandshakeProcessor()

        if self.protocol == EXIProtocol.DIN:
            self.din = DINProcessor()
        elif self.protocol == EXIProtocol.ISO_2:
            raise NotImplementedError("ISO-2 EXI Protocol is not implemented yet")
        elif self.protocol == EXIProtocol.ISO_20:
            raise NotImplementedError("ISO-20 EXI Protocol is not implemented yet")
        else:
            raise ValueError(f"Unsupported EXI Protocol: {self.protocol.value}")
        
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
        
        self.messagesSentRecieved = {
            "SET_KEY_REQ": {"sent": 0, "recieved": 0},

            "CM_SLAC_PARM_REQ": {"sent": 0, "recieved": 0},
            "CM_SLAC_PARM_CNF": {"sent": 0, "recieved": 0},
            "START_ATTEN_CHAR_IND": {"sent": 0, "recieved": 0},
            "CM_MNBC_SOUND_IND": {"sent": 0, "recieved": 0},
            "CM_ATTEN_CHAR_IND": {"sent": 0, "recieved": 0},
            "CM_ATTEN_CHAR_RES": {"sent": 0, "recieved": 0},
            "CM_SLAC_MATCH_REQ": {"sent": 0, "recieved": 0},
            "CM_SLAC_MATCH_CNF": {"sent": 0, "recieved": 0},

            "SECC_RequestMessage": {"sent": 0, "recieved": 0},
            "SECC_ResponseMessage": {"sent": 0, "recieved": 0},

            "SYN": {"sent": 0, "recieved": 0},
            "SYNACK": {"sent": 0, "recieved": 0},
            "FIN": {"sent": 0, "recieved": 0},
            "RST": {"sent": 0, "recieved": 0},

            "supportedAppProtocolReq": {"sent": 0, "recieved": 0},
            "supportedAppProtocolRes": {"sent": 0, "recieved": 0},

            "SessionSetupReq": {"sent": 0, "recieved": 0},
            "SessionSetupRes": {"sent": 0, "recieved": 0},
            "ServiceDiscoveryReq": {"sent": 0, "recieved": 0},
            "ServiceDiscoveryRes": {"sent": 0, "recieved": 0},
            "ServicePaymentSelectionReq": {"sent": 0, "recieved": 0},
            "ServicePaymentSelectionRes": {"sent": 0, "recieved": 0},
            "ContractAuthenticationReq": {"sent": 0, "recieved": 0},
            "ContractAuthenticationRes:Ongoing": {"sent": 0, "recieved": 0},
            "ContractAuthenticationRes:Finished": {"sent": 0, "recieved": 0},
            "ChargeParameterDiscoveryReq": {"sent": 0, "recieved": 0},
            "ChargeParameterDiscoveryRes:Ongoing": {"sent": 0, "recieved": 0},
            "ChargeParameterDiscoveryRes:Finished": {"sent": 0, "recieved": 0},
            "CableCheckReq": {"sent": 0, "recieved": 0},
            "CableCheckRes:Ongoing": {"sent": 0, "recieved": 0},
            "CableCheckRes:Finished": {"sent": 0, "recieved": 0},
            "PreChargeReq": {"sent": 0, "recieved": 0},
            "PreChargeRes": {"sent": 0, "recieved": 0},
            "PowerDeliveryReq": {"sent": 0, "recieved": 0},
            "PowerDeliveryRes": {"sent": 0, "recieved": 0},
            "CurrentDemandReq": {"sent": 0, "recieved": 0},
            "CurrentDemandRes": {"sent": 0, "recieved": 0},
            "SessionStopReq": {"sent": 0, "recieved": 0},
            "SessionStopRes": {"sent": 0, "recieved": 0}
        }

        # Logging
        logging.basicConfig(
            level=logging.DEBUG if self.debug else logging.INFO,
            format=f"%(asctime)s.%(msecs)03d | %(levelname)-7s | {self.emulatorType.value.upper():<4} -- %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        logging.info("Emulator Initialized")
    
    def resetMessagesSentRecieved(self):
        for key in self.messagesSentRecieved:
            self.messagesSentRecieved[key]["sent"] = 0
            self.messagesSentRecieved[key]["recieved"] = 0
        logging.debug("Messages Sent/Recieved Counters Reset")

    def getRandomMAC(self):
        mac = [random.randint(0x00, 0x7f) for _ in range(6)]
        return ":".join(f"{x:02x}" for x in mac)
    
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

        # Set NMK for PEV Emulator
        if self.emulatorType == EmulatorType.EVSE:
            self.sendPacket(SetKeyReq(self))
            self.messagesSentRecieved["SET_KEY_REQ"]["sent"] += 1
            logging.info("Sent SET_KEY_REQ")

        # Start threads
        # Sniffing thread
        logging.debug("Starting Sniffing Thread")
        self.sniffingThread = AsyncSniffer(iface=self.iface, prn=self.handlePacket, started_callback=lambda: logging.debug("Sniffing Thread Started"), lfilter=lambda x: x.haslayer("Ethernet") and not x[Ether].src == self.sourceMAC)
        self.sniffingThread.start()

        # Timeout thread
        logging.debug("Starting Timeout Thread")
        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()

        # SLAC
        logging.info("Starting SLAC")
        self.setState(EmulatorState.B)

        if self.emulatorType == EmulatorType.PEV:
            self.sendPacket(SlacParmReq(self))
            self.messagesSentRecieved["CM_SLAC_PARM_REQ"]["sent"] += 1
            logging.info("Sent CM_SLAC_PARM_REQ")

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


        

        # TODO: only check for packets with correct RunID
        # Handle HPGP Packets
        if pkt[Ether].type == 0x88e1:
            self.lastMessageTime = time.time()
            HPGPLayer = self.expandPacketLayers(pkt)[2]
            match HPGPLayer:
                case "CM_SLAC_PARM_REQ":
                    self.messagesSentRecieved["CM_SLAC_PARM_REQ"]["recieved"] += 1
                    logging.info("Recieved CM_SLAC_PARM_REQ")
                    self.destinationMAC = pkt[Ether].src
                    self.runID = pkt[CM_SLAC_PARM_REQ].RunID
                    self.sendPacket(SlacParmCnf(self))
                    self.messagesSentRecieved["CM_SLAC_PARM_CNF"]["sent"] += 1
                    logging.info("Sent CM_SLAC_PARM_CNF")
                case "CM_SLAC_PARM_CNF":
                    self.messagesSentRecieved["CM_SLAC_PARM_CNF"]["recieved"] += 1
                    logging.info("Recieved CM_SLAC_PARM_CNF")
                    self.destinationMAC = pkt[Ether].src
                    self.remainingSounds = 10
                    startSoundPkts = [StartAttenCharInd(self) for i in range(3)]
                    soundPkts = [MNBCSoundInd(self) for i in range(10)]
                    self.sendPacket(startSoundPkts)
                    self.messagesSentRecieved["START_ATTEN_CHAR_IND"]["sent"] += 3
                    logging.info("Sent 3 START_ATTEN_CHAR_IND")
                    self.sendPacket(soundPkts)
                    self.messagesSentRecieved["CM_MNBC_SOUND_IND"]["sent"] += 10
                    logging.info("Sent 10 MNBC_SOUND_IND")
                case "CM_MNBC_SOUND_IND":
                    self.messagesSentRecieved["CM_MNBC_SOUND_IND"]["recieved"] += 1
                    if pkt[CM_MNBC_SOUND_IND].Countdown != 0:
                        return
                    logging.info("Recieved CM_MNBC_SOUND_IND")
                    self.sendPacket(AttenCharInd(self))
                    self.messagesSentRecieved["CM_ATTEN_CHAR_IND"]["sent"] += 1
                    logging.info("Sent CM_ATTEN_CHAR_IND")
                case "CM_ATTEN_CHAR_IND":
                    self.messagesSentRecieved["CM_ATTEN_CHAR_IND"]["recieved"] += 1
                    logging.info("Recieved CM_ATTEN_CHAR_IND")
                    self.sendPacket(AttenCharRes(self))
                    self.messagesSentRecieved["CM_ATTEN_CHAR_RES"]["sent"] += 1
                    logging.info("Sent CM_ATTEN_CHAR_RES")
                    self.sendPacket(SlacMatchReq(self))
                    self.messagesSentRecieved["CM_SLAC_MATCH_REQ"]["sent"] += 1
                    logging.info("Sent CM_SLAC_MATCH_REQ")
                case "CM_SLAC_MATCH_REQ":
                    self.messagesSentRecieved["CM_SLAC_MATCH_REQ"]["recieved"] += 1
                    logging.info("Recieved CM_SLAC_MATCH_REQ")
                    self.sendPacket(SlacMatchCnf(self))
                    self.messagesSentRecieved["CM_SLAC_MATCH_CNF"]["sent"] += 1
                    logging.info("Sent CM_SLAC_MATCH_CNF")
                case "CM_SLAC_MATCH_CNF":
                    self.messagesSentRecieved["CM_SLAC_MATCH_CNF"]["recieved"] += 1
                    logging.info("Recieved CM_SLAC_MATCH_CNF")
                    self.NID = pkt[CM_SLAC_MATCH_CNF].VariableField.NetworkID
                    self.NMK = pkt[CM_SLAC_MATCH_CNF].VariableField.NMK
                    self.sendPacket(SetKeyReq(self))
                    self.messagesSentRecieved["SET_KEY_REQ"]["sent"] += 1
                    logging.info("Sent SET_KEY_REQ")
                    time.sleep(3)
                    SECCpkts = [SECCRequest(self) for i in range(3)]
                    self.sendPacket(SECCpkts)
                    self.messagesSentRecieved["SECC_RequestMessage"]["sent"] += 3
                    logging.info("Sent 3 SECC_RequestMessage")
            
        # Handle SECC Packets
        elif pkt.haslayer("SECC"):
            SECCtype = self.expandPacketLayers(pkt)[4]
            match SECCtype:
                case "SECC_RequestMessage":
                    self.messagesSentRecieved["SECC_RequestMessage"]["recieved"] += 1
                    logging.info("Recieved SECC_RequestMessage")
                    self.destinationIP = pkt[IPv6].src
                    self.destinationPort = pkt[UDP].sport
                    responsePkts = [SECCResponse(self) for i in range(3)]
                    self.sendPacket(responsePkts)
                    self.messagesSentRecieved["SECC_ResponseMessage"]["sent"] += 3
                    logging.debug(f"SECC Destination IP: {self.destinationIP}")
                    logging.debug(f"SECC Destination Port: {self.destinationPort}")
                    logging.info("Sent 3 SECC_ResponseMessage")
                case "SECC_ResponseMessage":
                    self.messagesSentRecieved["SECC_ResponseMessage"]["recieved"] += 1
                    logging.info("Recieved SECC_ResponseMessage")
                    self.destinationIP = pkt[SECC_ResponseMessage].TargetAddress
                    self.destinationPort = pkt[SECC_ResponseMessage].TargetPort
                    self.sendPacket(SYN(self))
                    self.messagesSentRecieved["SYN"]["sent"] += 1
                    logging.debug(f"SECC Destination IP: {self.destinationIP}")
                    logging.debug(f"SECC Destination Port: {self.destinationPort}")
                    logging.info("Sent TCP SYN")
        
        # Handle IPv6/TCP packets
        elif pkt.haslayer("IPv6") and pkt.haslayer("TCP") and pkt[TCP].dport == self.sourcePort and pkt[IPv6].dst == self.sourceIP:
            self.seq = pkt[TCP].ack
            self.ack = pkt[TCP].seq + len(pkt[TCP].payload)

            if pkt.flags and pkt.flags == "S":
                logging.info("Recieved TCP SYN")
                self.messagesSentRecieved["SYN"]["recieved"] += 1
                self.destinationMAC = pkt[Ether].src
                self.destinationIP = pkt[IPv6].src
                self.destinationPort = pkt[TCP].sport
                self.ack = self.ack + 1
                self.sendPacket(SYNACK(self))
                self.messagesSentRecieved["SYNACK"]["sent"] += 1
                logging.info("Sent TCP SYN-ACK")
            if pkt.flags and pkt.flags == "SA":
                self.messagesSentRecieved["SYNACK"]["recieved"] += 1
                logging.info("Recieved TCP SYN-ACK")
                self.sendPacket(ACK(self))
                logging.info("Sent TCP ACK")
                self.sendPacket(V2G(self, self.appHandshake.encode(SupportedAppProtocolRequest())))
                self.messagesSentRecieved["supportedAppProtocolReq"]["sent"] += 1
                logging.info("Sent SupportedAppProtocolReq")
            if pkt.flags and pkt.flags == "F":
                self.messagesSentRecieved["FIN"]["recieved"] += 1
                logging.info("Recieved TCP FIN")
                self.sendPacket(FINACK(self))
                logging.info("Sent TCP FIN-ACK")
                self.killall()
            if pkt.flags and "P" in pkt.flags:
                exiString = V2GTP(pkt[Raw].load).Payload

                # First check if the AppHandshake is complete
                if not self.appHandshakeComplete:
                    xmlJson = self.appHandshake.decode(exiString)
                    pktName = list(xmlJson.keys())[0]
                    
                    if pktName == "supportedAppProtocolReq":
                        self.messagesSentRecieved["supportedAppProtocolReq"]["recieved"] += 1
                        logging.info("Recieved SupportedAppProtocolReq")
                        self.appHandshakeComplete = True
                        self.sendPacket(V2G(self, self.appHandshake.encode(SupportedAppProtocolResponse())))
                        self.messagesSentRecieved["supportedAppProtocolRes"]["sent"] += 1
                        logging.info("Sent SupportedAppProtocolRes")
                    elif pktName == "supportedAppProtocolRes":
                        self.messagesSentRecieved["supportedAppProtocolRes"]["recieved"] += 1
                        logging.info("Recieved SupportedAppProtocolRes")
                        self.appHandshakeComplete = True
                        self.sendPacket(V2G(self, self.din.encode(SessionSetupRequest())))
                        self.messagesSentRecieved["SessionSetupReq"]["sent"] += 1
                        logging.info("Sent SessionSetupReq")
                else:
                    xmlJson = self.din.decode((exiString))
                    pktName = list(xmlJson["Body"].keys())[0]
                    Header = xmlJson["Header"]
                    if "bytes" in Header["SessionID"]:
                        sessionID = bytearray(Header["SessionID"]["bytes"])
                    else:
                        sessionID = "00"

                    if self.sessionActive and not self.sessionID == sessionID:
                        logging.warning(f"Recieved V2G Message {pktName} with SessionID: {sessionID} vs current SessionID: {self.sessionID}")
                        logging.debug(f"XML: {xmlJson}")
                        return

                    Body = xmlJson["Body"]
                    if not len(Body) == 1:
                        logging.warning("Recieved invalid V2G Message")
                        logging.warning(f"XML Json: {xmlJson}")
                        return

                    match pktName:
                        case "SessionSetupReq":
                            self.messagesSentRecieved["SessionSetupReq"]["recieved"] += 1
                            logging.info("Recieved SessionSetupReq")
                            self.sessionID = bytearray(random.randbytes(8))
                            self.sessionActive = True
                            logging.debug(f"Setting SessionID: {self.sessionID}")
                            self.sendPacket(V2G(self, self.din.encode(SessionSetupResponse(sessionID=self.sessionID))))
                            self.messagesSentRecieved["SessionSetupRes"]["sent"] += 1
                            logging.info("Sent SessionSetupRes")
                        case "SessionSetupRes":
                            self.messagesSentRecieved["SessionSetupRes"]["recieved"] += 1
                            logging.info("Recieved SessionSetupRes")
                            self.sessionID = sessionID
                            self.sessionActive = True
                            logging.debug(f"Setting SessionID: {sessionID}")
                            self.sendPacket(V2G(self, self.din.encode(ServiceDiscoveryRequest(sessionID=self.sessionID))))
                            self.messagesSentRecieved["ServiceDiscoveryReq"]["sent"] += 1
                            logging.info("Sent ServiceDiscoveryReq")
                        case "ServiceDiscoveryReq":
                            self.messagesSentRecieved["ServiceDiscoveryReq"]["recieved"] += 1
                            logging.info("Recieved ServiceDiscoveryReq")
                            self.sendPacket(V2G(self, self.din.encode(ServiceDiscoveryResponse(sessionID=self.sessionID))))
                            self.messagesSentRecieved["ServiceDiscoveryRes"]["sent"] += 1
                            logging.info("Sent ServiceDiscoveryRes")
                        case "ServiceDiscoveryRes":
                            self.messagesSentRecieved["ServiceDiscoveryRes"]["recieved"] += 1
                            logging.info("Recieved ServiceDiscoveryRes")
                            self.sendPacket(V2G(self, self.din.encode(ServicePaymentSelectionRequest(sessionID=self.sessionID))))
                            self.messagesSentRecieved["ServicePaymentSelectionReq"]["sent"] += 1
                            logging.info("Sent ServicePaymentSelectionReq")
                        case "ServicePaymentSelectionReq":
                            self.messagesSentRecieved["ServicePaymentSelectionReq"]["recieved"] += 1
                            logging.info("Recieved ServicePaymentSelectionReq")
                            self.sendPacket(V2G(self, self.din.encode(ServicePaymentSelectionResponse(sessionID=self.sessionID))))
                            self.messagesSentRecieved["ServicePaymentSelectionRes"]["sent"] += 1
                            logging.info("Sent ServicePaymentSelectionRes")
                        case "ServicePaymentSelectionRes":
                            self.messagesSentRecieved["ServicePaymentSelectionRes"]["recieved"] += 1
                            logging.info("Recieved ServicePaymentSelectionRes")
                            self.sendPacket(V2G(self, self.din.encode(ContractAuthenticationRequest(sessionID=self.sessionID))))
                            self.messagesSentRecieved["ContractAuthenticationReq"]["sent"] += 1
                            logging.info("Sent ContractAuthenticationReq")
                        case "ContractAuthenticationReq":
                            self.messagesSentRecieved["ContractAuthenticationReq"]["recieved"] += 1
                            logging.info("Recieved ContractAuthenticationReq")
                            # TODO: implement scanning mode
                            if self.mode == RunMode.STALL:
                                evseProcessing = "Ongoing"
                            elif self.mode == RunMode.FULL:
                                evseProcessing = "Finished"
                            elif self.mode == RunMode.SCAN:
                                evseProcessing = "Ongoing"
                                if not self.scanning:
                                    logging.info("Starting Port Scanner")
                                    self.scanning = True
                                    self.scanner.start()
                            else:
                                logging.warning(f"RunMode not supported: {self.mode}")
                            self.sendPacket(V2G(self, self.din.encode(ContractAuthenticationResponse(sessionID=self.sessionID, evseProcessing=evseProcessing))))
                            if evseProcessing == "Ongoing":
                                self.messagesSentRecieved["ContractAuthenticationRes:Ongoing"]["sent"] += 1
                                if self.messagesSentRecieved["ContractAuthenticationRes:Ongoing"]["sent"] == 0:
                                    logging.info("Sent ContractAuthenticationRes -- Ongoing")
                            else:
                                self.messagesSentRecieved["ContractAuthenticationRes:Finished"]["sent"] += 1
                                logging.info("Sent ContractAuthenticationRes -- Finished")
                        case "ContractAuthenticationRes":
                            logging.info("Recieved ContractAuthenticationRes")
                            evseProcessing = Body["ContractAuthenticationRes"]["EVSEProcessing"]
                            if evseProcessing == EVSEProcessingMap.get("Ongoing", 1):
                                self.messagesSentRecieved["ContractAuthenticationRes:Ongoing"]["recieved"] += 1
                                if self.messagesSentRecieved["ContractAuthenticationRes:Ongoing"]["recieved"] == 0:
                                    logging.info("Recieved ContractAuthenticationRes -- Ongoing")
                                self.sendPacket(V2G(self, self.din.encode(ContractAuthenticationRequest(sessionID=self.sessionID))))
                                self.messagesSentRecieved["ContractAuthenticationReq"]["sent"] += 1
                                if self.messagesSentRecieved["ContractAuthenticationReq"]["sent"] == 0:
                                    logging.info("Sent ContractAuthenticationReq -- Ongoing")
                            elif evseProcessing == EVSEProcessingMap.get("Finished", 0):
                                self.messagesSentRecieved["ContractAuthenticationRes:Finished"]["recieved"] += 1
                                logging.info("Recieved ContractAuthenticationRes -- Finished")
                                self.sendPacket(V2G(self, self.din.encode(ChargeParameterDiscoveryRequest(sessionID=self.sessionID))))
                                self.messagesSentRecieved["ChargeParameterDiscoveryReq"]["sent"] += 1
                                logging.info("Sent ChargeParameterDiscoveryReq")
                        case "ChargeParameterDiscoveryReq":
                            self.messagesSentRecieved["ChargeParameterDiscoveryReq"]["recieved"] += 1
                            logging.info("Recieved ChargeParameterDiscoveryReq")
                            self.sendPacket(V2G(self, self.din.encode(ChargeParameterDiscoveryResponse(sessionID=self.sessionID))))
                            self.messagesSentRecieved["ChargeParameterDiscoveryRes:Finished"]["sent"] += 1
                            logging.info("Sent ChargeParameterDiscoveryRes -- Finished")
                        case "ChargeParameterDiscoveryRes":
                            evseProcessing = Body["ChargeParameterDiscoveryRes"]["EVSEProcessing"]
                            if evseProcessing == EVSEProcessingMap.get("Ongoing", 1):
                                self.messagesSentRecieved["ChargeParameterDiscoveryRes:Ongoing"]["recieved"] += 1
                                logging.info("Recieved ChargeParameterDiscoveryRes -- Ongoing")
                                self.sendPacket(V2G(self, self.din.encode(ChargeParameterDiscoveryRequest(sessionID=self.sessionID))))
                                self.messagesSentRecieved["ChargeParameterDiscoveryReq"]["sent"] += 1
                                if self.messagesSentRecieved["ChargeParameterDiscoveryReq"]["sent"] == 0:
                                    logging.info("Sent ChargeParameterDiscoveryReq")
                            elif evseProcessing == EVSEProcessingMap.get("Finished", 0):
                                self.messagesSentRecieved["ChargeParameterDiscoveryRes:Finished"]["recieved"] += 1
                                logging.info("Recieved ChargeParameterDiscoveryRes -- Finished")
                                self.setState(EmulatorState.C)
                                self.sendPacket(V2G(self, self.din.encode(CableCheckRequest(sessionID=self.sessionID))))
                                self.messagesSentRecieved["CableCheckReq"]["sent"] += 1
                                logging.info("Sent CableCheckReq")
                            else:
                                logging.warning("Unexpected EVSEProcessing status")
                                logging.warning(f"EVSEProcessing: {evseProcessing}")
                                logging.warning(f"XML: {xmlJson}")
                        case "CableCheckReq":
                            self.messagesSentRecieved["CableCheckReq"]["recieved"] += 1
                            logging.info("Recieved CableCheckReq")
                            self.sendPacket(V2G(self, self.din.encode(CableCheckResponse(sessionID=self.sessionID))))
                            self.messagesSentRecieved["CableCheckRes:Finished"]["sent"] += 1
                            logging.info("Sent CableCheckRes")
                        case "CableCheckRes":
                            evseProcessing = Body["CableCheckRes"]["EVSEProcessing"]
                            if evseProcessing == EVSEProcessingMap.get("Ongoing", 1):
                                self.messagesSentRecieved["CableCheckRes:Ongoing"]["recieved"] += 1
                                if self.messagesSentRecieved["CableCheckRes:Ongoing"]["recieved"] == 0:
                                    logging.info("Sent CableCheckRes -- Ongoing")
                                self.sendPacket(V2G(self, self.din.encode(CableCheckRequest(sessionID=self.sessionID))))
                                self.messagesSentRecieved["CableCheckReq"]["sent"] += 1
                                if self.messagesSentRecieved["CableCheckReq"]["sent"] == 0:
                                    logging.info("Sent CableCheckReq -- Ongoing")
                            elif evseProcessing == EVSEProcessingMap.get("Finished", 0):
                                self.messagesSentRecieved["CableCheckRes:Finished"]["recieved"] += 1
                                logging.info("Recieved CableCheckRes -- Finished")
                                self.sendPacket(V2G(self, self.din.encode(PreChargeRequest(sessionID=self.sessionID))))
                                self.messagesSentRecieved["PreChargeReq"]["sent"] += 1
                                logging.info("Sent PreChargeReq")
                            else:
                                logging.warning("Unexpected EVSEProcessing status")
                                logging.warning(f"EVSEProcessing: {evseProcessing}")
                                logging.warning(f"XML: {xmlJson}")
                        case "PreChargeReq":
                            self.messagesSentRecieved["PreChargeReq"]["recieved"] += 1
                            logging.info("Recieved PreChargeReq")
                            self.sendPacket(V2G(self, self.din.encode(PreChargeResponse(sessionID=self.sessionID))))
                            self.messagesSentRecieved["PreChargeRes"]["sent"] += 1
                            logging.info("Sent PreChargeRes")
                        case "PreChargeRes":
                            self.messagesSentRecieved["PreChargeRes"]["recieved"] += 1
                            logging.info("Recieved PreChargeRes")
                            self.sendPacket(V2G(self, self.din.encode(PowerDeliveryRequest(sessionID=self.sessionID))))
                            self.messagesSentRecieved["PowerDeliveryReq"]["sent"] += 1
                            logging.info("Sent PowerDeliveryReq")
                        case "PowerDeliveryReq":
                            self.messagesSentRecieved["PowerDeliveryReq"]["recieved"] += 1
                            logging.info("Recieved PowerDeliveryReq")
                            self.sendPacket(V2G(self, self.din.encode(PowerDeliveryResponse(sessionID=self.sessionID))))
                            self.messagesSentRecieved["PowerDeliveryRes"]["sent"] += 1
                            logging.info("Sent PowerDeliveryRes")
                        case "PowerDeliveryRes":
                            self.messagesSentRecieved["PowerDeliveryRes"]["recieved"] += 1
                            logging.info("Recieved PowerDeliveryRes")
                            self.sendPacket(V2G(self, self.din.encode(CurrentDemandRequest(sessionID=self.sessionID))))
                            self.messagesSentRecieved["CurrentDemandReq"]["sent"] += 1
                            logging.info("Sent CurrentDemandReq")
                        case "CurrentDemandReq":
                            self.messagesSentRecieved["CurrentDemandReq"]["recieved"] += 1
                            reportedSOC = Body["CurrentDemandReq"]["DC_EVStatus"]["EVRESSSOC"]
                            requestedCurrent = Body["CurrentDemandReq"]["EVTargetCurrent"]["Value"] * 10 ** Body["CurrentDemandReq"]["EVTargetCurrent"]["Multiplier"]
                            requestedVoltage = Body["CurrentDemandReq"]["EVTargetVoltage"]["Value"] * 10 ** Body["CurrentDemandReq"]["EVTargetVoltage"]["Multiplier"]
                            logging.info(f"Recieved CurrentDemandReq -- SOC:{reportedSOC} | Current:{requestedCurrent} | Voltage:{requestedVoltage}")
                            self.sendPacket(V2G(self, self.din.encode(CurrentDemandResponse(sessionID=self.sessionID))))
                            self.messagesSentRecieved["CurrentDemandRes"]["sent"] += 1
                            logging.info("Sent CurrentDemandRes")
                        case "CurrentDemandRes":
                            self.messagesSentRecieved["CurrentDemandRes"]["recieved"] += 1
                            reportedCurrent = Body["CurrentDemandRes"]["EVSEPresentCurrent"]["Value"] * 10 ** Body["CurrentDemandRes"]["EVSEPresentCurrent"]["Multiplier"]
                            reportedVoltage = Body["CurrentDemandRes"]["EVSEPresentVoltage"]["Value"] * 10 ** Body["CurrentDemandRes"]["EVSEPresentVoltage"]["Multiplier"]
                            logging.info(f"Recieved CurrentDemandRes -- Current:{reportedCurrent} | Voltage:{reportedVoltage}")
                            self.sendPacket(V2G(self, self.din.encode(CurrentDemandRequest(sessionID=self.sessionID))))
                            self.messagesSentRecieved["CurrentDemandReq"]["sent"] += 1
                            logging.info("Sent CurrentDemandReq")
                        case "SessionStopReq":
                            self.messagesSentRecieved["SessionStopReq"]["recieved"] += 1
                            logging.info("Recieved SessionStopReq")
                            self.sendPacket(V2G(self, self.din.encode(SessionStopResponse(sessionID=self.sessionID))))
                            self.messagesSentRecieved["SessionStopRes"]["sent"] += 1
                            logging.info("Sent SessionStopRes")
                            self.killall()
                        case _:
                            logging.warning("Unsuppored V2G Packet Recieved")
                            logging.warning(f"XML: {xmlJson}")

        # Handle advertisment packets
        elif pkt.haslayer("ICMPv6ND_NS") and pkt[ICMPv6ND_NS].tgt == self.sourceIP:
            logging.info("Recieved ICMPv6 Neighbor Solicitation")
            self.sendPacket(NeighborAdvertisement(self))
            logging.info("Sent ICMPv6 Neighbor Advertisement")

        else:
            # Dont update message time if packet is not for this emulator
            return
        
        self.lastMessageTime = time.time()
    
    def killall(self):
        self.running = False
        self.sniffingThread.stop()
        self.timeoutThread.stop()
        self.bus.write_byte_data(self.I2C_ADDR, self.I2C_REG, self.I2C_ALL_OFF)
        logging.info("Emulator Stopped")

    def sendPacket(self, pkt):
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
                time.sleep(3)
                self.setState(EmulatorState.B)

                self.resetMessagesSentRecieved()

                if self.emulatorType == EmulatorType.PEV:
                    self.sendPacket(SlacParmReq(self))
                    self.messagesSentRecieved["CM_SLAC_PARM_REQ"]["sent"] += 1
                    logging.info("Sent CM_SLAC_PARM_REQ")

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