"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
    
    This class is used to emulate a EVSE when talking to an PEV. Handles level 2 SLAC communications
    and level 3 UDP and TCP communications to the electric vehicle.
"""

# need to do this to import the custom SECC and V2G scapy layer
import sys, os

sys.path.append("./external_libs/HomePlugPWN")
sys.path.append("./external_libs/V2GInjector/core")

from EmulatorEnum import *
from EXIProcessor import EXIProcessor
from XMLBuilder import XMLBuilder
from Packets import *
from V2GXML import *

import xml.etree.ElementTree as ET
from threading import Thread
import random
import argparse
import logging
import time
import binascii

class Emulator:
    def __init__(self, args):
        self.emulatorType = EmulatorType(args.type[0]) if args.type else EmulatorType.EVSE

        self.mode = RunMode(args.mode[0]) if args.mode else RunMode.FULL
        self.protocol = EXIProtocol(args.protocol[0].upper()) if args.protocol else EXIProtocol.DIN
        self.modified_cordset = True if args.modified_cordset else False
        self.virtual = True if args.virtual else False
        # TODO: add timeout cmd arg
        self.timeout = 10
        self.running = True

        if self.emulatorType == EmulatorType.EVSE:
            self.iface = args.interface[0] if args.interface else "ethevse"
            self.sourceMAC = args.source_mac[0] if args.source_mac else "00:1e:c0:f2:6c:a0"
            self.sourceIP = args.source_ip[0] if args.source_ip else "fe80::21e:c0ff:fef2:6ca0"
            self.sourcePort = args.source_port[0] if args.source_port else 25565
            self.NID = args.NID[0] if args.NID else b"\x9c\xb0\xb2\xbb\xf5\x6c\x0e"
            self.NMK = args.NMK[0] if args.NMK else b"\x48\xfe\x56\x02\xdb\xac\xcd\xe5\x1e\xda\xdc\x3e\x08\x1a\x52\xd1"
        else:
            self.iface = args.interface[0] if args.interface else "eth0"
            self.sourceMAC = args.source_mac[0] if args.source_mac else "00:1e:c0:f2:6c:a1"
            self.sourceIP = args.source_ip[0] if args.source_ip else "fe80::21e:c0ff:fef2:6ca1"
            self.sourcePort = args.source_port[0] if args.source_port else random.randint(1025, 65534)
            self.runID = os.urandom(8)

        self.destinationMAC = None
        self.destinationIP = None
        self.destinationPort = None

        self.seq = 10000
        self.ack = 0
        self.sessionID = "00"
        self.sessionActive = False

        self.exi = EXIProcessor(self.protocol)

        print(self.virtual)

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
            level=logging.INFO,
            format=f"%(asctime)s.%(msecs)03d | %(levelname)-7s | {self.emulatorType.value.upper():<4} -- %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        logging.info("Emulator Initialized")

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
|                                                             __/ |                                 |
|                                                            |___/                                  |
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
                    logging.info("Recieved CM_SLAC_PARM_REQ")
                    self.destinationMAC = pkt[Ether].src
                    self.runID = pkt[CM_SLAC_PARM_REQ].RunID
                    self.sendPacket(SlacParmCnf(self))
                    logging.info("Sent CM_SLAC_PARM_CNF")
                case "CM_SLAC_PARM_CNF":
                    logging.info("Recieved CM_SLAC_PARM_CNF")
                    self.destinationMAC = pkt[Ether].src
                    self.remainingSounds = 10
                    startSoundPkts = [StartAttenCharInd(self) for i in range(3)]
                    soundPkts = [MNBCSoundInd(self) for i in range(10)]
                    self.sendPacket(startSoundPkts)
                    logging.info("Sent 3 START_ATTEN_CHAR_IND")
                    self.sendPacket(soundPkts)
                    logging.info("Sent 10 MNBC_SOUND_IND")
                case "CM_MNBC_SOUND_IND":
                    if pkt[CM_MNBC_SOUND_IND].Countdown != 0:
                        return
                    logging.info("Recieved CM_MNBC_SOUND_IND")
                    self.sendPacket(AttenCharInd(self))
                    logging.info("Sent CM_ATTEN_CHAR_IND")
                case "CM_ATTEN_CHAR_IND":
                    logging.info("Recieved CM_ATTEN_CHAR_IND")
                    self.sendPacket(AttenCharRes(self))
                    logging.info("Sent CM_ATTEN_CHAR_RES")
                    self.sendPacket(SlacMatchReq(self))
                    logging.info("Sent CM_SLAC_MATCH_REQ")
                case "CM_SLAC_MATCH_REQ":
                    logging.info("Recieved CM_SLAC_MATCH_REQ")
                    self.sendPacket(SlacMatchCnf(self))
                    logging.info("Sent CM_SLAC_MATCH_CNF")
                case "CM_SLAC_MATCH_CNF":
                    logging.info("Recieved CM_SLAC_MATCH_CNF")
                    self.NID = pkt[CM_SLAC_MATCH_CNF].VariableField.NetworkID
                    self.NMK = pkt[CM_SLAC_MATCH_CNF].VariableField.NMK
                    self.sendPacket(SetKeyReq(self))
                    logging.info("Sent SET_KEY_REQ")
                    time.sleep(3)
                    SECCpkts = [SECCRequest(self) for i in range(3)]
                    self.sendPacket(SECCpkts)
                    logging.info("Sent 3 SECC_RequestMessage")
            
        # Handle SECC Packets
        elif pkt.haslayer("SECC"):
            SECCtype = self.expandPacketLayers(pkt)[4]
            match SECCtype:
                case "SECC_RequestMessage":
                    logging.info("Recieved SECC_RequestMessage")
                    self.destinationIP = pkt[IPv6].src
                    self.destinationPort = pkt[UDP].sport
                    responsePkts = [SECCResponse(self) for i in range(3)]
                    self.sendPacket(responsePkts)
                    logging.info("Sent 3 SECC_ResponseMessage")
                case "SECC_ResponseMessage":
                    logging.info("Recieved SECC_ResponseMessage")
                    self.destinationIP = pkt[SECC_ResponseMessage].TargetAddress
                    self.destinationPort = pkt[SECC_ResponseMessage].TargetPort
                    self.sendPacket(SYN(self))
                    logging.info("Sent TCP SYN")
        
        # Handle IPv6/TCP packets
        elif pkt.haslayer("IPv6") and pkt.haslayer("TCP") and pkt[TCP].sport == self.destinationPort and pkt[TCP].dport == self.sourcePort:
            self.seq = pkt[TCP].ack
            self.ack = pkt[TCP].seq + len(pkt[TCP].payload)

            if pkt.flags and pkt.flags == "S":
                logging.info("Recieved TCP SYN")
                self.destinationMAC = pkt[Ether].src
                self.destinationIP = pkt[IPv6].src
                self.destinationPort = pkt[TCP].sport
                self.sendPacket(SYNACK(self))
                logging.info("Sent TCP SYN-ACK")
            if pkt.flags and pkt.flags == "SA":
                logging.info("Recieved TCP SYN-ACK")
                self.sendPacket(ACK(self))
                logging.info("Sent TCP ACK")
                self.sendPacket(V2G(self, self.exi.encode(SupportedAppProtocolRequest())))
                logging.info("Sent SupportedAppProtocolReq")
            if pkt.flags and pkt.flags == "F":
                logging.info("Recieved TCP FIN")
                self.sendPacket(FINACK(self))
                logging.info("Sent TCP FIN-ACK")
                self.killall()
            if pkt.flags and "P" in pkt.flags:
                # print(V2GTP(pkt[Raw].load).Payload)
                exiString = V2GTP(pkt[Raw].load).Payload
                xmlString = self.exi.decode(exiString)
                root = ET.fromstring(xmlString)

                if "supportedAppProtocolReq" in root.tag:
                    logging.info("Recieved SupportedAppProtocolReq")
                    self.sendPacket(V2G(self, self.exi.encode(SupportedAppProtocolResponse())))
                    logging.info("Sent SupportedAppProtocolRes")
                elif "supportedAppProtocolRes" in root.tag:
                    logging.info("Recieved SupportedAppProtocolRes")
                    self.sendPacket(V2G(self, self.exi.encode(SessionSetupRequest())))
                    logging.info("Sent SessionSetupReq")
                else:
                    Header = root.find("{urn:din:70121:2012:MsgDef}Header")
                    SessionID = Header.find("{urn:din:70121:2012:MsgHeader}SessionID").text

                    if self.sessionActive and not self.sessionID == SessionID:
                        return

                    Body = root.find("{urn:din:70121:2012:MsgDef}Body")
                    if not len(Body) == 1:
                        logging.warning("Recieved invalid V2G Message")
                        logging.warning(f"XML: {xmlString}")
                        return
                    pktName = Body[0].tag.split("}")[1]

                    match pktName:
                        case "SessionSetupReq":
                            logging.info("Recieved SessionSetupReq")
                            self.sessionActive = True
                            self.sendPacket(V2G(self, self.exi.encode(SessionSetupResponse())))
                            logging.info("Sent SessionSetupRes")
                        case "SessionSetupRes":
                            logging.info("Recieved SessionSetupRes")
                            self.SessionID = SessionID
                            self.sessionActive = True
                            self.sendPacket(V2G(self, self.exi.encode(ServiceDiscoveryRequest(sessionID=self.sessionID))))
                            logging.info("Sent ServiceDiscoveryReq")
                        case "ServiceDiscoveryReq":
                            logging.info("Recieved ServiceDiscoveryReq")
                            self.sendPacket(V2G(self, self.exi.encode(ServiceDiscoveryResponse(sessionID=self.sessionID))))
                            logging.info("Sent ServiceDiscoveryRes")
                        case "ServiceDiscoveryRes":
                            logging.info("Recieved ServiceDiscoveryRes")
                            self.sendPacket(V2G(self, self.exi.encode(ServicePaymentSelectionRequest(sessionID=self.sessionID))))
                            logging.info("Sent ServicePaymentSelectionReq")
                        case "ServicePaymentSelectionReq":
                            logging.info("Recieved ServicePaymentSelectionReq")
                            self.sendPacket(V2G(self, self.exi.encode(ServicePaymentSelectionResponse(sessionID=self.sessionID))))
                            logging.info("Sent ServicePaymentSelectionRes")
                        case "ServicePaymentSelectionRes":
                            logging.info("Recieved ServicePaymentSelectionRes")
                            self.sendPacket(V2G(self, self.exi.encode(ContractAuthenticationRequest(sessionID=self.sessionID))))
                            logging.info("Sent ContractAuthenticationReq")
                        case "ContractAuthenticationReq":
                            logging.info("Recieved ContractAuthenticationReq")
                            # TODO: implement scanning mode
                            if self.mode == RunMode.STALL:
                                evseProcessing = "Ongoing"
                            elif self.mode == RunMode.FULL:
                                evseProcessing = "Finished"
                            else:
                                logging.warning(f"RunMode not supported: {self.mode}")
                            self.sendPacket(V2G(self, self.exi.encode(ContractAuthenticationResponse(sessionID=self.sessionID, evseProcessing=evseProcessing))))
                            logging.info("Sent ContractAuthenticationRes")
                        case "ContractAuthenticationRes":
                            logging.info("Recieved ContractAuthenticationRes")
                            self.sendPacket(V2G(self, self.exi.encode(ChargeParameterDiscoveryRequest(sessionID=self.sessionID))))
                            logging.info("Sent ChargeParameterDiscoveryReq")
                        case "ChargeParameterDiscoveryReq":
                            logging.info("Recieved ChargeParameterDiscoveryReq")
                            self.sendPacket(V2G(self, self.exi.encode(ChargeParameterDiscoveryResponse(sessionID=self.sessionID))))
                            logging.info("Sent ChargeParameterDiscoveryRes")
                        case "ChargeParameterDiscoveryRes":
                            logging.info("Recieved ChargeParameterDiscoveryRes")
                            evseProcessing = Body.find("{urn:din:70121:2012:MsgBody}ChargeParameterDiscoveryRes/{urn:din:70121:2012:MsgBody}EVSEProcessing").text
                            if evseProcessing == "Ongoing":
                                self.sendPacket(V2G(self, self.exi.encode(ContractAuthenticationRequest(sessionID=self.sessionID))))
                                logging.info("Sent ContractAuthenticationReq")
                            elif evseProcessing == "Finished":
                                self.setState(EmulatorState.C)
                                self.sendPacket(V2G(self, self.exi.encode(CableCheckRequest(sessionID=self.sessionID))))
                                logging.info("Sent CableCheckReq")
                            else:
                                logging.warning("Unexpected EVSEProcessing status")
                                logging.warning(f"EVSEProcessing: {evseProcessing}")
                                logging.warning(f"XML: {xmlString}")
                        case "CableCheckReq":
                            logging.info("Recieved CableCheckReq")
                            self.sendPacket(V2G(self, self.exi.encode(CableCheckResponse(sessionID=self.sessionID))))
                            logging.info("Sent CableCheckRes")
                        case "CableCheckRes":
                            evseProcessing = Body.find("{urn:din:70121:2012:MsgBody}CableCheckRes/{urn:din:70121:2012:MsgBody}EVSEProcessing").text
                            if evseProcessing == "Ongoing":
                                self.sendPacket(V2G(self, self.exi.encode(CableCheckRequest(sessionID=self.sessionID))))
                                logging.info("Sent CableCheckReq")
                            elif evseProcessing == "Finished":
                                self.sendPacket(V2G(self, self.exi.encode(PreChargeRequest(sessionID=self.sessionID))))
                                logging.info("Sent PreChargeReq")
                            else:
                                logging.warning("Unexpected EVSEProcessing status")
                                logging.warning(f"EVSEProcessing: {evseProcessing}")
                                logging.warning(f"XML: {xmlString}")
                        case "PreChargeReq":
                            logging.info("Recieved PreChargeReq")
                            self.sendPacket(V2G(self, self.exi.encode(PreChargeResponse(sessionID=self.sessionID))))
                            logging.info("Sent PreChargeRes")
                        case "PreChargeRes":
                            # TODO: do the precharge mumbo jumbo with serial controllers
                            logging.info("Recieved PreChargeRes")
                            self.sendPacket(V2G(self, self.exi.encode(PowerDeliveryRequest(sessionID=self.sessionID))))
                            logging.info("Sent PowerDeliveryReq")
                        case "PowerDeliveryReq":
                            logging.info("Recieved PowerDeliveryReq")
                            self.sendPacket(V2G(self, self.exi.encode(PowerDeliveryResponse(sessionID=self.sessionID))))
                            logging.info("Sent PowerDeliveryRes")
                        case "PowerDeliveryRes":
                            logging.info("Recieved PowerDeliveryRes")
                            self.sendPacket(V2G(self, self.exi.encode(CurrentDemandRequest(sessionID=self.sessionID))))
                            logging.info("Sent CurrentDemandReq")
                        case "CurrentDemandReq":
                            logging.info("Recieved CurrentDemandReq")
                            self.sendPacket(V2G(self, self.exi.encode(CurrentDemandResponse(sessionID=self.sessionID))))
                            logging.info("Sent CurrentDemandRes")
                        case "CurrentDemandRes":
                            logging.info("Recieved CurrentDemandRes")
                            self.sendPacket(V2G(self, self.exi.encode(CurrentDemandRequest(sessionID=self.sessionID))))
                            logging.info("Sent CurrentDemandReq")
                        case "SessionStopReq":
                            logging.info("Recieved SessionStopReq")
                            self.sendPacket(V2G(self, self.exi.encode(SessionStopResponse(sessionID=self.sessionID))))
                            logging.info("Sent SessionStopRes")
                            self.killall()
                        case _:
                            logging.warning("Unsuppored V2G Packet Recieved")
                            logging.warning(f"XML: {xmlString}")

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
                self.setState(EmulatorState.A)
                time.sleep(1)
                self.setState(EmulatorState.B)

                if self.emulatorType == EmulatorType.PEV:
                    self.sendPacket(SlacParmReq(self))
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

    args = parser.parse_args()

    emulator = Emulator(args)
    emulator.start()