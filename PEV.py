"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

    This class is used to emulate a PEV when talking to an EVSE. Handles level 2 SLAC communications
    and level 3 UDP and TCP communications to the charging station.
"""

# need to do this to import the custom SECC and V2G scapy layer
import sys, os

sys.path.append("./external_libs/HomePlugPWN")
sys.path.append("./external_libs/V2GInjector/core")

from threading import Thread

from layers.SECC import *
from layers.V2G import *
from layerscapy.HomePlugGP import *
from XMLBuilder import XMLBuilder
from EXIProcessor import EXIProcessor
from EmulatorEnum import *
from NMAPScanner import NMAPScanner
import xml.etree.ElementTree as ET
import binascii
import os.path
import random
from smbus import SMBus
import argparse


class PEV:

    def __init__(self, args):
        self.mode = RunMode(args.mode[0]) if args.mode else RunMode.FULL
        self.iface = args.interface[0] if args.interface else "eth1"
        self.sourceMAC = args.source_mac[0] if args.source_mac else "00:1e:c0:f2:6c:a1"
        self.sourceIP = args.source_ip[0] if args.source_ip else "fe80::21e:c0ff:fef2:6ca1"
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

        self.exi = EXIProcessor(self.protocol)

        self.slac = _SLACHandler(self)
        self.tcp = _TCPHandler(self)

        # I2C bus for relays
        self.bus = SMBus(1)

        # Constants for i2c controlled relays
        self.I2C_ADDR = 0x20
        self.CONTROL_REG = 0x9
        self.PEV_CP1 = 0b10
        self.PEV_CP2 = 0b100
        self.PEV_PP = 0b10000
        self.ALL_OFF = 0b0

    def start(self):
        # Initialize the smbus for I2C commands
        self.bus.write_byte_data(self.I2C_ADDR, 0x00, 0x00)

        self.toggleProximity()
        self.doSLAC()
        self.doTCP()
        # If NMAP is not done, restart connection
        if not self.tcp.finishedNMAP:
            print("INFO (PEV) : Attempting to restart connection...")
            self.start()

    def doTCP(self):
        self.tcp.start()
        print("INFO (PEV) : Done TCP")

    def doSLAC(self):
        print("INFO (PEV) : Starting SLAC")
        self.slac.start()
        self.slac.sniffThread.join()
        print("INFO (PEV) : Done SLAC")

    def closeProximity(self):
        self.setState(PEVState.B)

    def openProximity(self):
        self.setState(PEVState.A)

    def setState(self, state: PEVState):
        if state == PEVState.A:
            print("INFO (PEV) : Going to state A")
            self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.ALL_OFF)
        elif state == PEVState.B:
            print("INFO (PEV) : Going to state B")
            self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.PEV_PP | self.PEV_CP1)
        elif state == PEVState.C:
            print("INFO (PEV) : Going to state C")
            self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.PEV_PP | self.PEV_CP1 | self.PEV_CP2)

    def toggleProximity(self, t: int = 5):
        self.openProximity()
        time.sleep(t)
        self.closeProximity()


# This class handles the level 2 SLAC protocol communications and the SECC Request
class _SLACHandler:
    def __init__(self, pev: PEV):
        self.pev = pev
        self.iface = self.pev.iface
        self.sourceMAC = self.pev.sourceMAC
        self.sourceIP = self.pev.sourceIP
        self.runID = b"\xf4\x00\x37\xd0\x00\x5c\x00\x7f"

        self.timeSinceLastPkt = time.time()
        self.timeout = 8  # How long to wait for a message to timeout
        self.stop = False

    # This method starts the slac process and will stop
    def start(self):
        self.runID = os.urandom(8)
        self.stop = False
        # Thread for sniffing packets and handling responses
        # self.sniffThread = Thread(target=self.startSniff)
        # self.sniffThread.start()

        self.sniffThread = AsyncSniffer(iface=self.iface, prn=self.handlePacket, stop_filter=self.stopSniff)
        self.sniffThread.start()

        # Thread to determine if PEV timed out or SLAC error occured and restart SLAC process
        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()

        self.neighborSolicitationThread = AsyncSniffer(
            iface=self.iface, lfilter=lambda x: x.haslayer("ICMPv6ND_NS") and x[ICMPv6ND_NS].tgt == self.sourceIP, prn=self.sendNeighborSoliciation
        )
        self.neighborSolicitationThread.start()

    # The EVSE sometimes fails the SLAC process, so this automatically restarts it from the beginning
    def checkForTimeout(self):
        while self.stop == False:
            if time.time() - self.timeSinceLastPkt > self.timeout:
                print("INFO (PEV) : Timed out... Sending SLAC_PARM_REQ")
                sendp(self.buildSlacParmReq(), iface=self.iface, verbose=0)
                self.timeSinceLastPkt = time.time()

    def startSniff(self):
        sniff(iface=self.iface, prn=self.handlePacket, stop_filter=self.stopSniff)

    # Stop the thread when the slac match is done
    def stopSniff(self, pkt):
        if pkt.haslayer("SECC_ResponseMessage"):
            self.pev.destinationIP = pkt[SECC_ResponseMessage].TargetAddress
            self.pev.destinationPort = pkt[SECC_ResponseMessage].TargetPort
            if self.neighborSolicitationThread.running:
                self.neighborSolicitationThread.stop()
            return True
        return False

    def handlePacket(self, pkt):
        if pkt[Ether].type != 0x88E1 or pkt[Ether].src == self.sourceMAC:
            return

        if hasattr(pkt[1][2], "RunID") and pkt[1][2].RunID != self.runID:
            return

        if pkt.haslayer("CM_SLAC_PARM_CNF"):
            print("INFO (PEV) : Recieved SLAC_PARM_CNF")
            self.destinationMAC = pkt[Ether].src
            self.pev.destinationMAC = pkt[Ether].src
            self.numSounds = pkt[CM_SLAC_PARM_CNF].NumberMSounds
            self.numRemainingSounds = self.numSounds
            startSoundsPkts = [self.buildStartAttenCharInd() for i in range(3)]
            soundPkts = [self.buildMNBCSoundInd() for i in range(self.numSounds)]
            print("INFO (PEV) : Sending 3 START_ATTEN_CHAR_IND")
            sendp(startSoundsPkts, iface=self.iface, verbose=0, inter=0.05)
            print(f"INFO (PEV) : Sending {self.numSounds} MNBC_SOUND_IND")
            sendp(soundPkts, iface=self.iface, verbose=0, inter=0.05)
            # self.stopSounds = False
            # Thread(target=self.sendSounds).start()
            return

        if pkt.haslayer("CM_ATTEN_CHAR_IND"):
            self.stopSounds = True
            print("INFO (PEV) : Recieved ATTEN_CHAR_IND")
            print("INFO (PEV) : Sending ATTEN_CHAR_RES")
            sendp(self.buildAttenCharRes(), iface=self.iface, verbose=0)
            self.timeSinceLastPkt = time.time()
            print("INFO (PEV) : Sending SLAC_MATCH_REQ")
            sendp(self.buildSlacMatchReq(), iface=self.iface, verbose=0)
            self.timeSinceLastPkt = time.time()
            return

        if pkt.haslayer("CM_SLAC_MATCH_CNF"):
            print("INFO (PEV) : Recieved SLAC_MATCH_CNF")
            self.NID = pkt[CM_SLAC_MATCH_CNF].VariableField.NetworkID
            self.NMK = pkt[CM_SLAC_MATCH_CNF].VariableField.NMK
            print("INFO (PEV) : Sending SET_KEY_REQ")
            sendp(self.buildSetKeyReq(), iface=self.iface, verbose=0)
            self.stop = True
            Thread(target=self.sendSECCRequest).start()
            return

    def sendSECCRequest(self):
        time.sleep(3)
        print("INFO (PEV) : Sending 3 SECC_RequestMessage")
        for i in range(1):
            sendp(self.buildSECCRequest(), iface=self.iface, verbose=0)

    def sendSounds(self):
        self.numRemainingSounds = self.numSounds
        print("INFO (PEV) : Sending 3 START_ATTEN_CHAR_IND")
        for i in range(3):
            if self.stopSounds:
                return
            sendp(self.buildStartAttenCharInd(), iface=self.iface, verbose=0)
            self.timeSinceLastPkt = time.time()
        print(f"INFO (PEV) : Sending {self.numSounds} MNBC_SOUND_IND")
        soundPkts = [self.buildMNBCSoundInd() for i in range(self.numSounds)]
        sendp(soundPkts, iface=self.iface, verbose=0, inter=0.05)
        self.timeSinceLastPkt = time.time()
        # for i in range(self.numSounds):
        #     if self.stopSounds: return
        #     sendp(self.buildMNBCSoundInd(), iface=self.iface, verbose=0)
        #     self.timeSinceLastPkt = time.time()
        print("INFO (PEV) : Done sending sounds")

    def buildSlacParmReq(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "ff:ff:ff:ff:ff:ff"

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        homePlugLayer = CM_SLAC_PARM_REQ()
        homePlugLayer.RunID = self.runID

        pkt = ethLayer / homePlugAVLayer / homePlugLayer
        return pkt

    def buildStartAttenCharInd(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "ff:ff:ff:ff:ff:ff"

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        homePlugLayer = CM_START_ATTEN_CHAR_IND()
        homePlugLayer.NumberOfSounds = self.numSounds
        homePlugLayer.TimeOut = 0x06
        homePlugLayer.ResponseType = 0x01
        homePlugLayer.ForwardingSTA = self.sourceMAC
        homePlugLayer.RunID = self.runID

        pkt = ethLayer / homePlugAVLayer / homePlugLayer
        return pkt

    def buildMNBCSoundInd(self):
        self.numRemainingSounds = self.numRemainingSounds - 1

        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "ff:ff:ff:ff:ff:ff"

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        homePlugLayer = CM_MNBC_SOUND_IND()
        homePlugLayer.Countdown = self.numRemainingSounds
        homePlugLayer.RunID = self.runID
        homePlugLayer.RandomValue = os.urandom(16)

        pkt = ethLayer / homePlugAVLayer / homePlugLayer
        return pkt

    def buildAttenCharRes(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        homePlugLayer = CM_ATTEN_CHAR_RSP()
        homePlugLayer.SourceAdress = self.sourceMAC
        homePlugLayer.RunID = self.runID
        homePlugLayer.Result = 0x00

        pkt = ethLayer / homePlugAVLayer / homePlugLayer
        return pkt

    def buildSlacMatchReq(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        homePlugLayer = CM_SLAC_MATCH_REQ()
        homePlugLayer.MatchVariableFieldLen = 0x3E00

        slacVars = SLAC_varfield()
        slacVars.EVMAC = self.sourceMAC
        slacVars.EVSEMAC = self.destinationMAC
        slacVars.RunID = self.runID

        homePlugLayer.VariableField = slacVars

        pkt = ethLayer / homePlugAVLayer / homePlugLayer
        return pkt

    # This packet is proof that I'm not allowed to have a good time
    def buildSetKeyReq(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "00:b0:52:00:00:01"  # Some AtherosC MAC for whatever reason

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        homePlugLayer = CM_SET_KEY_REQ()
        homePlugLayer.KeyType = 0x1
        homePlugLayer.MyNonce = 0xAAAAAAAA
        homePlugLayer.YourNonce = 0x00000000
        homePlugLayer.PID = 0x4
        homePlugLayer.NetworkID = self.NID
        homePlugLayer.NewEncKeySelect = 0x1
        homePlugLayer.NewKey = self.NMK

        responsePacket = ethLayer / homePlugAVLayer / homePlugLayer
        return responsePacket

    def buildSECCRequest(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "33:33:00:00:00:01"

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = "ff02::1"
        ipLayer.hlim = 255

        udpLayer = UDP()
        udpLayer.sport = self.pev.sourcePort
        udpLayer.dport = 15118

        seccLayer = SECC()
        seccLayer.SECCType = 0x9000
        seccLayer.PayloadLen = 2

        seccRequestLayer = SECC_RequestMessage()
        seccRequestLayer.SecurityProtocol = 16
        seccRequestLayer.TransportProtocol = 0

        responsePacket = ethLayer / ipLayer / udpLayer / seccLayer / seccRequestLayer
        return responsePacket

    def buildNeighborAdvertisement(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = self.destinationIP
        ipLayer.plen = 32
        ipLayer.hlim = 255

        icmpLayer = ICMPv6ND_NA()
        icmpLayer.type = 136
        icmpLayer.R = 0
        icmpLayer.S = 1
        icmpLayer.tgt = self.sourceIP

        optLayer = ICMPv6NDOptDstLLAddr()
        optLayer.type = 2
        optLayer.len = 1
        optLayer.lladdr = self.sourceMAC

        responsePacket = ethLayer / ipLayer / icmpLayer / optLayer
        return responsePacket

    def sendNeighborSoliciation(self, pkt):
        # if self.stop: exit()
        # if not (pkt.haslayer("ICMPv6ND_NS") and pkt[ICMPv6ND_NS].tgt == self.sourceIP): return
        # self.destinationMAC = pkt[Ether].src
        self.destinationIP = pkt[IPv6].src
        # print("INFO (EVSE): Sending Neighor Advertisement")
        sendp(self.buildNeighborAdvertisement(), iface=self.iface, verbose=0)


class _TCPHandler:
    def __init__(self, pev: PEV):
        self.pev = pev
        self.iface = self.pev.iface

        self.sourceMAC = self.pev.sourceMAC
        self.sourceIP = self.pev.sourceIP
        self.sourcePort = self.pev.sourcePort

        self.destinationMAC = self.pev.destinationMAC
        self.destinationIP = self.pev.destinationIP
        self.destinationPort = self.pev.destinationPort

        self.seq = 10000
        self.ack = 0
        self.sessionID = "00"

        self.exi = self.pev.exi
        self.xml = XMLBuilder(self.exi)
        self.msgList = {}

        self.stop = False
        self.startSniff = False
        self.finishedNMAP = False
        self.lastPort = 0
        
        self.scanner = None

        self.timeout = 5

        self.soc = 10

    def start(self):
        self.msgList = {}
        self.running = True
        self.prechargeCount = 0
        print("INFO (PEV) : Starting TCP")

        # self.sendNeighborSolicitation()

        self.recvThread = AsyncSniffer(
            iface=self.iface,
            lfilter=lambda x: x.haslayer("TCP") and x[TCP].sport == self.destinationPort and x[TCP].dport == self.sourcePort,
            prn=self.handlePacket,
            started_callback=self.setStartSniff,
        )
        self.recvThread.start()

        self.handshakeThread = Thread(target=self.handshake)
        self.handshakeThread.start()

        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()

        self.neighborSolicitationThread = AsyncSniffer(
            iface=self.iface, lfilter=lambda x: x.haslayer("ICMPv6ND_NS") and x[ICMPv6ND_NS].tgt == self.sourceIP, prn=self.sendNeighborAdvertisement
        )
        self.neighborSolicitationThread.start()

        while self.running:
            time.sleep(1)

    def checkForTimeout(self):
        print("INFO (PEV) : Starting timeout thread")
        self.lastMessageTime = time.time()
        while True:
            # if self.stop: break
            if time.time() - self.lastMessageTime > self.timeout or self.running == False:
                print("INFO (PEV) : TCP timed out, resetting connection...")
                # self.reset()
                self.killThreads()
                break
            time.sleep(1)

    def killThreads(self):
        print("INFO (PEV) : Killing sniffing threads")
        if self.scanner != None:
            self.scanner.stop()
        self.running = False
        if self.recvThread.running:
            self.recvThread.stop()
        if self.neighborSolicitationThread.running:
            self.neighborSolicitationThread.stop()

    def recv(self):
        print("INFO (PEV) : Starting recv thread")
        sniff(
            iface=self.iface,
            lfilter=lambda x: x.haslayer("TCP") and x[TCP].sport == self.destinationPort and x[TCP].dport == self.sourcePort,
            prn=self.handlePacket,
            started_callback=self.setStartSniff,
        )

    def fin(self):
        print("INFO (PEV): Recieved FIN")
        self.running = False
        self.ack = self.ack + 1

        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = self.destinationIP

        tcpLayer = TCP()
        tcpLayer.sport = self.sourcePort
        tcpLayer.dport = self.destinationPort
        tcpLayer.flags = "A"
        tcpLayer.seq = self.seq
        tcpLayer.ack = self.ack

        ack = ethLayer / ipLayer / tcpLayer

        sendp(ack, iface=self.iface, verbose=0)

        tcpLayer.flags = "FA"

        finAck = ethLayer / ipLayer / tcpLayer

        print("INFO (PEV): Sending FINACK")

        sendp(finAck, iface=self.iface, verbose=0)

        # print("INFO (PEV) : Sending LEAVE_REQ")

        # sendp(self.buildLeaveReq(), iface=self.iface, verbose=0)

    def setStartSniff(self):
        self.startSniff = True

    def startSession(self):
        sendp(
            Ether(src=self.sourceMAC, dst=self.destinationMAC)
            / IPv6(src=self.sourceIP, dst=self.destinationIP)
            / TCP(sport=self.sourcePort, dport=self.destinationPort, flags="A", seq=self.seq, ack=self.ack + 1),
            iface=self.iface,
            verbose=0,
        )
        self.xml.SupportedAppProtocolRequest()
        exi = self.xml.getEXI()
        sendp(self.buildV2G(binascii.unhexlify(exi)), iface=self.iface, verbose=0)

    def handlePacket(self, pkt):
        self.last_recv = pkt
        self.seq = self.last_recv[TCP].ack
        self.ack = self.last_recv[TCP].seq + len(self.last_recv[TCP].payload)

        if self.last_recv.flags == 0x12:
            print("INFO (PEV) : Recieved SYNACK")
            self.startSession()
        if "F" in self.last_recv.flags:
            self.fin()
            return
        if "P" not in self.last_recv.flags:
            return

        self.lastMessageTime = time.time()

        data = self.last_recv[Raw].load
        v2g = V2GTP(data)
        payload = v2g.Payload
        # Save responses to decrease load on java webserver
        if payload in self.msgList.keys():
            exi = self.msgList[payload]
        else:
            exi = self.getEXIFromPayload(payload)
            if exi == None:
                return
            self.msgList[payload] = exi

        sendp(self.buildV2G(binascii.unhexlify(exi)), iface=self.iface, verbose=0)

    def buildV2G(self, payload):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = self.destinationIP

        tcpLayer = TCP()
        tcpLayer.sport = self.sourcePort
        tcpLayer.dport = self.destinationPort
        tcpLayer.seq = self.seq
        tcpLayer.ack = self.ack
        tcpLayer.flags = "PA"

        v2gLayer = V2GTP()
        v2gLayer.PayloadLen = len(payload)
        v2gLayer.Payload = payload

        return ethLayer / ipLayer / tcpLayer / v2gLayer

    def getEXIFromPayload(self, data):
        data = binascii.hexlify(data)
        xmlString = self.exi.decode(data)
        # print(f"XML String: {xmlString}")
        root = ET.fromstring(xmlString)

        if root.text is None:
            if "AppProtocol" in root.tag:
                self.xml.SessionSetupRequest()
                return self.xml.getEXI()

            name = root[1][0].tag
            # print(f"Response: {name}")
            if "SessionSetupRes" in name:
                self.xml.ServiceDiscoveryRequest()
                self.SessionID = root[0][0].text
            elif "ServiceDiscoveryRes" in name:
                self.xml.ServicePaymentSelectionRequest()
            elif "ServicePaymentSelectionRes" in name:
                self.xml.ContractAuthenticationRequest()
            elif "ContractAuthenticationRes" in name:
                if root[1][0][1].text == "Ongoing":
                    self.xml.ContractAuthenticationRequest()
                    # print("INFO (PEV) : Sending Contract Authenication Request")
                    if self.pev.mode == RunMode.SCAN:
                        # Start nmap scan while connection is kept alive
                        if self.scanner == None:
                            nmapMAC = self.pev.nmapMAC if self.pev.nmapMAC else self.destinationMAC
                            nmapIP = self.pev.nmapIP if self.pev.nmapIP else self.destinationIP
                            self.scanner = NMAPScanner(EmulatorType.PEV, self.pev.nmapPorts, self.iface, self.sourceMAC, self.sourceIP, nmapMAC, nmapIP)
                        self.scanner.start()
                else:
                    self.xml.ChargeParameterDiscoveryRequest()
            elif "ChargeParameterDiscoveryRes" in name:
                if root[1][0][1].text == "Ongoing":
                    self.xml.ChargeParameterDiscoveryRequest()
                else:
                    self.pev.setState(PEVState.C)
                    self.xml.CableCheckRequest()
            elif "CableCheckRes" in name:
                if root[1][0][2].text == "Ongoing":
                    self.xml.CableCheckRequest()
                else:
                    self.xml.PreChargeRequest()
            elif "PreChargeRes" in name:
                currentVoltage = int(root[1][0][2][2].text)
                if abs(currentVoltage - 400) < 10:
                    self.xml.PowerDeliveryRequest()
                else:
                    self.xml.PreChargeRequest()
                    # self.prechargeCount = self.prechargeCount + 1
            # Dont know if can get passed this point without providing actual voltage
            elif "PowerDeliveryRes" in name:
                self.xml.CurrentDemandRequest()
            elif "CurrentDemandRes" in name:
                self.xml.CurrentDemandRequest()
                # self.xml.EVRESSSOC.text = str(random.randint(0,100))
                # self.xml.EVRESSSOC.text = str(self.soc % 100)
                # print(f"Current SOC: {self.soc}")
                # self.soc = self.soc + 5
            else:
                raise Exception(f'Packet type "{name}" not recognized')

            self.xml.SessionID.text = self.SessionID
            return self.xml.getEXI()

    def handshake(self):
        while not self.startSniff:
            if not self.running:
                return
            time.sleep(0.1)

        self.destinationMAC = self.pev.destinationMAC
        self.destinationIP = self.pev.destinationIP
        self.destinationPort = self.pev.destinationPort

        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = self.destinationIP

        tcpLayer = TCP()
        tcpLayer.sport = self.sourcePort
        tcpLayer.dport = self.destinationPort
        tcpLayer.flags = "S"
        tcpLayer.seq = self.seq

        synPacket = ethLayer / ipLayer / tcpLayer
        print("INFO (PEV) : Sending SYN")
        sendp(synPacket, iface=self.iface, verbose=0)

    def sendNeighborSolicitation(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "33:33:ff:00" + self.destinationIP[-7:-5] + ":" + self.destinationIP[-4:-2] + ":" + self.destinationIP[-2:]

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = "ff02::1:" + self.destinationIP[-9:]

        icmpLayer = ICMPv6ND_NS()
        icmpLayer.type = 135
        icmpLayer.tgt = self.destinationIP

        optLayer = ICMPv6NDOptDstLLAddr()
        optLayer.type = 1
        optLayer.len = 1
        optLayer.lladdr = self.sourceMAC

        pkt = ethLayer / ipLayer / icmpLayer / optLayer
        print("INFO (PEV) : Sending Neighbor Solicitation")
        sendp(pkt, iface=self.iface, verbose=0)

    def sendNeighborAdvertisement(self, pkt):
        # if self.stop: exit()
        # if not (pkt.haslayer("ICMPv6ND_NS") and pkt[ICMPv6ND_NS].tgt == self.sourceIP): return
        self.destinationMAC = pkt[Ether].src
        self.destinationIP = pkt[IPv6].src
        # print("INFO (EVSE): Sending Neighor Advertisement")
        sendp(self.buildNeighborAdvertisement(), iface=self.iface, verbose=0)

    def buildLeaveReq(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        # ethLayer.dst = self.destinationMAC
        ethLayer.dst = "bc:f2:af:f2:0a:7b"

        hpLayer = HomePlugAV(binascii.unhexlify(b"01340000000100000000000000000000000000000000000000000000000000000000000000000000000000000000"))

        pkt = ethLayer / hpLayer
        return pkt

    def buildNeighborAdvertisement(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = self.destinationIP
        ipLayer.plen = 32
        ipLayer.hlim = 255

        icmpLayer = ICMPv6ND_NA()
        icmpLayer.type = 136
        icmpLayer.R = 0
        icmpLayer.S = 1
        icmpLayer.tgt = self.sourceIP

        optLayer = ICMPv6NDOptDstLLAddr()
        optLayer.type = 2
        optLayer.len = 1
        optLayer.lladdr = self.sourceMAC

        responsePacket = ethLayer / ipLayer / icmpLayer / optLayer
        return responsePacket


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
        print("INFO (PEV) : Shutting down emulator")
    except Exception as e:
        print(e)
    finally:
        pev.setState(PEVState.A)
        del pev
