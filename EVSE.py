"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
    
    This class is used to emulate a EVSE when talking to an PEV. Handles level 2 SLAC communications
    and level 3 UDP and TCP communications to the electric vehicle.
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
from smbus import SMBus
import argparse


class EVSE:

    def __init__(self, args):
        self.mode = RunMode(args.mode[0]) if args.mode else RunMode.FULL
        self.iface = args.interface[0] if args.interface else "eth1"
        self.sourceMAC = args.source_mac[0] if args.source_mac else "00:1e:c0:f2:6c:a0"
        self.sourceIP = args.source_ip[0] if args.source_ip else "fe80::21e:c0ff:fef2:6ca0"
        self.sourcePort = args.source_port[0] if args.source_port else 25565
        self.NID = args.NID[0] if args.NID else b"\x9c\xb0\xb2\xbb\xf5\x6c\x0e"
        self.NMK = args.NMK[0] if args.NMK else b"\x48\xfe\x56\x02\xdb\xac\xcd\xe5\x1e\xda\xdc\x3e\x08\x1a\x52\xd1"
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
        if args.modified_cordset:
            self.modified_cordset = True
        else:
            self.modified_cordset = False
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
        self.EVSE_CP = 0b1
        self.EVSE_PP = 0b1000
        self.ALL_OFF = 0b0

    # Start the emulator
    def start(self):
        # Initialize the I2C bus for wwrite
        self.bus.write_byte_data(self.I2C_ADDR, 0x00, 0x00)

        self.toggleProximity()
        self.doSLAC()
        self.doTCP()
        # If NMAP is not done, restart connection
        if not self.tcp.finishedNMAP:
            print("INFO (EVSE): Attempting to restart connection...")
            self.start()

    # Close the circuit for the proximity pins
    def closeProximity(self):
        if self.modified_cordset:
            print("INFO (EVSE): Closing CP/PP relay connections")
            self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.EVSE_PP | self.EVSE_CP)
        else:
            print("INFO (EVSE): Closing CP relay connection")
            self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.EVSE_CP)

    # Close the circuit for the proximity pins
    def openProximity(self):
        print("INFO (EVSE): Opening CP/PP relay connections")
        self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.ALL_OFF)

    # Opens and closes proximity circuit with a delay
    def toggleProximity(self, t: int = 5):
        self.openProximity()
        time.sleep(t)
        self.closeProximity()

    # Starts TCP/IPv6 thread that handles layer 3 comms
    def doTCP(self):
        self.tcp.start()
        print("INFO (EVSE): Done TCP")

    # Starts SLAC thread that handles layer 2 comms
    def doSLAC(self):
        self.slac.start()
        self.slac.sniffThread.join()
        print("INFO (EVSE): Done SLAC")


# Handles all SLAC communications
class _SLACHandler:
    def __init__(self, evse: EVSE):
        self.evse = evse
        self.iface = self.evse.iface
        self.sourceMAC = self.evse.sourceMAC
        self.sourceIP = self.evse.sourceIP
        self.sourcePort = self.evse.sourcePort
        self.NID = self.evse.NID
        self.NMK = self.evse.NMK

        self.timeout = 8
        self.stop = False

    # Starts SLAC process
    def start(self):
        self.stop = False
        print("INFO (EVSE): Sending SET_KEY_REQ")
        sendp(self.buildSetKey(), iface=self.iface, verbose=0)
        self.sniffThread = Thread(target=self.startSniff)
        self.sniffThread.start()

        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()

    def checkForTimeout(self):
        self.lastMessageTime = time.time()
        while True:
            if self.stop:
                break
            if time.time() - self.lastMessageTime > self.timeout:
                print("INFO (EVSE): SLAC timed out, resetting connection...")
                self.evse.toggleProximity()
                self.lastMessageTime = time.time()

    def startSniff(self):
        sniff(iface=self.iface, prn=self.handlePacket, stop_filter=self.stopSniff)

    def stopSniff(self, pkt):
        if pkt.haslayer("SECC_RequestMessage"):
            print("INDO (EVSE): Recieved SECC_RequestMessage")
            # self.evse.destinationMAC = pkt[Ether].src
            # use this to send 3 secc responses incase car doesnt see one
            self.destinationIP = pkt[IPv6].src
            self.destinationPort = pkt[UDP].sport
            Thread(target=self.sendSECCResponse).start()
            self.stop = True
        return self.stop

    def sendSECCResponse(self):
        time.sleep(0.2)
        for i in range(3):
            print("INFO (EVSE): Sending SECC_ResponseMessage")
            sendp(self.buildSECCResponse(), iface=self.iface, verbose=0)

    def handlePacket(self, pkt):
        if pkt[Ether].type != 0x88E1 or pkt[Ether].src == self.sourceMAC:
            return

        self.lastMessageTime = time.time()

        if pkt.haslayer("CM_SLAC_PARM_REQ"):
            print("INFO (EVSE): Recieved SLAC_PARM_REQ")
            self.destinationMAC = pkt[Ether].src
            self.runID = pkt[CM_SLAC_PARM_REQ].RunID
            print("INFO (EVSE): Sending CM_SLAC_PARM_CNF")
            sendp(self.buildSlacParmCnf(), iface=self.iface, verbose=0)

        if pkt.haslayer("CM_MNBC_SOUND_IND") and pkt[CM_MNBC_SOUND_IND].Countdown == 0:
            print("INFO (EVSE): Recieved last MNBC_SOUND_IND")
            print("INFO (EVSE): Sending ATTEN_CHAR_IND")
            sendp(self.buildAttenCharInd(), iface=self.iface, verbose=0)

        if pkt.haslayer("CM_SLAC_MATCH_REQ"):
            print("INFO (EVSE): Recieved SLAC_MATCH_REQ")
            print("INFO (EVSE): Sending SLAC_MATCH_CNF")
            sendp(self.buildSlacMatchCnf(), iface=self.iface, verbose=0)

    def buildSlacParmCnf(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        # Parameters copied from packet #13 in BMW-i3-Plugin-ChargeStart-UserStop.pcapng
        homePlugLayer = CM_SLAC_PARM_CNF()
        homePlugLayer.MSoundTargetMAC = "ff:ff:ff:ff:ff:ff"
        homePlugLayer.NumberMSounds = 0x0A
        homePlugLayer.TimeOut = 0x06
        homePlugLayer.ResponseType = 0x01
        homePlugLayer.ForwardingSTA = self.destinationMAC
        homePlugLayer.RunID = self.runID

        # padding?
        rawLayer = Raw()
        rawLayer.load = b"\x00" * 16

        responsePacket = ethLayer / homePlugAVLayer / homePlugLayer / rawLayer
        return responsePacket

    def buildAttenCharInd(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        # Parameters copied from packet #29 in BMW-i3-Plugin-ChargeStart-UserStop.pcapng
        homePlugLayer = CM_ATTEN_CHAR_IND()
        homePlugLayer.ApplicationType = 0x00
        homePlugLayer.SecurityType = 0x00
        homePlugLayer.SourceAdress = self.destinationMAC
        homePlugLayer.RunID = self.runID
        homePlugLayer.NumberOfSounds = 0x0A
        # TODO: deal with number of groups and average attenuations
        # Does the number of groups change?
        homePlugLayer.NumberOfGroups = 58
        attens = [
            26,
            25,
            26,
            28,
            25,
            27,
            34,
            33,
            33,
            36,
            31,
            31,
            31,
            31,
            30,
            29,
            29,
            28,
            27,
            26,
            25,
            23,
            22,
            22,
            21,
            20,
            24,
            27,
            31,
            36,
            41,
            45,
            45,
            38,
            32,
            29,
            29,
            31,
            32,
            32,
            32,
            34,
            35,
            35,
            35,
            35,
            35,
            35,
            34,
            38,
            39,
            39,
            40,
            40,
            39,
            41,
            42,
            57,
        ]
        groups = []
        for e in attens:
            g = HPGP_GROUP()
            g.group = e
            groups.append(g)
        homePlugLayer.Groups = groups

        responsePacket = ethLayer / homePlugAVLayer / homePlugLayer
        return responsePacket

    def buildSlacMatchCnf(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        slacVars = SLAC_varfield_cnf()
        slacVars.EVMAC = self.destinationMAC
        slacVars.EVSEMAC = self.sourceMAC
        slacVars.RunID = self.runID
        slacVars.NetworkID = self.NID
        slacVars.NMK = self.NMK

        homePlugLayer = CM_SLAC_MATCH_CNF()
        homePlugLayer.MatchVariableFieldLen = 0x5600
        homePlugLayer.VariableField = slacVars

        responsePacket = ethLayer / homePlugAVLayer / homePlugLayer
        return responsePacket

    def buildSetKey(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "00:b0:52:00:00:01"  # Some AtherosC MAC for some reason

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

    def buildSECCResponse(self):
        e = Ether()
        e.src = self.sourceMAC
        e.dst = self.destinationMAC

        ip = IPv6()
        ip.src = self.sourceIP
        ip.dst = self.destinationIP

        udp = UDP()
        udp.sport = 15118
        udp.dport = self.destinationPort

        secc = SECC()
        secc.SECCType = 0x9001
        secc.PayloadLen = 20

        seccRM = SECC_ResponseMessage()
        seccRM.SecurityProtocol = 16
        seccRM.TargetPort = self.sourcePort
        seccRM.TargetAddress = self.sourceIP  # eno1

        responsePacket = e / ip / udp / secc / seccRM
        return responsePacket


class _TCPHandler:
    def __init__(self, evse: EVSE):
        self.evse = evse
        self.iface = self.evse.iface

        self.sourceMAC = self.evse.sourceMAC
        self.sourceIP = self.evse.sourceIP
        self.sourcePort = self.evse.sourcePort

        self.destinationMAC = self.evse.destinationMAC
        self.destinationIP = self.evse.destinationIP
        self.destinationPort = self.evse.destinationPort

        self.seq = 10000
        self.ack = 0

        self.exi = self.evse.exi
        self.xml = XMLBuilder(self.exi)
        self.msgList = {}

        self.stop = False
        self.scanner = None

        self.timeout = 5

    def start(self):
        self.msgList = {}
        self.running = True
        print("INFO (EVSE): Starting TCP")
        self.startSniff = False

        self.recvThread = AsyncSniffer(
            iface=self.iface,
            lfilter=lambda x: x.haslayer("TCP") and x[TCP].sport == self.destinationPort and x[TCP].dport == self.sourcePort,
            prn=self.handlePacket,
            started_callback=self.setStartSniff,
        )
        self.recvThread.start()

        while not self.startSniff:
            continue

        self.handshakeThread = AsyncSniffer(
            count=1, iface=self.iface, lfilter=lambda x: x.haslayer("IPv6") and x.haslayer("TCP") and x[TCP].flags == "S", prn=self.handshake
        )
        self.handshakeThread.start()

        self.neighborSolicitationThread = AsyncSniffer(
            iface=self.iface, lfilter=lambda x: x.haslayer("ICMPv6ND_NS") and x[ICMPv6ND_NS].tgt == self.sourceIP, prn=self.sendNeighborSoliciation
        )
        self.neighborSolicitationThread.start()

        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()

        while self.running:
            time.sleep(1)

    def checkForTimeout(self):
        print("INFO (EVSE): Starting timeout thread")
        self.lastMessageTime = time.time()
        while True:
            # if self.stop: break
            if time.time() - self.lastMessageTime > self.timeout or self.running == False:
                print("INFO (EVSE): TCP timed out, resetting connection...")
                self.killThreads()
                break
            time.sleep(1)

    # Need this so the sniff thread is actually running when the handshake is sent
    def setStartSniff(self):
        self.startSniff = True
        # print("INFO (EVSE): Starting recv sniff")

    def recv(self):
        print("EVSE (INFO): Starting recv thread")
        sniff(
            iface=self.iface,
            lfilter=lambda x: x.haslayer("TCP") and x[TCP].sport == self.destinationPort and x[TCP].dport == self.sourcePort,
            prn=self.handlePacket,
            started_callback=self.setStartSniff,
        )

    def fin(self):
        print("INFO (EVSE): Recieved FIN")
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

        print("INFO (EVSE): Sending FINACK")

        sendp(finAck, iface=self.iface, verbose=0)

    def killThreads(self):
        print("INFO (EVSE): Killing sniffing threads")
        self.running = False
        if self.scanner:
            self.scanner.stop()
        if self.recvThread.running:
            self.recvThread.stop()
        if self.handshakeThread.running:
            self.handshakeThread.stop()
        if self.neighborSolicitationThread.running:
            self.neighborSolicitationThread.stop()

    def handlePacket(self, pkt):
        self.last_recv = pkt
        self.seq = self.last_recv[TCP].ack
        self.ack = self.last_recv[TCP].seq + len(self.last_recv[TCP].payload)

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
            if root[0].tag == "AppProtocol":
                self.xml.SupportedAppProtocolResponse()
                return self.xml.getEXI()

            name = root[1][0].tag
            print(f"Request: {name}")
            if "SessionSetupReq" in name:
                self.xml.SessionSetupResponse()
            elif "ServiceDiscoveryReq" in name:
                self.xml.ServiceDiscoveryResponse()
            elif "ServicePaymentSelectionReq" in name:
                self.xml.ServicePaymentSelectionResponse()
            elif "ContractAuthenticationReq" in name:
                self.xml.ContractAuthenticationResponse()
                if self.evse.mode == RunMode.STOP:
                    self.xml.EVSEProcessing.text = "Ongoing"
                elif self.evse.mode == RunMode.SCAN:
                    self.xml.EVSEProcessing.text = "Ongoing"
                    # Start nmap scan while connection is kept alive
                    if self.scanner == None:
                        nmapMAC = self.evse.nmapMAC if self.evse.nmapMAC else self.destinationMAC
                        nmapIP = self.evse.nmapIP if self.evse.nmapIP else self.destinationIP
                        self.scanner = NMAPScanner(EmulatorType.EVSE, self.evse.nmapPorts, self.iface, self.sourceMAC, self.sourceIP, nmapMAC, nmapIP)
                    self.scanner.start()
            elif "ChargeParameterDiscoveryReq" in name:
                self.xml.ChargeParameterDiscoveryResponse()
                # self.xml.MinCurrentLimitValue.text = "0"
                self.xml.MaxCurrentLimitValue.text = "5"
            elif "CableCheckReq" in name:
                self.xml.CableCheckResponse()
            elif "PreChargeReq" in name:
                self.xml.PreChargeResponse()
                self.xml.Multiplier.text = root[1][0][1][0].text
                self.xml.Value.text = root[1][0][1][2].text
            elif "PowerDeliveryReq" in name:
                self.xml.PowerDeliveryResponse()
            elif "CurrentDemandReq" in name:
                self.xml.CurrentDemandResponse()
                self.xml.CurrentMultiplier.text = root[1][0][1][0].text
                self.xml.CurrentValue.text = root[1][0][1][2].text
                self.xml.VoltageMultiplier.text = root[1][0][8][0].text
                self.xml.VoltageValue.text = root[1][0][8][2].text
                self.xml.CurrentLimitValue.text = "5"
            elif "SessionStopReq" in name:
                self.running = False
                self.xml.SessionStopResponse()
            else:
                raise Exception(f'Packet type "{name}" not recognized')
            return self.xml.getEXI()

    def startNeighborSolicitationSniff(self):
        sniff(iface=self.iface, prn=self.sendNeighborSoliciation)

    def sendNeighborSoliciation(self, pkt):
        # if self.stop: exit()
        # if not (pkt.haslayer("ICMPv6ND_NS") and pkt[ICMPv6ND_NS].tgt == self.sourceIP): return
        self.destinationMAC = pkt[Ether].src
        self.destinationIP = pkt[IPv6].src
        # print("INFO (EVSE): Sending Neighor Advertisement")
        sendp(self.buildNeighborAdvertisement(), iface=self.iface, verbose=0)

    def handshake(self, syn):
        self.destinationMAC = syn[Ether].src
        self.destinationIP = syn[IPv6].src
        self.destinationPort = syn[TCP].sport
        self.ack = syn[TCP].seq + 1

        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = self.destinationIP

        tcpLayer = TCP()
        tcpLayer.sport = self.sourcePort
        tcpLayer.dport = self.destinationPort
        tcpLayer.flags = "SA"
        tcpLayer.seq = self.seq
        tcpLayer.ack = self.ack

        synAck = ethLayer / ipLayer / tcpLayer
        print("INFO (EVSE): Sending SYNACK")
        sendp(synAck, iface=self.iface, verbose=0)

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
        print("INFO (EVSE): Shutting down emulator")
    except Exception as e:
        print(e)
    finally:
        evse.openProximity()
        del evse
