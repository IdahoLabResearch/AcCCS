import os, time, logging, socket

from threading import Thread
from typing import TYPE_CHECKING, Optional

from scapy.all import Packet, Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr

from external_libs.HomePlugPWN.layerscapy.HomePlugGP import *

if TYPE_CHECKING:
    from app.evcc.controller.pev import PEV

logger = logging.getLogger("SLAC")

# This class handles the level 2 SLAC protocol communications
class SLACHandler:
    def __init__(self, pev: "PEV"):
        self.pev = pev
        self.iface = self.pev.iface
        self.sourceMAC = self.pev.sourceMAC
        self.sourceIP = self.pev.sourceIP
        self.runID = b"\xf4\x00\x37\xd0\x00\x5c\x00\x7f"
        
        self.sock = None

        self.timeSinceLastPkt = int(time.time())
        self.timeout = 8  # How long to wait for a message to timeout
        self.stop = False
        
        self.CM_ATTEN_CHAR_IND_recved = False
        
    def create_socket(self):
        # Create a raw socket
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        # Bind to a specific network interface (e.g., "eth0")
        self.sock.bind((self.iface, 0))
    
    def receive(self) -> Optional[Packet]:
        raw_packet = self.sock.recv(65535)
        
        try:
            packet = Ether(raw_packet)
            if packet[Ether].type != 0x88E1 or packet[Ether].src == self.sourceMAC:
                return None
            if hasattr(packet[1][2], "RunID") and packet[1][2].RunID != self.runID:
                return None
            return packet
        except Exception as err:
            logger.error(err)

    # This method starts the slac process and will stop
    def start(self):
        self.runID = os.urandom(8)
        self.stop = False

        # Thread to determine if PEV timed out or SLAC error occured and restart SLAC process
        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()

        self.neighborSolicitationThread = AsyncSniffer(
            iface=self.iface, lfilter=lambda x: x.haslayer("ICMPv6ND_NS") and x[ICMPv6ND_NS].tgt == self.sourceIP, prn=self.sendNeighborSoliciation
        )
        self.neighborSolicitationThread.start()
        
        self.create_socket()
        self.handleSLAC()
        
        if self.neighborSolicitationThread.running:
            self.neighborSolicitationThread.stop()

    # The EVSE sometimes fails the SLAC process, so this automatically restarts it from the beginning
    def checkForTimeout(self):
        while self.stop == False:
            if int(time.time()) - self.timeSinceLastPkt > self.timeout:
                self.CM_ATTEN_CHAR_IND_recved = False
                logger.info("Timed out... Sending SLAC_PARM_REQ")
                self.sock.send(bytes(self.buildSlacParmReq()))
                self.timeSinceLastPkt = int(time.time()) 
                
    def handleSLAC(self):
        logger.info("Sending CM_SLAC_PARM_REQ")
        self.sock.send(bytes(self.buildSlacParmReq()))
        while not self.stop:
            packet = self.receive()
            if not packet:
                continue
            if packet.haslayer("CM_SLAC_PARM_CNF"):
                self.handle_CM_SLAC_PARM_CNF(packet)
            elif packet.haslayer("CM_ATTEN_CHAR_IND"):
                self.handle_CM_ATTEN_CHAR_IND()
            elif packet.haslayer("CM_SLAC_MATCH_CNF"):
                self.handle_CM_SLAC_MATCH_CNF(packet)
        
    def handle_CM_SLAC_PARM_CNF(self, packet: Packet):
        logger.info("Recieved CM_SLAC_PARM_CNF")
        self.destinationMAC = packet[Ether].src
        self.pev.destinationMAC = packet[Ether].src
        self.numSounds = packet[CM_SLAC_PARM_CNF].NumberMSounds
        self.numRemainingSounds = self.numSounds
        
        logger.info("Sending 3 CM_START_ATTEN_CHAR_IND")
        self.sock.send(bytes(self.buildStartAttenCharInd()))
        for i in range(2):
            time.sleep(0.02)
            self.sock.send(bytes(self.buildStartAttenCharInd()))
        
        logger.info(f"Sending {self.numSounds} CM_MNBC_SOUND_IND")
        self.sock.send(bytes(self.buildMNBCSoundInd()))
        for i in range(self.numSounds - 1):
            time.sleep(0.02)
            self.sock.send(bytes(self.buildMNBCSoundInd()))
        return

    def handle_CM_ATTEN_CHAR_IND(self):
        self.stopSounds = True
        logger.info("Recieved CM_ATTEN_CHAR_IND")
        if self.CM_ATTEN_CHAR_IND_recved == False:
            self.CM_ATTEN_CHAR_IND_recved = True
            logger.info("Sending ATTEN_CHAR_RES")
            sendp(self.buildAttenCharRes(), iface=self.iface, verbose=0)
            logger.info("Sending SLAC_MATCH_REQ")
            sendp(self.buildSlacMatchReq(), iface=self.iface, verbose=0)
        self.timeSinceLastPkt = int(time.time())
        return

    def handle_CM_SLAC_MATCH_CNF(self, packet: Packet):
        logger.info("Recieved SLAC_MATCH_CNF")
        self.NID = packet[CM_SLAC_MATCH_CNF].VariableField.NetworkID
        self.NMK = packet[CM_SLAC_MATCH_CNF].VariableField.NMK
        logger.info("Sending SET_KEY_REQ")
        sendp(self.buildSetKeyReq(), iface=self.iface, verbose=0)
        self.stop = True
        return

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
        # logger.info("Sending Neighor Advertisement")
        sendp(self.buildNeighborAdvertisement(), iface=self.iface, verbose=0)