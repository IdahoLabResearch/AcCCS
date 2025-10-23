import time, logging, socket

from threading import Thread
from scapy.all import Packet, Ether
from typing import TYPE_CHECKING, Optional

from external_libs.HomePlugPWN.layerscapy.HomePlugGP import *

if TYPE_CHECKING:
    from app.secc.controller.evse import EVSE

logger = logging.getLogger("SLAC")

# Handles all SLAC communications
class SLACHandler:
    def __init__(self, evse: "EVSE"):
        self.evse = evse
        self.iface = self.evse.iface
        self.sourceMAC = self.evse.sourceMAC
        self.NID = self.evse.NID
        self.NMK = self.evse.NMK
        self.runID = None
        
        self.sock = None
        
        self.timeSinceLastPkt = int(time.time())
        self.timeout = 8
        self.stop = False
        
    def create_socket(self):
        # Create a raw socket
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        # Bind to a specific network interface (e.g., "eth0")
        self.sock.bind((self.iface, 0))
    
    def receive(self) -> Optional[Packet]:
        raw_packet = self.sock.recv(65535)
        
        try:
            packet = Ether(raw_packet)
            if packet[Ether].type != 0x88E1 or packet[Ether].src == self.sourceMAC:
                return None
            if hasattr(packet[1][2], "RunID") and self.runID != None:
                if packet[1][2].RunID != self.runID:
                    return None
            return packet
        except Exception as err:
            logger.error(err)

    # Starts SLAC process
    def start(self):
        self.stop = False
        self.create_socket()
        self.handleSLAC()

        # Thread to determine if EVSE timed out or SLAC error occured and restart SLAC process
        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()

    def checkForTimeout(self):
        while self.stop == False:
            if int(time.time()) - self.timeSinceLastPkt > self.timeout:
                logger.info("Timed out... Sending SET_KEY_REQ")
                self.sock.send(bytes(self.buildSetKey()))
                self.timeSinceLastPkt = int(time.time()) 
                
    def handleSLAC(self):
        logger.info("Sending SET_KEY_REQ")
        self.sock.send(bytes(self.buildSetKey()))
        while not self.stop:
            packet = self.receive()
            if not packet:
                continue
            if packet.haslayer("CM_SLAC_PARM_REQ"):
                self.handle_CM_SLAC_PARM_REQ(packet)
            elif packet.haslayer("CM_MNBC_SOUND_IND"):
                self.handle_CM_ATTEN_CHAR_IND(packet)
            elif packet.haslayer("CM_SLAC_MATCH_REQ"):
                self.handle_CM_SLAC_MATCH_CNF(packet)
            self.timeSinceLastPkt = int(time.time())
            
    def handle_CM_SLAC_PARM_REQ(self, packet: Packet):
        logger.info("Recieved SLAC_PARM_REQ")
        self.destinationMAC = packet[Ether].src
        self.runID = packet[CM_SLAC_PARM_REQ].RunID
        logger.info("Sending CM_SLAC_PARM_CNF")
        self.sock.send(bytes(self.buildSlacParmCnf()))
        
    def handle_CM_ATTEN_CHAR_IND(self, packet: Packet):
        logger.info(f"Recieved MNBC_SOUND_IND, Countdown {packet[CM_MNBC_SOUND_IND].Countdown}")
        if packet[CM_MNBC_SOUND_IND].Countdown == 0:
            logger.info("Sending ATTEN_CHAR_IND")
            self.sock.send(bytes(self.buildAttenCharInd()))
        
    def handle_CM_SLAC_MATCH_CNF(self, packet: Packet):
        logger.info("Recieved SLAC_MATCH_REQ")
        logger.info("Sending SLAC_MATCH_CNF")
        self.sock.send(bytes(self.buildSlacMatchCnf()))
        self.stop = True

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