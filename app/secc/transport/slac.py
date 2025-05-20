import time, logging

from threading import Thread
from scapy.all import Ether
from typing import TYPE_CHECKING

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

        self.timeout = 8
        self.stop = False

    # Starts SLAC process
    def start(self):
        self.stop = False
        logger.info("Sending SET_KEY_REQ")
        sendp(self.buildSetKey(), iface=self.iface, verbose=0)
        
        self.sniffThread = Thread(target=self.startSniff)
        self.sniffThread.start()

        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()

    def checkForTimeout(self):
        self.lastMessageTime = int(time.time())
        while True:
            if self.stop:
                break
            if int(time.time()) - self.lastMessageTime > self.timeout:
                logger.info("SLAC timed out, resetting connection...")
                self.evse.toggleProximity()
                self.lastMessageTime = int(time.time())

    def startSniff(self):
        sniff(iface=self.iface, prn=self.handlePacket, stop_filter=self.stopSniff)

    def stopSniff(self, pkt):
        return self.stop

    def handlePacket(self, pkt):
        if pkt[Ether].type != 0x88E1 or pkt[Ether].src == self.sourceMAC:
            return

        self.lastMessageTime = int(time.time())

        if pkt.haslayer("CM_SLAC_PARM_REQ"):
            logger.info("Recieved SLAC_PARM_REQ")
            self.destinationMAC = pkt[Ether].src
            self.runID = pkt[CM_SLAC_PARM_REQ].RunID
            logger.info("Sending CM_SLAC_PARM_CNF")
            sendp(self.buildSlacParmCnf(), iface=self.iface, verbose=0)

        if pkt.haslayer("CM_MNBC_SOUND_IND"):
            logger.info(f"Recieved MNBC_SOUND_IND, Countdown {pkt[CM_MNBC_SOUND_IND].Countdown}")
            if pkt[CM_MNBC_SOUND_IND].Countdown == 0:
                logger.info("Sending ATTEN_CHAR_IND")
                sendp(self.buildAttenCharInd(), iface=self.iface, verbose=0)

        if pkt.haslayer("CM_SLAC_MATCH_REQ"):
            logger.info("Recieved SLAC_MATCH_REQ")
            logger.info("Sending SLAC_MATCH_CNF")
            sendp(self.buildSlacMatchCnf(), iface=self.iface, verbose=0)
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