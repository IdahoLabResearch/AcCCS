"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
"""

# Have a list of packet types to modify
# Pass them to PEV and EVSE emulators
import sys, os

sys.path.append("./external_libs/HomePlugPWN")
sys.path.append("./external_libs/V2GInjector/core")

from PEV import PEV
from EVSE import EVSE
from EmulatorEnum import *
from EXIProcessor import EXIProcessor

from layers.SECC import *
from layers.V2G import *
from layerscapy.HomePlugGP import *

import xml.etree.ElementTree as ET
import binascii


class MIM:
    def __init__(self, pev_iface, evse_iface, msgList: list = []):
        self.pev_iface = pev_iface
        self.evse_iface = evse_iface

        self.PEVMAC = "f0:7f:0c:00:62:af"
        self.PEVIP = "fe80::f27f:cff:fe00:9d76"
        self.PEVPort = 52538

        self.EVSEMAC = "00:1e:c0:f2:6c:a0"
        self.EVSEIP = "fe80::21e:c0ff:fef2:02f3"
        self.EVSEPort = 25565

        self.PEVSessionID = None
        self.EVSESessionID = "4142423030303031"

        # This is connected to the acutal EVSE
        self.pev = PEV(self.pev_iface, sourceMAC=self.PEVMAC, sourceIP=self.PEVIP, sourcePort=self.PEVPort)
        # This is connected to the actual PEV
        self.evse = EVSE(self.evse_iface, sourceMAC=self.EVSEMAC, sourceIP=self.EVSEIP, sourcePort=self.EVSEPort)

        self.msgList = msgList

    def start(self):
        # set up threads to sniff traffic through each interface
        self.PEVSniffThread = AsyncSniffer(iface=self.pev_iface, prn=self.handlePEVPacket)
        self.EVSESniffThread = AsyncSniffer(iface=self.evse_iface, prn=self.handleEVSEPacket)

        self.PEVSniffThread.start()
        self.EVSESniffThread.start()

        # Complete SLAC for each device
        # Do them sequentially to eliminate chance of cross-talk
        self.evse.doSLAC()
        self.pev.doSLAC()

    # For both PEV and EVSE handle functions it essentially takes the packet from one interface
    # changes the source and destination for each layer and transmits it on the other interface
    def handlePEVPacket(self, pkt):  # Packets coming from EVSE
        if not pkt.haslayer("TCP"):
            return

        pkt[Ether].src = self.evse.sourceMAC
        pkt[Ether].dst = self.evse.destinationMAC

        pkt[IPv6].src = self.evse.sourceIP
        pkt[IPv6].dst = self.evse.destinationIP

        pkt[TCP].sport = self.evse.sourcePort
        pkt[TCP].dport = self.evse.destinationPort

        # V2G stuff will only be in push packets
        if "P" in pkt[TCP].flags:
            # Extract XML from V2G layer and modify
            data = pkt[Raw].load
            v2gPkt = V2GTP(data)
            payload = v2gPkt.Payload
            xmlString = self.pev.exi.decode(payload)
            xmlString = self.modifyXML(xmlString)
            xmlString = self.updateSessionID(xmlString, self.PEVSessionID)

            root = ET.fromstring(xmlString)
            if root.text is None and "AppProtocol" not in root.tag:
                name = root[1][0].tag
                if "ChargeParameterDiscoveryRes" in name and root[1][0][1].text != "Ongoing":
                    self.pev.setState(PEVState.C)

            # Convert back to exi and put into v2g packet
            exiString = self.pev.exi.encode(xmlString)
            v2gPkt.Payload = exiString
            v2gPkt.PayloadLen = len(exiString)

            resPkt = pkt[Ether] / pkt[IPv6] / pkt[TCP] / v2gPkt
            sendp(resPkt, iface=self.evse_iface, verbose=0)
        else:
            sendp(pkt, iface=self.evse_iface, verbose=0)

    def handleEVSEPacket(self, pkt):  # Packets coming from PEV
        if not pkt.haslayer("TCP"):
            return

        # Change packet addresses
        pkt[Ether].src = self.pev.sourceMAC
        pkt[Ether].dst = self.pev.destinationMAC

        pkt[IPv6].src = self.pev.sourceIP
        pkt[IPv6].dst = self.pev.destinationIP

        pkt[TCP].sport = self.pev.sourcePort
        pkt[TCP].dport = self.pev.destinationPort

        # V2G stuff will only be in push packets
        if "P" in pkt[TCP].flags:
            # Extract XML from V2G layer and modify
            data = pkt[Raw].load
            v2gPkt = V2GTP(data)
            payload = v2gPkt.Payload
            xmlString = self.evse.exi.decode(payload)
            xmlString = self.modifyXML(xmlString)
            xmlString = self.updateSessionID(xmlString, self.EVSESessionID)

            # Convert back to exi and put into v2g packet
            exiString = self.evse.exi.encode(xmlString)
            v2gPkt.Payload = exiString
            v2gPkt.PayloadLen = len(exiString)

            resPkt = pkt[Ether] / pkt[IPv6] / pkt[TCP] / v2gPkt
            sendp(resPkt, iface=self.pev_iface, verbose=0)
        else:
            sendp(pkt, iface=self.pev_iface, verbose=0)

    def updateSessionID(self, xmlString, sessionID):
        root = ET.fromstring(xmlString)
        root[0][0].text = sessionID
        return ET.tostring(root, encoding="UTF-8", method="xml")

    def modifyXML(self, xmlString):
        if not self.msgList:
            return xmlString
        root = ET.fromstring(xmlString)
        name = root[1][0].tag
        for entry in self.msgList:
            if entry[0] not in name:
                continue
            for key in entry[1].keys():
                ind = xmlString.find(key)
                start = xmlString.find(f"{key}>", ind)
                end = xmlString.find(f"</{key}", ind)
                xmlString = xmlString[: start + len(key) + 1] + entry[1][key] + xmlString[end:]
        return xmlString


if __name__ == "__main__":
    m = MIM(evse_iface="eth1", pev_iface="eth2")
    m.start()
