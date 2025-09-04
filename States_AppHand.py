"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
"""

from AbstractState import AbstractState
from EmulatorEnum import PacketType, StateMachineResponseType
from scapy.all import *
from Packets import *
from V2Gjson import *
from States_DIN import *

import logging
logger = logging.getLogger(__name__)

class supportedAppProtocolReqState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.supportedAppProtocolRes]
        return [pkt.value for pkt in pkts]

    @property
    def pktToSend(self) -> Packet:
        return V2G(self.emulator, self.emulator.appHandshake.encode(SupportedAppProtocolRequest()))

    @property
    def currentState(self) -> PacketType:
        return PacketType.supportedAppProtocolReq
    
    def handlePacket(self, receivedPacket):
        # Check if packet is TCP, addressed to us, is PSH
        if not (receivedPacket.haslayer(TCP) and receivedPacket[TCP].dport == self.emulator.sourcePort and 'P' in receivedPacket[TCP].flags):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Check if packet is V2G packet
        if not receivedPacket.haslayer("Raw"):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        exiString = V2GTP(receivedPacket[Raw].load).Payload
        xmlJson = self.emulator.appHandshake.decode(exiString)
        pktName = list(xmlJson.keys())[0]

        if pktName not in self.validResponsePacketTypes:
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)
        
        # Packet should be supportedAppProtocolRes
        self.emulator.seq = receivedPacket[TCP].ack
        self.emulator.ack = receivedPacket[TCP].seq + len(receivedPacket[TCP].payload)

        # TODO: Implement other schemas besides DIN
        rspPkt = V2G(self.emulator, self.emulator.EXIProcessor.encode(SessionSetupRequest()))
        return (SessionSetupReqState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkt)