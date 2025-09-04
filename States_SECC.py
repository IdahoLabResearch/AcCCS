"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
"""

from AbstractState import AbstractState
from EmulatorEnum import PacketType, StateMachineResponseType
from scapy.all import *
from Packets import *
from States_TCP import SYNState

import logging
logger = logging.getLogger(__name__)

class SDPRequestState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.SDPResponse]
        return [pkt.value for pkt in pkts]
    
    @property
    def pktToSend(self) -> Packet:
        return None

    @property
    def currentState(self) -> PacketType:
        return PacketType.SDPRequest
    
    def handlePacket(self, receivedPacket: Packet) -> tuple:
        # Check if packet is IPv6 and addressed to us
        if not (receivedPacket.haslayer(IPv6) and receivedPacket[IPv6].dst == self.emulator.sourceIP):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Check if packet is UDP and addressed to correct port
        if not (receivedPacket.haslayer(UDP) and receivedPacket[UDP].dport == self.emulator.sourcePort):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Check if packet has SECC layer
        if not receivedPacket.haslayer("SECC"):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)
        
        SECCtype = self.expandPacketLayers(receivedPacket)[4]

        if SECCtype not in self.validResponsePacketTypes:
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        self.emulator.destinationIP = receivedPacket[SECC_ResponseMessage].TargetAddress
        self.emulator.destinationPort = receivedPacket[SECC_ResponseMessage].TargetPort
        synPkt = SYN(self.emulator)

        return (SYNState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, synPkt)