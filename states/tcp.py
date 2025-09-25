"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
"""

from AbstractState import AbstractState
from scapy.layers.inet import TCP
from scapy.packet import Packet
from Packets import *
from EmulatorEnum import *
from .apphand import *
from V2Gjson import *

#########################################################################################################################
# PEV STATES #

class SYNState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.SYN_ACK]
        return [pkt.value for pkt in pkts]

    @property
    def pktToSend(self) -> Packet | None:
        return SYN(self.emulator)

    @property
    def currentState(self) -> PacketType:
        return PacketType.SYN

    def handlePacket(self, receivedPacket: Packet) -> tuple:
        # Check if packet is SYN_ACK TCP and addressed to us
        if not (receivedPacket.haslayer(TCP) and receivedPacket[TCP].dport == self.emulator.sourcePort and receivedPacket[TCP].flags in self.validResponsePacketTypes):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)
        
        self.emulator.seq = receivedPacket[TCP].ack
        self.emulator.ack = receivedPacket[TCP].seq + 1

        ACKpkt = ACK(self.emulator)
        apphandPkt = V2G(self.emulator, self.emulator.appHandshake.encode(SupportedAppProtocolRequest()))
        rspPkts = [ACKpkt, apphandPkt]
        return (supportedAppProtocolReqState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkts)

#########################################################################################################################
# EVSE STATES #

class SYNACKState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.supportedAppProtocolReq]
        return [pkt.value for pkt in pkts]
    
    @property
    def pktToSend(self) -> Packet | None:
        return SYNACK(self.emulator)
    
    @property
    def currentState(self) -> PacketType:
        return PacketType.SYN_ACK
    
    def handlePacket(self, receivedPacket: Packet) -> tuple:
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
        
        # Packet should be supportedAppProtocolReq
        self.emulator.seq = receivedPacket[TCP].ack
        self.emulator.ack = receivedPacket[TCP].seq + len(receivedPacket[TCP].payload)

        rspPkt = V2G(self.emulator, self.emulator.appHandshake.encode(SupportedAppProtocolResponse()))
        return (supportedAppProtocolResState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkt)