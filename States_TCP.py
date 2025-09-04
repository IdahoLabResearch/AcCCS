from AbstractState import AbstractState
from scapy.all import *
from Packets import *
from EmulatorEnum import *
from States_AppHand import supportedAppProtocolReqState
from V2Gjson import *

class SYNState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.SYN_ACK]
        return [pkt.value for pkt in pkts]

    @property
    def pktToSend(self) -> Packet:
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