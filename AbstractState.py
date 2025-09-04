from abc import ABC, abstractmethod
from scapy.all import *
from EmulatorEnum import *
from Packets import *

class AbstractState(ABC):
    def __init__(self, emulator):
        self.emulator = emulator
    
    def expandPacketLayers(self, pkt: Packet) -> list:
        res = []
        res.append(pkt.name)
        while pkt.payload:
            pkt = pkt.payload
            res.append(pkt.name)
        return res

    def _handlePacketTCPHelper(self, receivedPacket: Packet) -> bool:
        """Helper function to 
        - check if a received packet is a valid TCP packet
        - check if the packet is a valid V2G packet
        - update the emulator's seq and ack numbers"""

        # Check if packet is TCP, addressed to us, is PSH
        if not (receivedPacket.haslayer(TCP) and receivedPacket[TCP].dport == self.emulator.sourcePort and 'P' in receivedPacket[TCP].flags):
            return False, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET

        # Check if packet is V2G packet
        if not receivedPacket.haslayer("Raw"):
            return False, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET

        exiString = V2GTP(receivedPacket[Raw].load).Payload
        xmlJson = self.emulator.EXIProcessor.decode(exiString)
        pktName = list(xmlJson["Body"].keys())[0]

        if pktName not in self.validResponsePacketTypes:
            return False, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET

        # Packet should be sessionSetupRes
        self.emulator.seq = receivedPacket[TCP].ack
        self.emulator.ack = receivedPacket[TCP].seq + len(receivedPacket[TCP].payload)

        return True, xmlJson

    @property
    @abstractmethod
    def pktToSend(self) -> Packet:
        """Returns the packet to be sent in this state."""
        pass

    @property
    @abstractmethod
    def validResponsePacketTypes(self) -> list[PacketType]:
        """Returns a list of valid packet types that can be received in this state."""
        pass

    @property
    @abstractmethod
    def currentState(self) -> PacketType:
        """Returns the current state."""
        pass

    @abstractmethod
    def handlePacket(self, receivedPacket: Packet) -> tuple:
        """Handles the received packet and returns a tuple with (the next state, the type of response, and the response packet)."""
        pass

    def __str__(self):
        return self.__class__.__name__
    
    def __repr__(self):
        return self.__class__.__name__