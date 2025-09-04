from abc import ABC, abstractmethod
from EmulatorEnum import PacketType
from scapy.all import Packet

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