"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
"""

from abc import ABC, abstractmethod
from scapy.layers.inet import TCP
from EmulatorEnum import *
from Packets import *

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from Emulator import Emulator

def expandPacketLayers(pkt: Packet) -> list:
        res = []
        res.append(pkt.name)
        while pkt.payload:
            pkt = pkt.payload
            res.append(pkt.name)
        return res

@dataclass
class StateTransitionResult:
    success: bool
    next_state: 'AbstractState | None'
    error_message: str | None


class StateContext:
    def __init__(self, emulator: "Emulator"):
        self.emulator = emulator
        self.session_data = {}


class PacketValidator:
    @staticmethod
    def validateEthernetPacket(pkt: Packet, emulator: "Emulator") -> StateTransitionResult | None:
        if not pkt.haslayer(Ether):
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message="Packet is not Ethernet"
            )
        else:
            if pkt[Ether].dst != emulator.sourceMAC and pkt[Ether].dst != "ff:ff:ff:ff:ff:ff" and pkt[Ether].dst != "33:33:00:00:00:01":
                return StateTransitionResult(
                    success=False,
                    next_state=None,
                    error_message="Ethernet not addressed to this device"
                )
    
    @staticmethod
    def validateHPGPPacket(pkt: Packet, emulator: "Emulator") -> StateTransitionResult | None:
        if not (result := PacketValidator.validateEthernetPacket(pkt, emulator)):
            return result
        
        if not (pkt[Ether].Type == 0x88e1):
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message="Packet is not HPGP"
            )

    @staticmethod
    def validateUDPPacket(pkt: Packet, emulator: "Emulator") -> StateTransitionResult | None:
        if not (result := PacketValidator.validateEthernetPacket(pkt, emulator)):
            return result
        
        if not (pkt.haslayer(IPv6)) :
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message="Packet is not IPv6"
            )
        
        if pkt[IPv6].dst != emulator.sourceIP and pkt[IPv6].dst != "ff02::1":
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message="IPv6 not addressed to this device"
            )
        
        if not (pkt.haslayer(UDP)):
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message="Packet is not UDP"
            )

    @staticmethod
    def validateV2GTPPacket(pkt: Packet, emulator: "Emulator") -> StateTransitionResult | None:
        if not (result := PacketValidator.validateEthernetPacket(pkt, emulator)):
            return result
        
        if not pkt.haslayer(IPv6):
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message="Packet is not IPv6"
            )
        
        if pkt[IPv6].dst != emulator.sourceIP:
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message="IPv6 not addressed to this device"
            )
        
        if not pkt.haslayer(TCP):
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message="Packet is not TCP"
            )
        
        if pkt[TCP].dport != emulator.sourcePort:
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message="TCP not addressed to this device"
            )
        

class AbstractState(ABC):
    # TODO: figure out context
    def __init__(self, context: StateContext) -> None:
        self.context = context
        self.emulator = context.emulator
        self.logger = context.emulator.logger
        self.onEnter()

    def __del__(self) -> None:
        self.onExit()

    def onEnter(self) -> None:
        """ Method called when entering the state"""
        self.logger.debug(f"Entering state: {self.name}")
        self.emulator.sendPacket(self.getOutgoingPackets())

    def onExit(self) -> None:
        """ Method called when exiting the state"""
        self.logger.debug(f"Exiting state: {self.name}")

    @property
    @abstractmethod
    def name(self) -> str:
        """ Returns the name of the state"""
    
    @property
    @abstractmethod
    def validIncomingPacketTypes(self) -> list[PacketType]:
        """ Returns a list of valid incoming packet types for this state"""

    @property
    @abstractmethod
    def shouldRetry(self) -> bool:
        """ Returns whether the state machine should retry to send the packet if no valid response is received"""

    @abstractmethod
    def getOutgoingPackets(self) -> list[Packet] | None:
        """ Returns a list of packets to be sent when entering this state, or None if no packet should be sent"""

    @abstractmethod
    def handlePacket(self, pkt: Packet) -> StateTransitionResult:
        """ Method called when a packet is received in this state.
            Returns a StateTransitionResult indicating the next state.
        """