"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
"""

from AbstractState import AbstractState
from EmulatorEnum import PacketType, StateMachineResponseType
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from Packets import *
from .secc import *

#########################################################################################################################
# PEV STATES #

class CM_SLAC_PARM_REQState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.CM_SLAC_PARM_CNF]
        return [pkt.value for pkt in pkts]
    
    @property
    def pktToSend(self) -> Packet | None:
        return SlacParmReq(self.emulator)

    @property
    def currentState(self) -> PacketType:
        return PacketType.CM_SLAC_PARM_REQ
    
    def handlePacket(self, receivedPacket: Packet) -> tuple:
        # Check if the packet is of type HPGP
        if not receivedPacket[Ether].type == 0x88e1:
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Check if the packet addressed to the emulator's MAC address
        if not receivedPacket[Ether].dst == self.emulator.sourceMAC:
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Update emulator timeout timer
        self.emulator.lastMessageTime = time.time()

        HPHPLayerName = self.expandPacketLayers(receivedPacket)[2]

        if HPHPLayerName not in self.validResponsePacketTypes:
            self.logger.warning(f"Received unexpected packet of type {HPHPLayerName} in state {self.currentState}")
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)

        # Only allowed packet should be CM_SLAC_PARM_CNF
        self.logger.debug(f"Received packet of type {HPHPLayerName} in state {self.currentState}")
        self.emulator.destinationMAC = receivedPacket[Ether].src
        self.emulator.runID = receivedPacket[CM_SLAC_PARM_CNF].RunID

        startAttenPkts = [StartAttenCharInd(self.emulator) for i in range(3)]
        soundPkts = [MNBCSoundInd(self.emulator) for i in range(10)]
        rspPkts = startAttenPkts + soundPkts
        return (CM_MNBC_SOUND_INDState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkts)

class CM_MNBC_SOUND_INDState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.CM_ATTEN_CHAR_IND]
        return [pkt.value for pkt in pkts]

    @property
    def pktToSend(self) -> Packet | None:
        return None
    
    @property
    def currentState(self) -> PacketType:
        return PacketType.CM_START_ATTEN_CHAR_IND
    
    def handlePacket(self, receivedPacket: Packet) -> tuple:
        # Check if the packet is of type HPGP
        if not receivedPacket[Ether].type == 0x88e1:
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Check if the packet addressed to the emulator's MAC address
        if not receivedPacket[Ether].dst == self.emulator.sourceMAC:
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)
        
        # Update emulator timeout timer
        self.emulator.lastMessageTime = time.time()

        HPHPLayerName = self.expandPacketLayers(receivedPacket)[2]

        if HPHPLayerName not in self.validResponsePacketTypes:
            self.logger.warning(f"Received unexpected packet of type {HPHPLayerName} in state {self.currentState}")
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)
        
        # Only allowed packet should be CM_ATTEN_CHAR_IND
        self.logger.debug(f"Received packet of type {HPHPLayerName} in state {self.currentState}")
        attenCharResPkt = AttenCharRes(self.emulator)
        slacMatchReqPkt = SlacMatchReq(self.emulator)
        rspPkts = [attenCharResPkt, slacMatchReqPkt]
        return (CM_SLAC_MATCH_REQState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkts)

class CM_SLAC_MATCH_REQState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.CM_SLAC_MATCH_CNF]
        return [pkt.value for pkt in pkts]
    
    @property
    def pktToSend(self) -> Packet | None:
        return SlacMatchReq(self.emulator)

    @property
    def currentState(self) -> PacketType:
        return PacketType.CM_SLAC_MATCH_REQ
    
    def handlePacket(self, receivedPacket: Packet) -> tuple:
        # Check if the packet is of type HPGP
        if not receivedPacket[Ether].type == 0x88e1:
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Check if the packet addressed to the emulator's MAC address
        if not receivedPacket[Ether].dst == self.emulator.sourceMAC:
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Update emulator timeout timer
        self.emulator.lastMessageTime = time.time()

        HPHPLayerName = self.expandPacketLayers(receivedPacket)[2]

        if HPHPLayerName not in self.validResponsePacketTypes:
            self.logger.warning(f"Received unexpected packet of type {HPHPLayerName} in state {self.currentState}")
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)

        # Only allowed packet should be CM_SLAC_MATCH_CNF
        self.logger.debug(f"Received packet of type {HPHPLayerName} in state {self.currentState}")
        self.emulator.NID = receivedPacket[CM_SLAC_MATCH_CNF].VariableField.NetworkID
        self.emulator.NMK = receivedPacket[CM_SLAC_MATCH_CNF].VariableField.NMK

        setKeyPkt = [SetKeyReq(self.emulator)]
        SECCpkts = [SECCRequest(self.emulator) for i in range(3)]
        rspPkts = setKeyPkt + SECCpkts
        
        return (SDPRequestState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkts)

#########################################################################################################################
# EVSE STATES #

class CM_SET_KEY_REQState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.CM_SLAC_PARM_REQ]
        return [pkt.value for pkt in pkts]
    
    @property
    def pktToSend(self) -> Packet | None:
        return None

    @property
    def currentState(self) -> PacketType:
        return PacketType.CM_SET_KEY_REQ
    
    def handlePacket(self, receivedPacket: Packet) -> tuple:
        # Check if the packet is of type HPGP
        if not receivedPacket[Ether].type == 0x88e1:
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Check if the packet broadcast
        if not receivedPacket[Ether].dst == "ff:ff:ff:ff:ff:ff":
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Update emulator timeout timer
        self.emulator.lastMessageTime = time.time()

        HPHPLayerName = self.expandPacketLayers(receivedPacket)[2]

        if HPHPLayerName not in self.validResponsePacketTypes:
            self.logger.warning(f"Received unexpected packet of type {HPHPLayerName} in state {self.currentState}")
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)

        # Only allowed packet should be CM_SLAC_PARM_REQ
        self.logger.debug(f"Received packet of type {HPHPLayerName} in state {self.currentState}")

        self.emulator.destinationMAC = receivedPacket[Ether].src
        self.emulator.runID = receivedPacket[CM_SLAC_PARM_REQ].RunID

        rspPkt = SlacParmCnf(self.emulator)

        return (CM_SLAC_PARM_CNFState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkt)

class CM_SLAC_PARM_CNFState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.CM_MNBC_SOUND_IND]
        return [pkt.value for pkt in pkts]
    
    @property
    def pktToSend(self) -> Packet | None:
        return SlacParmCnf(self.emulator)
    
    @property
    def currentState(self) -> PacketType:
        return PacketType.CM_SLAC_PARM_CNF
    
    def handlePacket(self, receivedPacket: Packet) -> tuple:
        # Check if the packet is of type HPGP
        if not receivedPacket[Ether].type == 0x88e1:
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)
        
        # Check if the packet is broadcast
        if not receivedPacket[Ether].dst == "ff:ff:ff:ff:ff:ff":
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)
        
        # Update emulator timeout timer
        self.emulator.lastMessageTime = time.time()

        HPHPLayerName = self.expandPacketLayers(receivedPacket)[2]

        if HPHPLayerName not in self.validResponsePacketTypes:
            self.logger.warning(f"Received unexpected packet of type {HPHPLayerName} in state {self.currentState}")
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)
        
        # Only allowed packet should be CM_MNBC_SOUND_IND
        countdownVal = receivedPacket[CM_MNBC_SOUND_IND].Countdown
        self.logger.debug(f"Received packet of type {HPHPLayerName} in state {self.currentState} with countdown value {countdownVal}")

        if countdownVal > 0:
            return (self, StateMachineResponseType.NO_TRANSITION_VALID_PACKET, None)
        
        rspPkt = AttenCharInd(self.emulator)
        return (CM_ATTEN_CHAR_INDState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkt)
    
class CM_ATTEN_CHAR_INDState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.CM_SLAC_MATCH_REQ]
        return [pkt.value for pkt in pkts]
    
    @property
    def pktToSend(self) -> Packet | None:
        return AttenCharInd(self.emulator)

    @property
    def currentState(self) -> PacketType:
        return PacketType.CM_ATTEN_CHAR_IND
    
    def handlePacket(self, receivedPacket: Packet) -> tuple:
        # Check if the packet is of type HPGP
        if not receivedPacket[Ether].type == 0x88e1:
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Check if the packet addressed to the emulator's MAC address
        if not receivedPacket[Ether].dst == self.emulator.sourceMAC:
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Update emulator timeout timer
        self.emulator.lastMessageTime = time.time()

        HPHPLayerName = self.expandPacketLayers(receivedPacket)[2]

        if HPHPLayerName not in self.validResponsePacketTypes:
            self.logger.warning(f"Received unexpected packet of type {HPHPLayerName} in state {self.currentState}")
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)

        # Only allowed packet should be CM_SLAC_MATCH_REQ
        self.logger.debug(f"Received packet of type {HPHPLayerName} in state {self.currentState}")
        slacMatchCnfPkt = SlacMatchCnf(self.emulator)
        rspPkts = [slacMatchCnfPkt]
        return (CM_SLAC_MATCH_CNFState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkts)
    
class CM_SLAC_MATCH_CNFState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.SDPRequest]
        return [pkt.value for pkt in pkts]
    
    @property
    def pktToSend(self) -> Packet | None:
        return SlacMatchCnf(self.emulator)
    
    @property
    def currentState(self) -> PacketType:
        return PacketType.CM_SLAC_MATCH_CNF
    
    def handlePacket(self, receivedPacket: Packet) -> tuple:
        # Check if packet has IPv6 and is broadcast
        if not (receivedPacket.haslayer(IPv6) and receivedPacket[IPv6].dst == "ff02::1"):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)
        
        # Check if packet has UDP and is addressed to correct port
        if not (receivedPacket.haslayer(UDP) and receivedPacket[UDP].dport == 15118):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)
        
        # Check if packet has SECC layer
        if not receivedPacket.haslayer("SECC"):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)
        
        SECCtype = self.expandPacketLayers(receivedPacket)[4]

        if SECCtype not in self.validResponsePacketTypes:
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)
        
        # Only allowed packet should be SDP Request
        self.logger.debug(f"Received packet of type {SECCtype} in state {self.currentState}")

        self.emulator.destinationIP = receivedPacket[IPv6].src
        self.emulator.destinationPort = receivedPacket[UDP].sport

        rspPkts = [SECCResponse(self.emulator) for i in range(3)]
        return (SDPResponseState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkts)