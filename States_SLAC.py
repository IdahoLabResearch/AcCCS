"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
"""

from AbstractState import AbstractState
from EmulatorEnum import PacketType, StateMachineResponseType
from scapy.all import *
from Packets import *
from States_SECC import SDPRequestState

import logging
logger = logging.getLogger(__name__)

class CM_SLAC_PARM_REQState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.CM_SLAC_PARM_CNF]
        return [pkt.value for pkt in pkts]
    
    @property
    def pktToSend(self) -> Packet:
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
            logger.warning(f"Received unexpected packet of type {HPHPLayerName} in state {self.currentState}")
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)

        # Only allowed packet should be CM_SLAC_PARM_CNF
        logger.debug(f"Received packet of type {HPHPLayerName} in state {self.currentState}")
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
    def pktToSend(self) -> Packet:
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
            logger.warning(f"Received unexpected packet of type {HPHPLayerName} in state {self.currentState}")
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)
        
        # Only allowed packet should be CM_ATTEN_CHAR_IND
        logger.debug(f"Received packet of type {HPHPLayerName} in state {self.currentState}")
        attenCharResPkt = AttenCharRes(self.emulator)
        slacMatchReqPkt = SlacMatchReq(self.emulator)
        rspPkts = [attenCharResPkt, slacMatchReqPkt]
        return (CM_SLAC_MATCH_REQState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkts)

class CM_ATTEN_CHAR_RSPState(AbstractState):
    def __init__(self):
        pass

class CM_VALIDATE_REQState(AbstractState):
    def __init__(self):
        pass

class CM_SLAC_MATCH_REQState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.CM_SLAC_MATCH_CNF]
        return [pkt.value for pkt in pkts]
    
    @property
    def pktToSend(self) -> Packet:
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
            logger.warning(f"Received unexpected packet of type {HPHPLayerName} in state {self.currentState}")
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)

        # Only allowed packet should be CM_SLAC_MATCH_CNF
        logger.debug(f"Received packet of type {HPHPLayerName} in state {self.currentState}")
        self.emulator.NID = receivedPacket[CM_SLAC_MATCH_CNF].VariableField.NetworkID
        self.emulator.NMK = receivedPacket[CM_SLAC_MATCH_CNF].VariableField.NMK

        setKeyPkt = [SetKeyReq(self.emulator)]
        SECCpkts = [SECCRequest(self.emulator) for i in range(3)]
        rspPkts = setKeyPkt + SECCpkts
        
        return (SDPRequestState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkts)


class CM_AMP_MAP_CNFState(AbstractState):
    def __init__(self):
        pass

class CM_SET_KEY_REQState(AbstractState):
    def __init__(self):
        pass