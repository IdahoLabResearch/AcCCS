"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
"""

from .AbstractState import *
from EmulatorEnum import PacketType
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from Packets import *
from .secc import *

#########################################################################################################################
# PEV STATES #

class CM_SLAC_PARM_REQ_State(AbstractState):
    def __init__(self, context):
        super().__init__(context)

    @property
    def name(self) -> str:
        return "CM_SLAC_PARM_REQ"

    @property
    def validIncomingPacketTypes(self) -> list[PacketType]:
        pkts = [PacketType.CM_SLAC_PARM_CNF]
        return pkts
    
    def shouldRetry(self) -> bool:
        return True

    def getOutgoingPackets(self) -> list[Packet]:
        return [SlacParmReq(self.emulator)]

    def handlePacket(self, pkt: Packet) -> StateTransitionResult:
        if (result := PacketValidator.validateEthernetPacket(pkt, self.emulator)) is not None:
            return result

        if (result := PacketValidator.validateHPGPPacket(pkt, self.emulator)) is not None:
            return result

        # Update emulator timeout timer
        self.emulator.lastMessageTime = time.time()

        HPGPLayerName = expandPacketLayers(pkt)[2]

        if HPGPLayerName not in [pkt_type.value for pkt_type in self.validIncomingPacketTypes]:
            self.logger.warning(f"Received unexpected packet of type {HPGPLayerName} in state {self.name}")
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message=f"Received unexpected packet of type {HPGPLayerName} in state {self.name}"
            )

        # Only allowed packet should be CM_SLAC_PARM_CNF
        self.logger.debug(f"Received packet of type {HPGPLayerName} in state {self.name}")
        self.emulator.destinationMAC = pkt[Ether].src
        self.emulator.runID = pkt[CM_SLAC_PARM_CNF].RunID

        return StateTransitionResult(
            success=True,
            next_state=CM_MNBC_SOUND_IND_State(self.context),
            error_message=None
        )


class CM_MNBC_SOUND_IND_State(AbstractState):
    def __init__(self, context):
        super().__init__(context)

    @property
    def name(self) -> str:
        return "CM_MNBC_SOUND_IND"

    @property
    def validIncomingPacketTypes(self) -> list[PacketType]:
        return [PacketType.CM_ATTEN_CHAR_IND]
    
    def shouldRetry(self) -> bool:
        return False

    def getOutgoingPackets(self) -> list[Packet]:
        startAttenPkts = [StartAttenCharInd(self.emulator) for i in range(3)]
        soundPkts = [MNBCSoundInd(self.emulator) for i in range(10)]
        rspPkts = startAttenPkts + soundPkts
        return rspPkts
    
    def handlePacket(self, pkt: Packet) -> StateTransitionResult:
        if (result := PacketValidator.validateEthernetPacket(pkt, self.emulator)) is not None:
            return result

        if (result := PacketValidator.validateHPGPPacket(pkt, self.emulator)) is not None:
            return result
        
        # Update emulator timeout timer
        self.emulator.lastMessageTime = time.time()

        HPGPLayerName = expandPacketLayers(pkt)[2]

        if HPGPLayerName not in [pkt_type.value for pkt_type in self.validIncomingPacketTypes]:
            self.logger.warning(f"Received unexpected packet of type {HPGPLayerName} in state {self.name}")
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message=f"Received unexpected packet of type {HPGPLayerName} in state {self.name}"
            )
        
        # Only allowed packet should be CM_ATTEN_CHAR_IND
        self.logger.debug(f"Received packet of type {HPGPLayerName} in state {self.name}")

        return StateTransitionResult(
            success=True,
            next_state=CM_SLAC_MATCH_REQ_State(self.context),
            error_message=None
        )

class CM_SLAC_MATCH_REQ_State(AbstractState):
    def __init__(self, context):
        super().__init__(context)

    @property
    def name(self) -> str:
        return "CM_SLAC_MATCH_REQ"

    @property
    def validIncomingPacketTypes(self) -> list[PacketType]:
        return [PacketType.CM_SLAC_MATCH_CNF]
    
    def shouldRetry(self) -> bool:
        return False

    def getOutgoingPackets(self) -> list[Packet]:
        attenCharResPkt = AttenCharRes(self.emulator)
        slacMatchReqPkt = SlacMatchReq(self.emulator)
        rspPkts = [attenCharResPkt, slacMatchReqPkt]
        return rspPkts
    
    def handlePacket(self, pkt: Packet) -> StateTransitionResult:
        if (result := PacketValidator.validateEthernetPacket(pkt, self.emulator)) is not None:
            return result
        if (result := PacketValidator.validateHPGPPacket(pkt, self.emulator)) is not None:
            return result 

        # Update emulator timeout timer
        self.emulator.lastMessageTime = time.time()

        HPGPLayerName = expandPacketLayers(pkt)[2]

        if HPGPLayerName not in [pkt_type.value for pkt_type in self.validIncomingPacketTypes]:
            self.logger.warning(f"Received unexpected packet of type {HPGPLayerName} in state {self.name}")
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message=f"Received unexpected packet of type {HPGPLayerName} in state {self.name}"
            )

        # Only allowed packet should be CM_SLAC_MATCH_CNF
        self.logger.debug(f"Received packet of type {HPGPLayerName} in state {self.name}")
        self.emulator.NID = pkt[CM_SLAC_MATCH_CNF].VariableField.NetworkID
        self.emulator.NMK = pkt[CM_SLAC_MATCH_CNF].VariableField.NMK

        # TODO: Move this
        setKeyPkt = [SetKeyReq(self.emulator)]
        SECCpkts = [SECCRequest(self.emulator) for i in range(3)]
        rspPkts = setKeyPkt + SECCpkts
        
        return StateTransitionResult(
            success=True,
            next_state=SDPRequestState(self.context),
            error_message=None
        )

#########################################################################################################################
# EVSE STATES #

class CM_SET_KEY_REQ_State(AbstractState):
    def __init__(self, context):
        super().__init__(context)

    @property
    def name(self) -> str:
        return "CM_SET_KEY_REQ"

    @property
    def validIncomingPacketTypes(self) -> list[PacketType]:
        return [PacketType.CM_SLAC_PARM_REQ]

    def shouldRetry(self) -> bool:
        return False

    def getOutgoingPackets(self) -> list[Packet]:
        return [SetKeyReq(self.emulator)]
    
    def handlePacket(self, pkt: Packet) -> StateTransitionResult:
        if (result := PacketValidator.validateEthernetPacket(pkt, self.emulator)) is not None:
            return result
        
        if (result := PacketValidator.validateHPGPPacket(pkt, self.emulator)) is not None:
            return result

        # Update emulator timeout timer
        self.emulator.lastMessageTime = time.time()

        HPGPLayerName = expandPacketLayers(pkt)[2]

        if HPGPLayerName not in [pkt_type.value for pkt_type in self.validIncomingPacketTypes]:
            self.logger.warning(f"Received unexpected packet of type {HPGPLayerName} in state {self.name}")
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message=f"Received unexpected packet of type {HPGPLayerName} in state {self.name}"
            )

        # Only allowed packet should be CM_SLAC_PARM_REQ
        self.logger.debug(f"Received packet of type {HPGPLayerName} in state {self.name}")

        self.emulator.destinationMAC = pkt[Ether].src
        self.emulator.runID = pkt[CM_SLAC_PARM_REQ].RunID

        return StateTransitionResult(
            success=True,
            next_state=CM_SLAC_PARM_CNF_State(self.context),
            error_message=None
        )

class CM_SLAC_PARM_CNF_State(AbstractState):
    def __init__(self, context):
        super().__init__(context)

    @property
    def name(self) -> str:
        return "CM_SLAC_PARM_CNF"

    @property
    def validIncomingPacketTypes(self) -> list[PacketType]:
        return [PacketType.CM_MNBC_SOUND_IND]
    
    def shouldRetry(self) -> bool:
        return True

    def getOutgoingPackets(self) -> list[Packet]:
        return [SlacParmCnf(self.emulator)]
    
    def handlePacket(self, pkt: Packet) -> StateTransitionResult:
        if (result := PacketValidator.validateEthernetPacket(pkt, self.emulator)) is not None:
            return result
        
        if (result := PacketValidator.validateHPGPPacket(pkt, self.emulator)) is not None:
            return result
        
        # Check if the packet is broadcast
        if not pkt[Ether].dst == "ff:ff:ff:ff:ff:ff":
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message=None
            )
        
        # Update emulator timeout timer
        self.emulator.lastMessageTime = time.time()

        HPGPLayerName = expandPacketLayers(pkt)[2]

        if HPGPLayerName not in [pkt_type.value for pkt_type in self.validIncomingPacketTypes]:
            self.logger.warning(f"Received unexpected packet of type {HPGPLayerName} in state {self.name}")
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message=f"Received unexpected packet of type {HPGPLayerName} in state {self.name}"
            )
        
        # Only allowed packet should be CM_MNBC_SOUND_IND
        countdownVal = pkt[CM_MNBC_SOUND_IND].Countdown
        self.logger.debug(f"Received packet of type {HPGPLayerName} in state {self.name} with countdown value {countdownVal}")

        if countdownVal > 0:
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message=None
            )
        
        return StateTransitionResult(
            success=True,
            next_state=CM_ATTEN_CHAR_IND_State(self.context),
            error_message=None
        )
    
class CM_ATTEN_CHAR_IND_State(AbstractState):
    def __init__(self, context):
        super().__init__(context)

    @property
    def name(self) -> str:
        return "CM_ATTEN_CHAR_IND"

    @property
    def validIncomingPacketTypes(self) -> list[PacketType]:
        return [PacketType.CM_SLAC_MATCH_REQ]
    
    def shouldRetry(self) -> bool:
        return False

    def getOutgoingPackets(self) -> list[Packet]:
        return [AttenCharInd(self.emulator)]
    
    def handlePacket(self, pkt: Packet) -> StateTransitionResult:
        if (result := PacketValidator.validateEthernetPacket(pkt, self.emulator)) is not None:
            return result
        
        if (result := PacketValidator.validateHPGPPacket(pkt, self.emulator)) is not None:
            return result

        # Update emulator timeout timer
        self.emulator.lastMessageTime = time.time()

        HPGPLayerName = expandPacketLayers(pkt)[2]

        if HPGPLayerName not in [pkt_type.value for pkt_type in self.validIncomingPacketTypes]:
            self.logger.warning(f"Received unexpected packet of type {HPGPLayerName} in state {self.name}")
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message=f"Received unexpected packet of type {HPGPLayerName} in state {self.name}"
            )

        # Only allowed packet should be CM_SLAC_MATCH_REQ
        self.logger.debug(f"Received packet of type {HPGPLayerName} in state {self.name}")

        return StateTransitionResult(
            success=True,
            next_state=CM_SLAC_MATCH_CNF_State(self.context),
            error_message=None
        )
    
class CM_SLAC_MATCH_CNF_State(AbstractState):
    def __init__(self, context):
        super().__init__(context)

    @property
    def name(self) -> str:
        return "CM_SLAC_MATCH_CNF"

    @property
    def validIncomingPacketTypes(self) -> list[PacketType]:
        return [PacketType.SDPRequest]

    @property
    def shouldRetry(self) -> bool:
        return True

    def getOutgoingPackets(self) -> list[Packet]:
        return [SlacMatchCnf(self.emulator)]
    
    def handlePacket(self, pkt: Packet) -> StateTransitionResult:
        if (result := PacketValidator.validateUDPPacket(pkt, self.emulator)):
            return result
        
        if pkt[UDP].dport != 15118:
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message="UDP packet not addressed to port 15118"
            )
        
        # Check if packet has SECC layer
        if not pkt.haslayer("SECC"):
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message="Packet does not have SECC layer"
            )
        
        SECCtype = expandPacketLayers(pkt)[4]

        if SECCtype not in [pkt_type.value for pkt_type in self.validIncomingPacketTypes]:
            return StateTransitionResult(
                success=False,
                next_state=None,
                error_message=f"Received unexpected packet of type {SECCtype} in state {self.name}"
            )
        
        # Only allowed packet should be SDP Request
        self.logger.debug(f"Received packet of type {SECCtype} in state {self.name}")

        self.emulator.destinationIP = pkt[IPv6].src
        self.emulator.destinationPort = pkt[UDP].sport

        return StateTransitionResult(
            success=True,
            next_state=SDPResponseState(self.context),
            error_message=None
        )