"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
"""

from .AbstractState import AbstractState
from EmulatorEnum import PacketType, StateMachineResponseType
from scapy.layers.inet import TCP
from scapy.packet import Packet
from Packets import *
from V2Gjson.din import *
from V2Gjson.apphand import *
from .din import *
from EmulatorEnum import EXIProtocol

#########################################################################################################################
# PEV STATES #

class supportedAppProtocolReqState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.supportedAppProtocolRes]
        return [pkt.value for pkt in pkts]

    @property
    def pktToSend(self) -> Packet | None:

        if self.emulator.protocol == EXIProtocol.DIN:
            AppProtocol = AppProtocolType(ProtocolNamespace="urn:din:70121:2012:MsgDef", VersionNumberMajor=2, VersionNumberMinor=0, SchemaID=1, Priority=1)
        elif self.emulator.protocol == EXIProtocol.ISO_2:
            AppProtocol = AppProtocolType(ProtocolNamespace="urn:iso:15118:2:2013:MsgDef", VersionNumberMajor=2, VersionNumberMinor=0, SchemaID=1, Priority=1)
        elif self.emulator.protocol == EXIProtocol.ISO_20:
            raise Exception("ISO 15118-20 not yet implemented")
        
        supportedAppProtocolReqPayload = supportedAppProtocolReq(AppProtocol=[AppProtocol])
        EXIpayload = self.emulator.EXIProcessor.encode(supportedAppProtocolReqPayload)
        if EXIpayload is None:
            raise Exception(f"Error during EXI encoding while in {self.currentState} state")
        
        return V2G(self.emulator, EXIpayload)
        

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
        Header = MessageHeaderType(SessionID=self.emulator.SessionID)
        SessionSetupReq = SessionSetupReqType(EVCCID=self.emulator.EVCCID)
        Body = BodyType(SessionSetupReq=SessionSetupReq)
        V2Gpayload = V2G_Message(Header=Header, Body=Body)

        EXIpayload = self.emulator.EXIProcessor.encode(V2Gpayload)
        if EXIpayload is None:
            raise Exception(f"Error during EXI encoding while in {self.currentState} state")

        rspPkt = V2G(self.emulator, EXIpayload)
        return (SessionSetupReqState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkt)

#########################################################################################################################
# EVSE STATES #

class supportedAppProtocolResState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.SessionSetupReq]
        return [pkt.value for pkt in pkts]

    @property
    def pktToSend(self) -> Packet | None:

        SupportedAppProtocolRes = supportedAppProtocolRes(ResponseCode=responseCodeType.OK)
        Body = BodyType(SupportedAppProtocolResponse=SupportedAppProtocolResponse)
        V2Gpayload = V2G_Message(
            Header=MessageHeaderType(SessionID=self.emulator.SessionID),
            Body=Body
        )

        return V2G(self.emulator, self.emulator.appHandshake.encode(SupportedAppProtocolResponse()))

    @property
    def currentState(self) -> PacketType:
        return PacketType.supportedAppProtocolRes
    
    def handlePacket(self, receivedPacket):
        a = self._handlePacketTCPHelper(receivedPacket)
        if not a[0]:
            return (self, a[1], None)
        
        self.emulator.sessionID = bytearray(random.randbytes(8))
        self.logger.info(f"Generated new SessionID: {self.emulator.sessionID.hex()}")
        
        rspPkt = V2G(self.emulator, self.emulator.EXIProcessor.encode(SessionSetupResponse(sessionID=self.emulator.sessionID)))
        return (SessionSetupResState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkt)