from AbstractState import AbstractState
from scapy.all import *
from Packets import *
from EmulatorEnum import *
from V2Gjson import *

import logging
logger = logging.getLogger(__name__)

class SessionSetupReqState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.SessionSetupRes]
        return [pkt.value for pkt in pkts]
    
    @property
    def pktToSend(self) -> Packet:
        return V2G(self.emulator, self.emulator.din.encode(SessionSetupRequest()))
    
    @property
    def currentState(self) -> PacketType:
        return PacketType.SessionSetupReq

    def handlePacket(self, receivedPacket):
        # Check if packet is TCP, addressed to us, is PSH
        if not (receivedPacket.haslayer(TCP) and receivedPacket[TCP].dport == self.emulator.sourcePort and 'P' in receivedPacket[TCP].flags):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Check if packet is V2G packet
        if not receivedPacket.haslayer("Raw"):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        exiString = V2GTP(receivedPacket[Raw].load).Payload
        xmlJson = self.emulator.din.decode(exiString)
        pktName = list(xmlJson["Body"].keys())[0]

        if pktName not in self.validResponsePacketTypes:
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)

        # Packet should be sessionSetupRes
        self.emulator.seq = receivedPacket[TCP].ack
        self.emulator.ack = receivedPacket[TCP].seq + len(receivedPacket[TCP].payload)

        self.emulator.sessionID = bytearray(xmlJson["Header"]["SessionID"]["bytes"])

        rspPkt = V2G(self.emulator, self.emulator.din.encode(ServiceDiscoveryRequest(sessionID=self.emulator.sessionID)))
        return (ServiceDiscoveryReqState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkt)

class ServiceDiscoveryReqState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.ServiceDiscoveryRes]
        return [pkt.value for pkt in pkts]
    
    @property
    def pktToSend(self) -> Packet:
        return V2G(self.emulator, self.emulator.din.encode(ServiceDiscoveryRequest(sessionID=self.emulator.sessionID)))

    @property
    def currentState(self) -> PacketType:
        return PacketType.ServiceDiscoveryReq
    
    def handlePacket(self, receivedPacket):
        # Check if packet is TCP, addressed to us, is PSH
        if not (receivedPacket.haslayer(TCP) and receivedPacket[TCP].dport == self.emulator.sourcePort and 'P' in receivedPacket[TCP].flags):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Check if packet is V2G packet
        if not receivedPacket.haslayer("Raw"):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        exiString = V2GTP(receivedPacket[Raw].load).Payload
        xmlJson = self.emulator.din.decode(exiString)
        pktName = list(xmlJson["Body"].keys())[0]

        if pktName not in self.validResponsePacketTypes:
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)

        # Packet should be serviceDiscoveryRes
        self.emulator.seq = receivedPacket[TCP].ack
        self.emulator.ack = receivedPacket[TCP].seq + len(receivedPacket[TCP].payload)

        rspPkt = V2G(self.emulator, self.emulator.din.encode(ServicePaymentSelectionRequest(sessionID=self.emulator.sessionID)))
        return (ServicePaymentSelectionReqState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkt)
    
class ServicePaymentSelectionReqState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.ServicePaymentSelectionRes]
        return [pkt.value for pkt in pkts]

    @property
    def pktToSend(self) -> Packet:
        return V2G(self.emulator, self.emulator.din.encode(ServicePaymentSelectionRequest(sessionID=self.emulator.sessionID)))

    @property
    def currentState(self) -> PacketType:
        return PacketType.ServicePaymentSelectionReq

    def handlePacket(self, receivedPacket):
        # Check if packet is TCP, addressed to us, is PSH
        if not (receivedPacket.haslayer(TCP) and receivedPacket[TCP].dport == self.emulator.sourcePort and 'P' in receivedPacket[TCP].flags):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Check if packet is V2G packet
        if not receivedPacket.haslayer("Raw"):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        exiString = V2GTP(receivedPacket[Raw].load).Payload
        xmlJson = self.emulator.din.decode(exiString)
        pktName = list(xmlJson["Body"].keys())[0]

        if pktName not in self.validResponsePacketTypes:
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)

        # Packet should be servicePaymentSelectionRes
        self.emulator.seq = receivedPacket[TCP].ack
        self.emulator.ack = receivedPacket[TCP].seq + len(receivedPacket[TCP].payload)

        rspPkt = V2G(self.emulator, self.emulator.din.encode(ContractAuthenticationRequest(sessionID=self.emulator.sessionID)))
        return (ContractAuthenticationReqState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkt)

class ContractAuthenticationReqState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.ContractAuthenticationRes]
        return [pkt.value for pkt in pkts]

    @property
    def pktToSend(self) -> Packet:
        return V2G(self.emulator, self.emulator.din.encode(ContractAuthenticationRequest(sessionID=self.emulator.sessionID)))

    @property
    def currentState(self) -> PacketType:
        return PacketType.ContractAuthenticationReq

    def handlePacket(self, receivedPacket):
        # Check if packet is TCP, addressed to us, is PSH
        if not (receivedPacket.haslayer(TCP) and receivedPacket[TCP].dport == self.emulator.sourcePort and 'P' in receivedPacket[TCP].flags):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Check if packet is V2G packet
        if not receivedPacket.haslayer("Raw"):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        exiString = V2GTP(receivedPacket[Raw].load).Payload
        xmlJson = self.emulator.din.decode(exiString)
        pktName = list(xmlJson["Body"].keys())[0]

        if pktName not in self.validResponsePacketTypes:
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)

        # Packet should be ContractAuthenticationRes
        self.emulator.seq = receivedPacket[TCP].ack
        self.emulator.ack = receivedPacket[TCP].seq + len(receivedPacket[TCP].payload)

        evseProcessing = xmlJson["Body"]["ContractAuthenticationRes"]["EVSEProcessing"]

        if evseProcessing == EVSEProcessingMap.get("Ongoing", 1):
            rspPkt = V2G(self.emulator, self.emulator.din.encode(ContractAuthenticationRequest(sessionID=self.emulator.sessionID)))
            return (self, StateMachineResponseType.NO_TRANSITION_VALID_PACKET, rspPkt)
        elif evseProcessing == EVSEProcessingMap.get("Finished", 0):
            rspPkt = V2G(self.emulator, self.emulator.din.encode(ChargeParameterDiscoveryRequest(sessionID=self.emulator.sessionID)))
            return (ChargeParameterDiscoveryReqState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkt)
        else:
            raise ValueError(f"Invalid EVSEProcessing state: {evseProcessing} while in ContractAuthenticationReqState")

class ChargeParameterDiscoveryReqState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.ChargeParameterDiscoveryRes]
        return [pkt.value for pkt in pkts]

    @property
    def pktToSend(self) -> Packet:
        return V2G(self.emulator, self.emulator.din.encode(ChargeParameterDiscoveryRequest(sessionID=self.emulator.sessionID)))
    
    @property
    def currentState(self) -> PacketType:
        return PacketType.ChargeParameterDiscoveryReq
    
    def handlePacket(self, receivedPacket):
        # Check if packet is TCP, addressed to us, is PSH
        if not (receivedPacket.haslayer(TCP) and receivedPacket[TCP].dport == self.emulator.sourcePort and 'P' in receivedPacket[TCP].flags):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Check if packet is V2G packet
        if not receivedPacket.haslayer("Raw"):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        exiString = V2GTP(receivedPacket[Raw].load).Payload
        xmlJson = self.emulator.din.decode(exiString)
        pktName = list(xmlJson["Body"].keys())[0]

        if pktName not in self.validResponsePacketTypes:
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)

        # Packet should be ChargeParameterDiscoveryRes
        self.emulator.seq = receivedPacket[TCP].ack
        self.emulator.ack = receivedPacket[TCP].seq + len(receivedPacket[TCP].payload)

        evseProsessing = xmlJson["Body"]["ChargeParameterDiscoveryRes"]["EVSEProcessing"]

        if evseProsessing == EVSEProcessingMap.get("Ongoing", 1):
            rspPkt = V2G(self.emulator, self.emulator.din.encode(ChargeParameterDiscoveryRequest(sessionID=self.emulator.sessionID)))
            return (self, StateMachineResponseType.NO_TRANSITION_VALID_PACKET, rspPkt)
        elif evseProsessing == EVSEProcessingMap.get("Finished", 0):
            rspPkt = V2G(self.emulator, self.emulator.din.encode(CableCheckRequest(sessionID=self.emulator.sessionID)))
            return (CableCheckReqState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkt)
        else:
            raise ValueError(f"Invalid EVSEProcessing state: {evseProsessing} while in ChargeParameterDiscoveryReqState")

class PowerDeliveryReqState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.PowerDeliveryRes]
        return [pkt.value for pkt in pkts]
    
    @property
    def pktToSend(self) -> Packet:
        return V2G(self.emulator, self.emulator.din.encode(PowerDeliveryRequest(sessionID=self.emulator.sessionID)))

    @property
    def currentState(self) -> PacketType:
        return PacketType.PowerDeliveryReq
    
    def handlePacket(self, receivedPacket):
        # Check if packet is TCP, addressed to us, is PSH
        if not (receivedPacket.haslayer(TCP) and receivedPacket[TCP].dport == self.emulator.sourcePort and 'P' in receivedPacket[TCP].flags):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Check if packet is V2G packet
        if not receivedPacket.haslayer("Raw"):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        exiString = V2GTP(receivedPacket[Raw].load).Payload
        xmlJson = self.emulator.din.decode(exiString)
        pktName = list(xmlJson["Body"].keys())[0]

        if pktName not in self.validResponsePacketTypes:
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)

        # Packet should be PowerDeliveryRes
        self.emulator.seq = receivedPacket[TCP].ack
        self.emulator.ack = receivedPacket[TCP].seq + len(receivedPacket[TCP].payload)

        rspPkt = V2G(self.emulator, self.emulator.din.encode(CurrentDemandRequest(sessionID=self.emulator.sessionID)))
        return (CurrentDemandReqState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkt)

class SessionStopReqState(AbstractState):
    def __init__(self):
        pass

class CableCheckReqState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.CableCheckRes]
        return [pkt.value for pkt in pkts]

    @property
    def pktToSend(self) -> Packet:
        return V2G(self.emulator, self.emulator.din.encode(CableCheckRequest(sessionID=self.emulator.sessionID)))

    @property
    def currentState(self) -> PacketType:
        return PacketType.CableCheckReq
    
    def handlePacket(self, receivedPacket):
        # Check if packet is TCP, addressed to us, is PSH
        if not (receivedPacket.haslayer(TCP) and receivedPacket[TCP].dport == self.emulator.sourcePort and 'P' in receivedPacket[TCP].flags):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Check if packet is V2G packet
        if not receivedPacket.haslayer("Raw"):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        exiString = V2GTP(receivedPacket[Raw].load).Payload
        xmlJson = self.emulator.din.decode(exiString)
        pktName = list(xmlJson["Body"].keys())[0]

        if pktName not in self.validResponsePacketTypes:
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)

        # Packet should be CableCheckRes
        self.emulator.seq = receivedPacket[TCP].ack
        self.emulator.ack = receivedPacket[TCP].seq + len(receivedPacket[TCP].payload)

        evseProcessing = xmlJson["Body"]["CableCheckRes"]["EVSEProcessing"]

        if evseProcessing == EVSEProcessingMap.get("Ongoing", 1):
            rspPkt = V2G(self.emulator, self.emulator.din.encode(CableCheckRequest(sessionID=self.emulator.sessionID)))
            return (self, StateMachineResponseType.NO_TRANSITION_VALID_PACKET, rspPkt)
        elif evseProcessing == EVSEProcessingMap.get("Finished", 0):
            rspPkt = V2G(self.emulator, self.emulator.din.encode(PreChargeRequest(sessionID=self.emulator.sessionID)))
            return (PreChargeReqState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkt)
        else:
            raise ValueError(f"Invalid EVSEProcessing state: {evseProcessing} while in CableCheckReqState")

class PreChargeReqState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.PreChargeRes]
        return [pkt.value for pkt in pkts]

    @property
    def pktToSend(self) -> Packet:
        return V2G(self.emulator, self.emulator.din.encode(PreChargeRequest(sessionID=self.emulator.sessionID)))

    @property
    def currentState(self) -> PacketType:
        return PacketType.PreChargeReq
    
    def handlePacket(self, receivedPacket):
        # Check if packet is TCP, addressed to us, is PSH
        if not (receivedPacket.haslayer(TCP) and receivedPacket[TCP].dport == self.emulator.sourcePort and 'P' in receivedPacket[TCP].flags):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Check if packet is V2G packet
        if not receivedPacket.haslayer("Raw"):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        exiString = V2GTP(receivedPacket[Raw].load).Payload
        xmlJson = self.emulator.din.decode(exiString)
        pktName = list(xmlJson["Body"].keys())[0]

        if pktName not in self.validResponsePacketTypes:
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)

        # Packet should be PreChargeRes
        self.emulator.seq = receivedPacket[TCP].ack
        self.emulator.ack = receivedPacket[TCP].seq + len(receivedPacket[TCP].payload)

        rspPkt = V2G(self.emulator, self.emulator.din.encode(PowerDeliveryRequest(sessionID=self.emulator.sessionID)))
        return (PowerDeliveryReqState(self.emulator), StateMachineResponseType.SUCCESSFUL_TRANSITION, rspPkt)

class CurrentDemandReqState(AbstractState):
    @property
    def validResponsePacketTypes(self) -> list:
        pkts = [PacketType.CurrentDemandRes, PacketType.SessionStopReq]
        return [pkt.value for pkt in pkts]
    
    @property
    def pktToSend(self) -> Packet:
        return V2G(self.emulator, self.emulator.din.encode(CurrentDemandRequest(sessionID=self.emulator.sessionID)))
    
    @property
    def currentState(self) -> PacketType:
        return PacketType.CurrentDemandReq
    
    def handlePacket(self, receivedPacket): 
        # Check if packet is TCP, addressed to us, is PSH
        if not (receivedPacket.haslayer(TCP) and receivedPacket[TCP].dport == self.emulator.sourcePort and 'P' in receivedPacket[TCP].flags):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        # Check if packet is V2G packet
        if not receivedPacket.haslayer("Raw"):
            return (self, StateMachineResponseType.NO_TRANSITION_IGNORED_PACKET, None)

        exiString = V2GTP(receivedPacket[Raw].load).Payload
        xmlJson = self.emulator.din.decode(exiString)
        pktName = list(xmlJson["Body"].keys())[0]

        if pktName not in self.validResponsePacketTypes:
            return (self, StateMachineResponseType.NO_TRANSITION_INVALID_PACKET, None)

        # Packet should be CurrentDemandRes
        self.emulator.seq = receivedPacket[TCP].ack
        self.emulator.ack = receivedPacket[TCP].seq + len(receivedPacket[TCP].payload)

        rspPkt = V2G(self.emulator, self.emulator.din.encode(CurrentDemandRequest(sessionID=self.emulator.sessionID)))
        return (self, StateMachineResponseType.NO_TRANSITION_VALID_PACKET, rspPkt)

class WeldingDetectionReqState(AbstractState):
    def __init__(self):
        pass

