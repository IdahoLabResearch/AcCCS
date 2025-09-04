"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
"""

from enum import Enum


class EXIProtocol(Enum):
    DIN = "DIN"
    ISO_2 = "ISO-2"
    ISO_20 = "ISO-20"


class PEVState(Enum):
    A = "a"
    B = "b"
    C = "c"


class EmulatorState(Enum):
    A = "a"
    B = "b"
    C = "c"


class RunMode(Enum):
    FULL = 0
    STALL = 1
    SCAN = 2


class EmulatorType(Enum):
    PEV = "pev"
    EVSE = "evse"


class StateMachineResponseType(Enum):
    SUCCESSFUL_TRANSITION = "successful_transition"
    NO_TRANSITION_IGNORED_PACKET = "no_transition_ignored_packet"
    NO_TRANSITION_INVALID_PACKET = "no_transition_invalid_packet"
    NO_TRANSITION_VALID_PACKET = "no_transition_valid_packet"


class PacketType(Enum):
    CM_SET_KEY_REQ = "CM_SET_KEY_REQ"
    CM_SET_KEY_CNF = "CM_SET_KEY_CNF"

    # SLAC
    CM_SLAC_PARM_REQ = "CM_SLAC_PARM_REQ"
    CM_SLAC_PARM_CNF = "CM_SLAC_PARM_CNF"
    CM_START_ATTEN_CHAR_IND = "CM_START_ATTEN_CHAR_IND"
    CM_MNBC_SOUND_IND = "CM_MNBC_SOUND_IND"
    CM_ATTEN_PROFILE_IND = "CM_ATTEN_PROFILE_IND"
    CM_ATTEN_CHAR_IND = "CM_ATTEN_CHAR_IND"
    CM_ATTEN_CHAR_RSP = "CM_ATTEN_CHAR_RSP"
    CM_VALIDATE_REQ = "CM_VALIDATE_REQ"
    CM_VALIDATE_CNF = "CM_VALIDATE_CNF"
    CM_SLAC_MATCH_REQ = "CM_SLAC_MATCH_REQ"
    CM_SLAC_MATCH_CNF = "CM_SLAC_MATCH_CNF"
    CM_AMP_MAP_REQ = "CM_AMP_MAP_REQ"
    CM_AMP_MAP_CNF = "CM_AMP_MAP_CNF"

    # SECC Discovery Protocol
    SDPRequest = "SECC_RequestMessage"
    SDPResponse = "SECC_ResponseMessage"

    # Handshake
    supportedAppProtocolReq = "supportedAppProtocolReq"
    supportedAppProtocolRes = "supportedAppProtocolRes"

    # TCP
    SYN = "S"
    SYN_ACK = "SA"
    ACK = "A"
    FIN = "F"
    FIN_ACK = "FA"
    PSH = "P"
    RST = "R"

    # V2G
    SessionSetupReq = "SessionSetupReq"
    SessionSetupRes = "SessionSetupRes"
    ServiceDiscoveryReq = "ServiceDiscoveryReq"
    ServiceDiscoveryRes = "ServiceDiscoveryRes"
    ServicePaymentSelectionReq = "ServicePaymentSelectionReq"
    ServicePaymentSelectionRes = "ServicePaymentSelectionRes"
    ContractAuthenticationReq = "ContractAuthenticationReq"
    ContractAuthenticationRes = "ContractAuthenticationRes"
    ChargeParameterDiscoveryReq = "ChargeParameterDiscoveryReq"
    ChargeParameterDiscoveryRes = "ChargeParameterDiscoveryRes"
    PowerDeliveryReq = "PowerDeliveryReq"
    PowerDeliveryRes = "PowerDeliveryRes"
    SessionStopReq = "SessionStopReq"
    SessionStopRes = "SessionStopRes"
    CableCheckReq = "CableCheckReq"
    CableCheckRes = "CableCheckRes"
    PreChargeReq = "PreChargeReq"
    PreChargeRes = "PreChargeRes"
    CurrentDemandReq = "CurrentDemandReq"
    CurrentDemandRes = "CurrentDemandRes"
    WeldingDetectionReq = "WeldingDetectionReq"
    WeldingDetectionRes = "WeldingDetectionRes"