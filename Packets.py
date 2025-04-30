import sys, os

sys.path.append("./external_libs/HomePlugPWN")
sys.path.append("./external_libs/V2GInjector/core")

from layers.SECC import *
from layers.V2G import *
from layerscapy.HomePlugGP import *

def SlacParmReq(emulator):
    ethLayer = Ether()
    ethLayer.src = emulator.sourceMAC
    ethLayer.dst = "ff:ff:ff:ff:ff:ff"

    homePlugAVLayer = HomePlugAV()
    homePlugAVLayer.version = 0x01

    homePlugLayer = CM_SLAC_PARM_REQ()
    homePlugLayer.RunID = emulator.runID

    return ethLayer / homePlugAVLayer / homePlugLayer

def SlacParmCnf(emulator):
    ethLayer = Ether()
    ethLayer.src = emulator.sourceMAC
    ethLayer.dst = emulator.destinationMAC

    homePlugAVLayer = HomePlugAV()
    homePlugAVLayer.version = 0x01

    homePlugLayer = CM_SLAC_PARM_CNF()
    homePlugLayer.MSoundTargetMAC = "ff:ff:ff:ff:ff:ff"
    homePlugLayer.NumberMSounds = 0x0A
    homePlugLayer.TimeOut = 0x06
    homePlugLayer.ResponseType = 0x01
    homePlugLayer.ForwardingSTA = emulator.destinationMAC
    homePlugLayer.RunID = emulator.runID

    rawLayer = Raw()
    rawLayer.load = b"\x00" * 16

    return ethLayer / homePlugAVLayer / homePlugLayer / rawLayer

def StartAttenCharInd(emulator):
    ethLayer = Ether()
    ethLayer.src = emulator.sourceMAC
    ethLayer.dst = "ff:ff:ff:ff:ff:ff"

    homePlugAVLayer = HomePlugAV()
    homePlugAVLayer.version = 0x01

    homePlugLayer = CM_START_ATTEN_CHAR_IND()
    homePlugLayer.NumberOfSounds = 0x0a
    homePlugLayer.TimeOut = 0x06
    homePlugLayer.ResponseType = 0x01
    homePlugLayer.ForwardingSTA = emulator.sourceMAC
    homePlugLayer.RunID = emulator.runID

    return ethLayer / homePlugAVLayer / homePlugLayer

def AttenCharInd(emulator):
    ethLayer = Ether()
    ethLayer.src = emulator.sourceMAC
    ethLayer.dst = emulator.destinationMAC

    homePlugAVLayer = HomePlugAV()
    homePlugAVLayer.version = 0x01

    homePlugLayer = CM_ATTEN_CHAR_IND()
    homePlugLayer.ApplicationType = 0x00
    homePlugLayer.SecurityType = 0x00
    homePlugLayer.SourceAdress = emulator.destinationMAC
    homePlugLayer.RunID = emulator.runID
    homePlugLayer.NumberOfSounds = 0x0A
    homePlugLayer.NumberOfGroups = 58
    attens = [26,25,26,28,25,27,34,33,33,36,31,31,31,31,30,29,29,28,27,26,25,23,22,22,21,20,24,27,31,36,41,45,45,38,32,29,29,31,32,32,32,34,35,35,35,35,35,35,34,38,39,39,40,40,39,41,42,57]
    # TODO: do some fun little list comprehension mumbo jumbo
    groups = []
    for e in attens:
        g = HPGP_GROUP()
        g.group = e
        groups.append(g)
    homePlugLayer.Groups = groups

    return ethLayer / homePlugAVLayer / homePlugLayer

def MNBCSoundInd(emulator):
    emulator.remainingSounds = emulator.remainingSounds - 1

    ethLayer = Ether()
    ethLayer.src = emulator.sourceMAC
    ethLayer.dst = "ff:ff:ff:ff:ff:ff"

    homePlugAVLayer = HomePlugAV()
    homePlugAVLayer.version = 0x01

    homePlugLayer = CM_MNBC_SOUND_IND()
    homePlugLayer.Countdown = emulator.remainingSounds
    homePlugLayer.RunID = emulator.runID
    homePlugLayer.RandomValue = os.urandom(16)

    return ethLayer / homePlugAVLayer / homePlugLayer

def AttenCharRes(emulator):
    ethLayer = Ether()
    ethLayer.src = emulator.sourceMAC
    ethLayer.dst = emulator.destinationMAC

    homePlugAVLayer = HomePlugAV()
    homePlugAVLayer.version = 0x01

    homePlugLayer = CM_ATTEN_CHAR_RSP()
    homePlugLayer.SourceAdress = emulator.sourceMAC
    homePlugLayer.RunID = emulator.runID
    homePlugLayer.Result = 0x00

    return ethLayer / homePlugAVLayer / homePlugLayer

def SlacMatchReq(emulator):
    ethLayer = Ether()
    ethLayer.src = emulator.sourceMAC
    ethLayer.dst = emulator.destinationMAC

    homePlugAVLayer = HomePlugAV()
    homePlugAVLayer.version = 0x01

    homePlugLayer = CM_SLAC_MATCH_REQ()
    homePlugLayer.MatchVariableFieldLen = 0x3E00

    slacVars = SLAC_varfield()
    slacVars.EVMAC = emulator.sourceMAC
    slacVars.EVSEMAC = emulator.destinationMAC
    slacVars.RunID = emulator.runID

    homePlugLayer.VariableField = slacVars

    return ethLayer / homePlugAVLayer / homePlugLayer

def SlacMatchCnf(emulator):
    ethLayer = Ether()
    ethLayer.src = emulator.sourceMAC
    ethLayer.dst = emulator.destinationMAC

    homePlugAVLayer = HomePlugAV()
    homePlugAVLayer.version = 0x01

    slacVars = SLAC_varfield_cnf()
    slacVars.EVMAC = emulator.destinationMAC
    slacVars.EVSEMAC = emulator.sourceMAC
    slacVars.RunID = emulator.runID
    slacVars.NetworkID = emulator.NID
    slacVars.NMK = emulator.NMK

    homePlugLayer = CM_SLAC_MATCH_CNF()
    homePlugLayer.MatchVariableFieldLen = 0x5600
    homePlugLayer.VariableField = slacVars

    return ethLayer / homePlugAVLayer / homePlugLayer

def SetKeyReq(emulator):
    ethLayer = Ether()
    ethLayer.src = emulator.sourceMAC
    ethLayer.dst = "00:b0:52:00:00:01"

    homePlugAVLayer = HomePlugAV()
    homePlugAVLayer.version = 0x01

    homePlugLayer = CM_SET_KEY_REQ()
    homePlugLayer.KeyType = 0x1
    homePlugLayer.MyNonce = 0xAAAAAAAA
    homePlugLayer.YourNonce = 0x00000000
    homePlugLayer.PID = 0x4
    homePlugLayer.NetworkID = emulator.NID
    homePlugLayer.NewEncKeySelect = 0x1
    homePlugLayer.NewKey = emulator.NMK

    return ethLayer / homePlugAVLayer / homePlugLayer

def SECCRequest(emulator):
    ethLayer = Ether()
    ethLayer.src = emulator.sourceMAC
    ethLayer.dst = "33:33:00:00:00:01"

    ipLayer = IPv6()
    ipLayer.src = emulator.sourceIP
    ipLayer.dst = "ff02::1"
    ipLayer.hlim = 255

    udpLayer = UDP()
    udpLayer.sport = emulator.sourcePort
    udpLayer.dport = 15118

    seccLayer = SECC()
    seccLayer.SECCType = 0x9000
    seccLayer.PayloadLen = 2

    seccRequestLayer = SECC_RequestMessage()
    seccRequestLayer.SecurityProtocol = 16
    seccRequestLayer.TransportProtocol = 0

    return ethLayer / ipLayer / udpLayer / seccLayer / seccRequestLayer

def SECCResponse(emulator):
    ethLayer = Ether()
    ethLayer.src = emulator.sourceMAC
    ethLayer.dst = emulator.destinationMAC

    ipLayer = IPv6()
    ipLayer.src = emulator.sourceIP
    ipLayer.dst = emulator.destinationIP

    udpLayer = UDP()
    udpLayer.sport = 15118
    udpLayer.dport = emulator.destinationPort

    seccLayer = SECC()
    seccLayer.SECCType = 0x9001
    seccLayer.PayloadLen = 20

    seccResponseLayer = SECC_ResponseMessage()
    seccResponseLayer.SecurityProtocol = 16
    seccResponseLayer.TargetPort = emulator.sourcePort
    seccResponseLayer.TargetAddress = emulator.sourceIP

    return ethLayer / ipLayer / udpLayer / seccLayer / seccResponseLayer

def NeighborAdvertisement(emulator):
    ethLayer = Ether()
    ethLayer.src = emulator.sourceMAC
    ethLayer.dst = emulator.destinationMAC

    ipLayer = IPv6()
    ipLayer.src = emulator.sourceIP
    ipLayer.dst = emulator.destinationIP
    ipLayer.plen = 32
    ipLayer.hlim = 255

    icmpLayer = ICMPv6ND_NA()
    icmpLayer.type = 136
    icmpLayer.R = 0
    icmpLayer.S = 1
    icmpLayer.tgt = emulator.sourceIP

    optLayer = ICMPv6NDOptDstLLAddr()
    optLayer.type = 2
    optLayer.len = 1
    optLayer.lladdr = emulator.sourceMAC

    return ethLayer / ipLayer / icmpLayer / optLayer

def NeighborSolicitation(emulator):
    ethLayer = Ether()
    ethLayer.src = emulator.sourceMAC
    ethLayer.dst = "33:33:ff:00" + emulator.destinationIP[-7:-5] + ":" + emulator.destinationIP[-4:-2] + ":" + emulator.destinationIP[-2:]

    ipLayer = IPv6()
    ipLayer.src = emulator.sourceIP
    ipLayer.dst = "ff02::1:" + emulator.destinationIP[-9:]

    icmpLayer = ICMPv6ND_NS()
    icmpLayer.type = 135
    icmpLayer.tgt = emulator.destinationIP

    optLayer = ICMPv6NDOptDstLLAddr()
    optLayer.type = 1
    optLayer.len = 1
    optLayer.lladdr = emulator.sourceMAC

    return ethLayer / ipLayer / icmpLayer / optLayer

def SYN(emulator):
    ethLayer = Ether()
    ethLayer.src = emulator.sourceMAC
    ethLayer.dst = emulator.destinationMAC

    ipLayer = IPv6()
    ipLayer.src = emulator.sourceIP
    ipLayer.dst = emulator.destinationIP

    tcpLayer = TCP()
    tcpLayer.sport = emulator.sourcePort
    tcpLayer.dport = emulator.destinationPort
    tcpLayer.flags = "S"
    tcpLayer.seq = emulator.seq

    return ethLayer / ipLayer / tcpLayer

def ACK(emulator):
    ethLayer = Ether()
    ethLayer.src = emulator.sourceMAC
    ethLayer.dst = emulator.destinationMAC

    ipLayer = IPv6()
    ipLayer.src = emulator.sourceIP
    ipLayer.dst = emulator.destinationIP

    tcpLayer = TCP()
    tcpLayer.sport = emulator.sourcePort
    tcpLayer.dport = emulator.destinationPort
    tcpLayer.flags = "A"
    tcpLayer.seq = emulator.seq
    tcpLayer.ack = emulator.ack

    return ethLayer / ipLayer / tcpLayer

def SYNACK(emulator):
    pkt = ACK(emulator)
    pkt[TCP].flags = "SA"
    return pkt

def FINACK(emulator):
    pkt = ACK(emulator)
    pkt[TCP].flags = "FA"
    return pkt

def V2G(emulator, payload: bytes):
    ethLayer = Ether()
    ethLayer.src = emulator.sourceMAC
    ethLayer.dst = emulator.destinationMAC

    ipLayer = IPv6()
    ipLayer.src = emulator.sourceIP
    ipLayer.dst = emulator.destinationIP

    tcpLayer = TCP()
    tcpLayer.sport = emulator.sourcePort
    tcpLayer.dport = emulator.destinationPort
    tcpLayer.seq = emulator.seq
    tcpLayer.ack = emulator.ack
    tcpLayer.flags = "PA"

    v2gLayer = V2GTP()
    v2gLayer.PayloadLen = len(payload)
    v2gLayer.Payload = payload

    return ethLayer / ipLayer / tcpLayer / v2gLayer

if __name__ == "__main__":
    print(SlacParmReq().name)