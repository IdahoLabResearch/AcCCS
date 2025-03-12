import time, logging

from threading import Thread

from external_libs.V2GInjector.core.layers.SECC import SECC, SECC_RequestMessage, SECC_ResponseMessage
from external_libs.HomePlugPWN.layerscapy.HomePlugGP import *

logger = logging.getLogger("UDP")

# This class handles the level 3 SDP protocol communications
class UDPHandler:
    def __init__(self, pev):
        self.pev = pev
        self.iface = self.pev.iface
        self.sourceMAC = self.pev.sourceMAC
        self.sourceIP = self.pev.sourceIP
        
        self.destinationAddress = ('::1', 15118)

        self.timeSinceLastPkt = time.time()
        self.timeout = 8  # How long to wait for a message to timeout
        self.stop = False

    # This method starts the slac process and will stop
    def start(self):
        self.stop = False
        # Thread for sniffing packets and handling responses
        # self.sniffThread = Thread(target=self.startSniff)
        # self.sniffThread.start()
        
        self.socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        logger.info(f"Connecting to UDP server on {self.destinationAddress[0]}:{self.destinationAddress[1]}")

        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()
        
        self.handleConnection()

    # The EVSE sometimes fails the SLAC process, so this automatically restarts it from the beginning
    def checkForTimeout(self):
        self.timeSinceLastPkt = time.time()
        while self.stop == False:
            if time.time() - self.timeSinceLastPkt > self.timeout:
                raise Exception("SDP timed out ...")
    
    def handleConnection(self):
        while not self.stop:
            self.sendSECCRequest()
            self.timeSinceLastPkt = time.time()
            pkt, _ = self.socket.recvfrom(1024)
            self.handlePacket(pkt)

    def handlePacket(self, data):
        try:
            pkt = SECC(data)
            if pkt.haslayer("SECC_ResponseMessage"):
                logger.info("Recieved SECC SDP Response Message")
                self.pev.destinationIP = pkt[SECC_ResponseMessage].TargetAddress
                self.pev.destinationPort = pkt[SECC_ResponseMessage].TargetPort
                self.stop = True
                return True
            return False
        except:
            logger.error("Packet couldn't be loaded.")

    def sendSECCRequest(self):
        time.sleep(3)
        for i in range(1):
            logger.info("Sending SECC SDP Request Message")
            self.socket.sendto(self.buildSECCRequest(), self.destinationAddress)

    def buildSECCRequest(self):
        seccLayer = SECC()
        seccLayer.SECCType = 0x9000
        seccLayer.PayloadLen = 2

        seccRequestLayer = SECC_RequestMessage()
        seccRequestLayer.SecurityProtocol = 16
        seccRequestLayer.TransportProtocol = 0

        responsePacket = seccLayer / seccRequestLayer
        return responsePacket.build()