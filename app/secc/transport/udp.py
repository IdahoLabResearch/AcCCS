import time, socket, logging

from threading import Thread

from external_libs.V2GInjector.core.layers.SECC import SECC, SECC_ResponseMessage

logger = logging.getLogger("UDP")

# Handles all SDP communications
class UDPHandler:
    def __init__(self, evse):
        self.evse = evse
        self.iface = self.evse.iface
        self.sourceIP = self.evse.sourceIP
        self.sourcePort = 15118
        
        self.destinationAddress = None

        self.timeout = 8
        self.stop = False

    # Starts SLAC process
    def start(self):
        self.stop = False
        
        self.socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        self.socket.bind((self.sourceIP, self.sourcePort))
        logger.info(f"Starting UDP server on {self.sourceIP}:{self.sourcePort}")

        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()
        
        self.handleConnection()

    def checkForTimeout(self):
        self.lastMessageTime = time.time()
        while True:
            if self.stop:
                break
            if time.time() - self.lastMessageTime > self.timeout:
                logger.info("SDP timed out, resetting connection ...")
                self.lastMessageTime = time.time()
                
    def handleConnection(self):
        while not self.stop:
            pkt, address = self.socket.recvfrom(1024)
            self.lastMessageTime = time.time()
            self.destinationAddress = address
            self.handlePacket(pkt)

    def handlePacket(self, data):
        try:
            pkt = SECC(data)
            if pkt.haslayer("SECC_RequestMessage"):
                logger.info("Recieved SECC SDP Request Message")
                self.evse.destinationIP = self.destinationAddress[0]
                self.evse.destinationPort= self.destinationAddress[1]
                self.sendSECCResponse()
                self.stop = True
            return self.stop
        except:
            logger.error("Packet couldn't be loaded.")

        self.lastMessageTime = time.time()

    def sendSECCResponse(self):
        time.sleep(0.2)
        for i in range(1):
            logger.info("Sending SECC SDP Response Message")
            self.socket.sendto(self.buildSECCResponse(), self.destinationAddress)

    def buildSECCResponse(self):
        secc = SECC()
        secc.SECCType = 0x9001
        secc.PayloadLen = 20

        seccRM = SECC_ResponseMessage()
        seccRM.SecurityProtocol = 16
        seccRM.TargetPort = self.evse.sourcePort
        seccRM.TargetAddress = self.sourceIP  # eno1

        responsePacket = secc / seccRM
        return responsePacket.build()