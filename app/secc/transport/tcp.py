import time, socket
import binascii, logging

from external_libs.V2GInjector.core.layers.V2G import V2GTP

from threading import Thread
import xml.etree.ElementTree as ET

from app.shared.XMLBuilder import XMLBuilder
from app.shared.EmulatorEnum import RunMode, EmulatorType
from app.shared.NMAPScanner import NMAPScanner

logger = logging.getLogger("TCP")

class TCPHandler:
    def __init__(self, evse):
        self.evse = evse
        self.iface = self.evse.iface

        self.sourceIP = self.evse.sourceIP
        self.sourcePort = self.evse.sourcePort

        self.destinationIP = self.evse.destinationIP
        self.destinationPort = self.evse.destinationPort

        self.exi = self.evse.exi
        self.xml = XMLBuilder(self.exi)
        self.msgList = {}

        self.stop = False
        self.scanner = None
        
        self.connection = None
        self.client = None

        self.timeout = 5
        
        self.messageType = None

    def start(self):
        self.msgList = {}

        self.socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.sourceIP, self.sourcePort))
        self.socket.listen(1)
        logger.info(f"Starting TCP server on IP: {self.sourceIP}, Port: {self.sourcePort}")

        logger.info("Waiting for connection from client")
        self.connection, self.client = self.socket.accept()
        logger.info(f"Connected to TCP client on IP: {self.client[0]}, Port: {self.client[1]}")
        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()
        self.handleConnection()
        self.timeoutThread.join()
        self.connection.close()

    def checkForTimeout(self):
        self.lastMessageTime = time.time()
        while not self.stop:
            if time.time() - self.lastMessageTime > self.timeout:
                logger.info("V2G session timed out. Stopping TCP server.")
                self.stop = True
                break
            time.sleep(0.1)
                
    def handleConnection(self):
        while not self.stop:
            pkt = self.connection.recv(4096)
            self.lastMessageTime = time.time()
            self.handlePacket(pkt)

    def handlePacket(self, pkt):
        v2g = V2GTP(pkt)
        EXIPayload = v2g.Payload
        XMLPayload = self.getXMLfromEXI(EXIPayload)
        EXIResponseHexStr = self.getResponse(XMLPayload)
        
        if EXIResponseHexStr:
            EXIResponseBytes = binascii.unhexlify(EXIResponseHexStr)
            logger.info(f"Sending V2G message: {self.messageType}")
            self.connection.sendall(self.buildV2G(EXIResponseBytes))
            
    def getXMLfromEXI(self, EXIPayload):
        EXIPayloadHex = binascii.hexlify(EXIPayload)
        if EXIPayloadHex in self.msgList.keys():
            XMLRes = self.msgList[EXIPayloadHex]
        else:
            XMLRes = self.exi.decode(EXIPayloadHex)
            self.msgList[EXIPayloadHex] = XMLRes
        if XMLRes:
            return ET.fromstring(XMLRes)
        else:
            raise Exception("EXI to XML decoding error!")

    def buildV2G(self, payload):
        v2gLayer = V2GTP()
        v2gLayer.PayloadLen = len(payload)
        v2gLayer.Payload = payload

        return v2gLayer.build()

    def getResponse(self, XMLElement: ET.Element):
        root = XMLElement
        if root.text is None:
            if root[0].tag == "AppProtocol":
                logger.info(f"V2G message received: SupportedAppProtocolReq")
                self.xml.SupportedAppProtocolResponse()
                self.messageType = "SupportedAppProtocolRes"
                return self.xml.getEXI()

            name = root[1][0].tag
            logger.info(f"V2G message received: {name.split("}")[1]}")
            if "SessionSetupReq" in name:
                self.xml.SessionSetupResponse()
            elif "ServiceDiscoveryReq" in name:
                self.xml.ServiceDiscoveryResponse()
            elif "ServicePaymentSelectionReq" in name:
                self.xml.ServicePaymentSelectionResponse()
            elif "PaymentServiceSelectionReq" in name:
                self.xml.PaymentServiceSelectionResponse()
            elif "PaymentDetailsReq" in name:
                self.xml.PaymentDetailsResponse()
            elif "AuthorizationReq" in name:
                self.xml.AuthorizationResponse()
            elif "ContractAuthenticationReq" in name:
                self.xml.ContractAuthenticationResponse()
                if self.evse.mode == RunMode.STOP:
                    self.xml.EVSEProcessing.text = "Ongoing"
                elif self.evse.mode == RunMode.SCAN:
                    self.xml.EVSEProcessing.text = "Ongoing"
                    # Start nmap scan while connection is kept alive
                    if self.scanner == None:
                        nmapMAC = self.evse.nmapMAC if self.evse.nmapMAC else self.destinationMAC
                        nmapIP = self.evse.nmapIP if self.evse.nmapIP else self.destinationIP
                        self.scanner = NMAPScanner(EmulatorType.EVSE, self.evse.nmapPorts, self.iface, self.sourceMAC, self.sourceIP, nmapMAC, nmapIP)
                    self.scanner.start()
            elif "ChargeParameterDiscoveryReq" in name:
                self.xml.ChargeParameterDiscoveryResponse()
                # self.xml.MinCurrentLimitValue.text = "0"
                self.xml.MaxCurrentLimitValue.text = "5"
            elif "CableCheckReq" in name:
                self.xml.CableCheckResponse()
            elif "PreChargeReq" in name:
                self.xml.PreChargeResponse()
                self.xml.Multiplier.text = root[1][0][1][0].text
                self.xml.Value.text = root[1][0][1][2].text
            elif "PowerDeliveryReq" in name:
                self.xml.PowerDeliveryResponse()
            elif "CurrentDemandReq" in name:
                self.xml.CurrentDemandResponse()
                self.xml.CurrentMultiplier.text = root[1][0][1][0].text
                self.xml.CurrentValue.text = root[1][0][1][2].text
                self.xml.VoltageMultiplier.text = root[1][0][8][0].text
                self.xml.VoltageValue.text = root[1][0][8][2].text
                self.xml.CurrentLimitValue.text = "5"
            elif "WeldingDetectionReq" in name:
                self.xml.WeldingDetectionResponse()
            elif "SessionStopReq" in name:
                self.xml.SessionStopResponse()
                self.stop = True
            else:
                raise Exception(f'Packet type "{name}" not recognized')
            self.messageType = self.xml.root[1][0].tag.split(":")[1]
            return self.xml.getEXI()