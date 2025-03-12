import time, logging, socket, binascii
import xml.etree.ElementTree as ET

from threading import Thread

from external_libs.V2GInjector.core.layers.V2G import V2GTP

from app.shared.XMLBuilder import XMLBuilder
from app.shared.EmulatorEnum import Protocol, RunMode, PEVState

logger = logging.getLogger("TCP")

class TCPHandler:
    def __init__(self, pev):
        self.pev = pev
        self.iface = self.pev.iface
        
        self.sessionID = "00"

        self.exi = self.pev.exi
        self.xml = XMLBuilder(self.exi)
        self.msgList = {}

        self.stop = False

        self.timeout = 5

        self.soc = 10
        self.messageType = "SupportedAppProtocolReq"

    def start(self):
        self.sourceIP = self.pev.sourceIP
        self.sourcePort = self.pev.sourcePort
        
        self.destinationIP = self.pev.destinationIP
        self.destinationPort = self.pev.destinationPort
        
        self.msgList = {}
        self.running = True
        self.prechargeCount = 0
        self.currentdemandcount = 0

        logger.info(f"Connecting to TCP server on IP: {self.destinationIP}, Port: {self.destinationPort}")
        self.socket = socket.create_connection((self.destinationIP, self.destinationPort))
        logger.info(f"Connected to TCP server")
        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()
        self.handleConnection()
        self.socket.close()
        self.timeoutThread.join()

    def checkForTimeout(self):
        self.lastMessageTime = time.time()
        while not self.stop:
            if time.time() - self.lastMessageTime > self.timeout:
                logger.info("V2G session timed out. Stopping TCP server.")
                self.stop = True
                break
            time.sleep(0.1)
            
    def handleConnection(self):
        self.startSession()
        while not self.stop:
            pkt = self.socket.recv(4096)
            self.lastMessageTime = time.time()
            self.handlePacket(pkt)

    def startSession(self):
        self.xml.SupportedAppProtocolRequest()
        exi = self.xml.getEXI()
        logger.info(f"Sending V2G message: {self.messageType}")
        self.socket.sendall(self.buildV2G(binascii.unhexlify(exi)))

    def handlePacket(self, pkt):
        v2g = V2GTP(pkt)
        EXIPayload = v2g.Payload
        XMLPayload = self.getXMLfromEXI(EXIPayload)
        EXIResponseHexStr = self.getResponse(XMLPayload)
        
        if EXIResponseHexStr:
            EXIResponseBytes = binascii.unhexlify(EXIResponseHexStr)
            logger.info(f"Sending V2G message: {self.messageType}")
            self.socket.sendall(self.buildV2G(EXIResponseBytes))
        
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
            if "AppProtocol" in root.tag:
                logger.info(f"V2G message received: SupportedAppProtocolRes")
                self.xml.SessionSetupRequest()
                self.messageType = self.xml.root[1][0].tag.split(":")[1]
                return self.xml.getEXI()

            name = root[1][0].tag
            logger.info(f"V2G message received: {name.split("}")[1]}")
            if "SessionSetupRes" in name:
                self.xml.ServiceDiscoveryRequest()
                self.SessionID = root[0][0].text
            elif "ServiceDiscoveryRes" in name:
                if self.exi.protocol == Protocol.DIN:
                    self.xml.ServicePaymentSelectionRequest()
                elif self.exi.protocol == Protocol.ISO_2:
                    self.xml.PaymentServiceSelectionRequest()
                else:
                    raise Exception("Not implemented")
            elif "ServicePaymentSelectionRes" in name:
                self.xml.ContractAuthenticationRequest()
            elif "PaymentServiceSelectionRes" in name:
                if self.pev.pnc:
                    self.xml.PaymentDetailsRequest()
                else:
                    self.xml.AuthorizationRequest()
            elif "PaymentDetailsRes" in name:
                self.xml.AuthorizationRequest()
            elif "AuthorizationRes" in name:
                self.xml.ChargeParameterDiscoveryRequest()
            elif "ContractAuthenticationRes" in name:
                if root[1][0][1].text == "Ongoing":
                    self.xml.ContractAuthenticationRequest()
                    # logger.info("Sending Contract Authenication Request")
                    if self.pev.mode == RunMode.SCAN:
                        pass
                        # # Start nmap scan while connection is kept alive
                        # if self.scanner == None:
                        #     nmapMAC = self.pev.nmapMAC if self.pev.nmapMAC else self.destinationMAC
                        #     nmapIP = self.pev.nmapIP if self.pev.nmapIP else self.destinationIP
                        #     self.scanner = NMAPScanner(EmulatorType.PEV, self.pev.nmapPorts, self.iface, self.sourceMAC, self.sourceIP, nmapMAC, nmapIP)
                        # self.scanner.start()
                else:
                    self.xml.ChargeParameterDiscoveryRequest()
            elif "ChargeParameterDiscoveryRes" in name:
                if root[1][0][1].text == "Ongoing":
                    self.xml.ChargeParameterDiscoveryRequest()
                else:
                    self.pev.setState(PEVState.C)
                    self.xml.CableCheckRequest()
            elif "CableCheckRes" in name:
                if root[1][0][2].text == "Ongoing":
                    self.xml.CableCheckRequest()
                else:
                    self.xml.PreChargeRequest()
            elif "PreChargeRes" in name:
                currentVoltage = int(root[1][0][2][2].text)
                if abs(currentVoltage - 400) < 10:
                    self.xml.PowerDeliveryRequest()
                else:
                    self.xml.PreChargeRequest()
                    # self.prechargeCount = self.prechargeCount + 1
            # Dont know if can get passed this point without providing actual voltage
            elif "PowerDeliveryRes" in name:
                if self.pev.complete:
                    self.xml.WeldingDetectionRequest()
                else:
                    self.xml.CurrentDemandRequest()
                    self.currentdemandcount += 1
            elif "CurrentDemandRes" in name:
                if self.currentdemandcount < 5:
                    self.xml.CurrentDemandRequest()
                    self.currentdemandcount += 1
                else:
                    self.pev.complete = True
                    if self.exi.protocol == Protocol.ISO_2:
                        self.xml.PowerDeliveryRequest(complete=True)
                    elif self.exi.protocol == Protocol.DIN:
                        self.xml.SessionStopRequest()
                    else:
                        raise Exception("Not implemented")
            elif "WeldingDetectionRes" in name:
                self.xml.SessionStopRequest()
                # self.xml.SessionStopRequest()
                # self.xml.EVRESSSOC.text = str(random.randint(0,100))
                # self.xml.EVRESSSOC.text = str(self.soc % 100)
                # logger.info(f"Current SOC: {self.soc}")
                # self.soc = self.soc + 5
            elif "SessionStopRes" in name:
                self.stop = True
                return None
            else:
                raise Exception(f'Packet type "{name}" not recognized')

            self.xml.SessionID.text = self.SessionID
            self.messageType = self.xml.root[1][0].tag.split(":")[1]
            return self.xml.getEXI()

    # def buildLeaveReq(self):
    #     ethLayer = Ether()
    #     ethLayer.src = self.sourceMAC
    #     # ethLayer.dst = self.destinationMAC
    #     ethLayer.dst = "bc:f2:af:f2:0a:7b"

    #     hpLayer = HomePlugAV(binascii.unhexlify(b"01340000000100000000000000000000000000000000000000000000000000000000000000000000000000000000"))

    #     pkt = ethLayer / hpLayer
    #     return pkt