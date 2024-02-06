""" 
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

    This class is used to make python requests to the V2Gdecoder hosted on a localhost java webserver

    This script was written in a feeble attempt to tame the creature known as the "Java Webserver".
    This attempt was made in vain.
"""

import requests
from requests.exceptions import Timeout
import subprocess
import os
from threading import Thread
import socket
import time
from EmulatorEnum import *


class EXIProcessor:
    def __init__(self, protocol: Protocol):
        self.protocol = protocol
        self.serverThread = Thread(target=self.startWebserver)
        self.serverThread.start()
        # Sleep to give time to java webserver to start
        for i in range(5):
            if self._isServerStarted():
                return
            else:
                time.sleep(1)
        raise Exception("ERROR: Java webserver never started")

    # Kills the subprocess so proccesses arent flooded with random Java webservers
    def __del__(self):
        print(f"INFO: Killing Java webserver with PID: {self.cmd.pid} on port: {self.port}")
        self.cmd.kill()
        self.serverThread.join()

    def _isServerStarted(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            sock.connect(("localhost", self.port))
            sock.shutdown(socket.SHUT_RDWR)
            return True
        except:
            return False
        finally:
            sock.close()

    # Starts the Java webserver on an open port
    def startWebserver(self):
        # os.chdir(os.path.abspath(__file__ + "/../java_decoder"))
        my_path = os.path.abspath(os.path.dirname(__file__))
        self.port = self._findOpenPort()
        self.cmd = subprocess.Popen(["java", "-jar", "V2GdecoderMOD.jar", "-w", str(self.port), "-c", self.protocol.value], cwd=my_path + "/java_decoder/")
        print(f"INFO: Started Java webserver with PID: {self.cmd.pid} on port: {self.port}")

    def _findOpenPort(self):
        sock = socket.socket()
        sock.bind(("", 0))
        _, port = sock.getsockname()
        sock.close()
        return port

    # Takes and XML string and encodes it into an EXI string
    def encode(self, xmlString):
        # Make post request to java webserver
        try:
            req = requests.post(url=f"http://localhost:{self.port}/", headers={"Format": "XML"}, data=xmlString, timeout=2)
        except Timeout:
            print("ERROR: Connection to the java webserver timed out.")
        except Exception as e:
            print(f"ERROR: XML string\n{xmlString}\ncaused exception\n{e}")

        # This occurs sometimes, specifically if the html body of the request is greater than 4096 bytes
        if req.text == "null":
            print("ERROR: Java webserver returned null")
            return None

        # java webserver returns hex string
        return req.text

    def decode(self, exiString):
        # Make post request to java webserver
        try:
            req = requests.post(url=f"http://localhost:{self.port}/", headers={"Format": "EXI"}, data=exiString, timeout=2)
        except Timeout:
            print(f"ERROR: Connection to the java webserver timed out when trying to decode {exiString}")
        except Exception as e:
            print(f"ERROR: EXI string\n{exiString}\ncaused exception\n{e}")

        # This occurs sometimes, specifically if the html body of the request is greater than 4096 bytes
        if req.text == "null":
            print("ERROR: Java webserver returned null")
            return None

        # java webserver returns hex string
        return req.text


if __name__ == "__main__":
    x = EXIProcessor(Protocol.DIN)
    for i in range(10):
        xmlString = f'<ns7:V2G_Message xmlns:ns7="urn:din:70121:2012:MsgDef" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ns3="http://www.w3.org/2001/XMLSchema" xmlns:ns4="http://www.w3.org/2000/09/xmldsig#" xmlns:ns5="urn:din:70121:2012:MsgBody" xmlns:ns6="urn:din:70121:2012:MsgDataTypes" xmlns:ns8="urn:din:70121:2012:MsgHeader"><ns7:Header><ns8:SessionID>4142423030303031</ns8:SessionID></ns7:Header><ns7:Body><ns5:ServiceDiscoveryRes><ns5:ResponseCode>OK</ns5:ResponseCode><ns5:PaymentOptions><ns6:PaymentOption>ExternalPayment</ns6:PaymentOption></ns5:PaymentOptions><ns5:ChargeService><ns6:ServiceTag><ns6:ServiceID>{i}</ns6:ServiceID><ns6:ServiceCategory>EVCharging</ns6:ServiceCategory></ns6:ServiceTag><ns6:FreeService>false</ns6:FreeService><ns6:EnergyTransferType>DC_extended</ns6:EnergyTransferType></ns5:ChargeService></ns5:ServiceDiscoveryRes></ns7:Body></ns7:V2G_Message>'
        res = x.encode(xmlString)
        print(res)
    # exiString = b'8000dbab9371d3234b71d1b981899189d191818991d26b9b3a232b30020000040040'
    # print(x.decode(exiString))
