from glob import glob
from EmulatorEnum import *
import time
from tqdm import *
import random
from scapy.all import *
from ipaddress import ip_address, IPv4Address

SCAN_RESULTS_DIR = "scan_results/"

class NMAPScanner():
    
    def __init__(self, emulatorType: EmulatorType, portList: list, iface, sourceMAC, sourceIP, destinationMAC, destinationIP):
        self.finished = False
        self.running = True
        self.portResults = []
        self.lastPort = 0
        self.scanThread = None
        
        self.iface = iface
        self.sourceMAC = sourceMAC
        self.sourceIP = sourceIP
        self.destinationMAC = destinationMAC
        self.destinationIP = destinationIP
        
        # Check if address types match
        sourceType = self.getType(sourceIP)
        self.destinationType = self.getType(destinationIP)
        if not sourceType:
            raise ValueError("source IP for NMAP scan is not valid")
        if not self.destinationType:
            raise ValueError("destination IP for NMAP scan is not valid")
        if self.destinationType == "ipv4" and sourceType == "ipv6":
            self.sourceIP = "10.42.0.{}".format(random.randint(1,255))
        if self.destinationType == "ipv6" and sourceType == "ipv4":
            # Random link local ipv6 address
            self.sourceIP = "fe80::9656:d028:8652:66b6"
            
        # Get list of current scan results
        fileList = glob(SCAN_RESULTS_DIR + "scan_res_{}_[0-9][0-9][0-9].txt".format(emulatorType.value))
        maxFileNum = 0
        # Find the largest number to properly name next scan file
        for fileName in fileList:
            num = int(fileName[-7:-4])
            maxFileNum = max(num, maxFileNum)    
        # Make new result file name   
        self.resultFileName = SCAN_RESULTS_DIR + "scan_res_{}_{:0>3}.txt".format(emulatorType.value, maxFileNum + 1)
        
        # Use provided portlist if not empty, use most common ports if not
        self.portList = portList if portList else self.getPortList()

    def getType(self, ipAddress):
        try: 
            return "ipv4" if type(ip_address(ipAddress)) is IPv4Address else "ipv6"
        except ValueError: 
            return None
    
    def getPortList(self):
        res = []
        with open("modportlist.txt", "r") as file:
            for line in file:
                res.append(int(line.strip()))
        return res
    
    def saveResults(self):
        print("INFO (NMAP): Saving results")
        cutoff = -11 if not self.finished else len(self.portResults)
        with open(self.resultFileName, 'a') as file:
            for result in self.portResults[:cutoff]:
                file.write("{: <5} | {}\n".format(result[0], result[1]))

    def start(self):
        if (not self.scanThread) or (not self.scanThread.is_alive()):
            self.scanThread = Thread(target=self._scan)
            self.scanThread.start()
        
    def stop(self):
        self.saveResults()
        self.running = False
        self.scanThread.join()
        
    def _scan(self):
        # Give the network a bit of time before scanning
        time.sleep(3)
        # Picks up where the last NMAP left off
        maxPorts = len(self.portList)
        # Disregards last 10 ports incase they were scanned after connection was terminated
        currentPort = max(self.lastPort - 10, 0)

        print(f"INFO (EVSE): Starting NMAP on port {self.portList[currentPort]} | {currentPort+1}/{maxPorts}")

        for i in trange(currentPort, maxPorts, initial=currentPort, unit=" ports", desc="Ports Scanned", ncols=100, total=maxPorts):
            if not self.running:
                break
            time.sleep(0.1) # Throttle the port scan
            self.lastPort = i

            sport = random.randint(1025, 65534)
            resp = srp1(
                Ether(src=self.sourceMAC, dst=self.destinationMAC)
                / (IPv6(src=self.sourceIP, dst=self.destinationIP) if self.destinationType == "ipv6" else IP(src=self.sourceIP, dst=self.destinationIP))
                / TCP(sport=sport, dport=self.portList[i], flags="S"),
                timeout=0.2,
                verbose=0,
                iface=self.iface,
            )

            if resp == None:
                self.portResults.append((self.portList[i], "filtered"))
                continue

            if resp.haslayer("TCP"):
                if resp.getlayer("TCP").flags == "SA":
                    # Send a gratuitous RST to close the connection
                    send_rst = srp(
                        Ether(src=self.sourceMAC, dst=self.destinationMAC)
                        / (IPv6(src=self.sourceIP, dst=self.destinationIP) if self.destinationType == "ipv6" else IP(src=self.sourceIP, dst=self.destinationIP))
                        / TCP(sport=sport, dport=self.portList[i], flags="R"),
                        timeout=0.2,
                        verbose=0,
                        iface=self.iface,
                    )
                    self.portResults.append((self.portList[i], "open"))
                    continue

                elif resp.getlayer("TCP").flags == 0x14:
                    self.portResults.append((self.portList[i], "closed"))
                    continue

            else:
                self.portResults.append((self.portList[i], "filtered"))
                continue

        # Check if NMAP finished scanning all ports in list
        if self.lastPort == maxPorts - 1:
            self.finished = True
        print(f"INFO (EVSE): NMAP Stopped on port {self.portList[self.lastPort]} | {self.lastPort+1}/{maxPorts}")
        self.saveResults()
