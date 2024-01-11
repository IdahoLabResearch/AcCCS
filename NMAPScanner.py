from glob import glob
from EmulatorEnum import *
import time
from tqdm import *
import random
from scapy.all import *

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
        if (not self.scanThread) or (not self.scanThread.is_alive):
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

            self.lastPort = i

            sport = random.randint(1025, 65534)
            resp = srp1(
                Ether(src=self.sourceMAC, dst=self.destinationMAC)
                / IPv6(src=self.sourceIP, dst=self.destinationIP)
                / TCP(sport=sport, dport=self.portList[i], flags="S"),
                timeout=1,
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
                        / IPv6(src=self.sourceIP, dst=self.destinationIP)
                        / TCP(sport=sport, dport=self.portList[i], flags="R"),
                        timeout=1,
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
