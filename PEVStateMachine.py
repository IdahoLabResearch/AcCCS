from States_SLAC import *
from States_AppHand import *
from States_DIN import *
from scapy.all import *
from EmulatorEnum import *

import logging
import threading
import time
logger = logging.getLogger(__name__)

class PEVStateMachine:
    def __init__(self, emulator):
        # TODO: implement other schema than DIN

        self.emulator = emulator
        self.state = None
        self.running = False
        self.pktToSend = None
        self.timeout = 0.5
        self.lastMessageTime = time.time()

        # Initialize with CM_SLAC_PARM_REQState
        self.goToState(CM_SLAC_PARM_REQState(emulator))

        self.pktSendingThread = threading.Thread(target=self.sendPacket)

    def start(self):
        logger.debug("Starting PEVStateMachine")
        self.running = True
        # Create a new thread if the previous one has already been started
        if hasattr(self.pktSendingThread, '_started') and self.pktSendingThread._started.is_set():
            self.pktSendingThread = threading.Thread(target=self.sendPacket)
        self.pktSendingThread.start()

    def stop(self):
        logger.debug("Stopping PEVStateMachine")
        self.running = False
        if self.pktSendingThread.is_alive():
            self.pktSendingThread.join()

    def handlePacket(self, pkt: Packet) -> Packet:
        """
        Reads the incoming packet and determines the next state.
        sets the next state and returns a response packet.
        """
        (state, responseType, rspPkts) = self.state.handlePacket(pkt)

        if responseType == StateMachineResponseType.SUCCESSFUL_TRANSITION:
            self.goToState(state)

        self.state = state
        return rspPkts

    def goToState(self, state: AbstractState):
        """
        Sets the current state to the given state.
        """
        logger.info(f"Transitioning from {self.state} to {state}")
        self.state = state
    
    def getPktToSend(self):
        return self.state.pktToSend
    
    def sendPacket(self):
        while self.running:
            if self.getPktToSend() and time.time() - self.lastMessageTime > self.timeout:
                self.emulator.sendPacket(self.getPktToSend())
                self.lastMessageTime = time.time()
                time.sleep(0.1)
