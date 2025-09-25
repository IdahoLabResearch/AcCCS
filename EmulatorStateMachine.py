"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
"""

from states import *
from EmulatorEnum import *

import threading
import time

class EmulatorStateMachine:
    def __init__(self, emulator):
        # TODO: implement other schema than DIN

        self.emulator = emulator
        self.state = None
        self.running = False
        self.pktToSend = None
        self.timeout = 1
        self.lastMessageTime = time.time()

        self.logger = self.emulator.logger

        if self.emulator.emulatorType == EmulatorType.PEV:
            # Initialize with CM_SLAC_PARM_REQState
            self.goToState(CM_SLAC_PARM_REQState(emulator))
        elif self.emulator.emulatorType == EmulatorType.EVSE:
            # Initialize with SetKeyReqState
            self.goToState(CM_SET_KEY_REQState(emulator))
        else:
            raise ValueError("Invalid emulator type")

        self.pktSendingThread = threading.Thread(target=self.sendPacket)

    def getType(self):
        return self.emulator.emulatorType

    def start(self):
        self.logger.debug(f"Starting {self.getType()} State Machine")
        self.running = True
        self.pktSendingThread = threading.Thread(target=self.sendPacket)
        self.pktSendingThread.start()

    def stop(self):
        self.logger.debug(f"Stopping {self.getType()} State Machine")
        self.running = False
        if self.pktSendingThread.is_alive():
            self.pktSendingThread.join()

    def handlePacket(self, pkt: Packet) -> Packet:
        """
        Reads the incoming packet and determines the next state.
        sets the next state and returns a response packet.
        """
        if self.state is None:
            raise ValueError("State machine is not in a value state.")
        (state, responseType, rspPkts) = self.state.handlePacket(pkt)

        if responseType == StateMachineResponseType.SUCCESSFUL_TRANSITION:
            self.goToState(state)

        self.state = state
        return rspPkts

    def goToState(self, state: AbstractState):
        """
        Sets the current state to the given state.
        """
        self.logger.info(f"Transitioning from {self.state} to {state}")
        self.state = state
    
    def getPktToSend(self):
        if self.state is None:
            raise ValueError("State machine is not in a value state.")
        return self.state.pktToSend
    
    def sendPacket(self):
        while self.running:
            if self.getPktToSend() and time.time() - self.lastMessageTime > self.timeout:
                self.emulator.sendPacket(self.getPktToSend())
                self.lastMessageTime = time.time()
                time.sleep(0.1)
