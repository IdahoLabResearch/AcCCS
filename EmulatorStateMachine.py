"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
"""

from states import *
from states.AbstractState import StateContext
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
            self.goToState(CM_SLAC_PARM_REQ_State(StateContext(emulator)))
        elif self.emulator.emulatorType == EmulatorType.EVSE:
            # Initialize with SetKeyReqState
            self.goToState(CM_SET_KEY_REQ_State(StateContext(emulator)))
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

    def handlePacket(self, pkt: Packet) -> None:
        """
        Reads the incoming packet and determines the next state.
        sets the next state and returns a response packet.
        """
        if self.state is None:
            raise ValueError("State machine is not in a valid state.")
        result = self.state.handlePacket(pkt)

        if result.success and result.next_state:
            self.goToState(result.next_state)

    def goToState(self, state: AbstractState):
        """
        Sets the current state to the given state.
        """
        self.logger.info(f"Transitioning from {self.state} to {state}")
        self.state = state
    
    def sendPacket(self):
        while self.running:
            if not self.state:
                time.sleep(0.1)
                continue
            if not self.state.shouldRetry:
                time.sleep(0.1)
                continue
            if self.state.getOutgoingPackets() and time.time() - self.lastMessageTime > self.timeout:
                self.emulator.sendPacket(self.state.getOutgoingPackets())
                self.lastMessageTime = time.time()
                time.sleep(0.1)
