"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
    Copyright 2025, Ford Motor Company
"""

import os, time, logging, socket

from threading import Thread
from typing import TYPE_CHECKING, Optional

from scapy.all import Packet, Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr

from external_libs.HomePlugPWN.layerscapy.HomePlugGP import *

if TYPE_CHECKING:
    from app.evcc.controller.pev import PEV

from app.shared.messages.out_of_spec import accept_out_of_spec, discard_out_of_spec

logger = logging.getLogger("SLAC")

# Cadence of the EV's batched SLAC frames (TP_EV_batch_msg_interval, 20-50 ms).
SOUND_INTERVAL_MS = 20
# ISO 15118-3 Table A.1 fixes the M-sound count at C_EV_match_MNBC = 10. A
# CM_SLAC_PARM.CNF that deviates is tolerated and logged, except where the
# count cannot work at all: zero (nothing to send, the Countdown underflows)
# or more than the personality's sound timeout lets us send at this cadence
# (the timeout thread would restart SLAC mid-sound-phase). Those frames are
# ignored as deviating content ([V2G3-A09-09] / DIN [V2G-DC-591]; issue #137).
SPEC_NUM_SOUNDS = 10
MIN_NUM_SOUNDS = 1
# Upper bound on the end-of-cycle join, so a wedged timer thread degrades to a
# logged leak rather than hanging the run (mirrors the SECC handler).
TIMEOUT_JOIN_TIMEOUT = 2.0

# This class handles the level 2 SLAC protocol communications
class SLACHandler:
    def __init__(self, pev: "PEV"):
        self.pev = pev
        self.iface = self.pev.iface
        self.sourceMAC = self.pev.sourceMAC
        self.sourceIP = self.pev.sourceIP
        self.runID = b"\xf4\x00\x37\xd0\x00\x5c\x00\x7f"
        self.NID = None
        self.NMK = None
        
        self.sock = None
        
        self.slac_sound_start = None
        self.stopSounds = False
        self.stopReceive = False

        self.timeSinceLastPkt = int(time.time())
        self.timeout = 1  # How long to wait for a message to timeout
        # Per-cycle "end this SLAC run" flag; `start()` clears it each cycle.
        self.stop = False
        # Sticky operator-quit flag (issue #40). Set once by `stop_handler` and
        # NEVER cleared by `start()`. `stop` alone is insufficient because a 'q'
        # landing in the executor spin-up window sets `stop = True`, but the
        # re-arm at the top of `start()` would reset it to False and loop SLAC
        # forever (hanging the process on the executor join). A separate sticky
        # flag survives the re-arm and is also what keeps an operator quit from
        # being clobbered by the future per-cycle re-arm loop (ADR-0005).
        self.quit = False

        self.CM_ATTEN_CHAR_IND_recved = False
        self.CM_START_ATTEN_CHAR_IND_sent = False
        
    def create_socket(self):
        # Re-arming a new cycle (ADR-0005) calls this again; close the prior
        # cycle's socket first so repeated cycles don't leak raw-socket fds.
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        # Create a raw socket
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        # Bind to a specific network interface (e.g., "eth0")
        self.sock.bind((self.iface, 0))
        # Time recv() out periodically so the handleSLAC loop wakes to observe
        # self.stop. A bare blocking recv() can't be interrupted from another
        # thread (closing the fd does not reliably wake a parked recv on Linux),
        # which would hang the operator 'q' quit while waiting for SLAC (#40).
        self.sock.settimeout(0.5)
    
    def stop_handler(self) -> None:
        """Tear down the SLAC process for a graceful operator quit (issue #40).

        Safe to call from another thread (the operator-console quit handler runs
        on the event-loop thread). Sets the stop flag, closes the raw socket to
        unblock the thread parked in `recv()` so `handleSLAC` can observe `stop`
        and return, and stops the neighbor-solicitation sniffer. A send racing
        this close is absorbed by `_send` (it sees `quit`/`stop` set), so no
        `OSError` traceback escapes the SLAC thread. Idempotent: a second call
        (e.g. quit during a phase where SLAC already finished) is a cheap no-op.
        """
        # `quit` is sticky so a re-arm in `start()` (this cycle's spin-up, or a
        # future re-arm cycle) can't undo the operator quit; `stop` ends the
        # current cycle's loops (issue #40).
        self.quit = True
        self.stop = True
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        nst = getattr(self, "neighborSolicitationThread", None)
        if nst is not None:
            try:
                if nst.running:
                    nst.stop()
            except Exception:  # noqa: BLE001 - best-effort teardown
                pass

    def receive(self) -> Optional[Packet]:
        """Read one frame, distinguishing idle from a genuine link failure (#51).

        The raw socket polls on a 0.5s timeout (see `create_socket`) so the
        handleSLAC loop can wake to observe `stop`/`quit`. Three `recv()`
        outcomes are kept apart rather than all collapsed to silent idle:

        - `socket.timeout` — the expected poll wake; no packet this tick.
        - close under us — `stop_handler` (operator quit) closed the fd while we
          were parked here; `quit`/`stop` is already set, so return cleanly
          instead of crashing the SLAC thread with a traceback.
        - any other `OSError` — a genuine failure on a live run (interface drop,
          `ENETDOWN`, ...). Surface it (log) and end the loop, rather than mask
          a dead link as ordinary idle.
        """
        try:
            raw_packet = self.sock.recv(65535)
        except socket.timeout:
            return None
        except OSError as err:
            if self.quit or self.stop:
                return None
            logger.error("SLAC socket error during recv: %s", err)
            self.stop = True
            return None

        try:
            packet = Ether(raw_packet)
            if packet[Ether].type != 0x88E1 or packet[Ether].src == self.sourceMAC:
                return None
            if hasattr(packet[1][2], "RunID") and packet[1][2].RunID != self.runID:
                return None
            return packet
        except Exception as err:
            logger.error(err)

    def _send(self, pkt: Packet) -> bool:
        """Send a built packet on the raw socket, tolerating the quit-close race.

        `stop_handler` closes the socket from the event-loop thread while the
        handshake runs in an executor thread, so a 'q' landing between a loop's
        `stop`/`quit` check and a send would otherwise raise `OSError` and crash
        the SLAC thread with a traceback (#51). Returns True on success. On the
        quit-close (`quit`/`stop` already set) it swallows the error and returns
        False. A genuine failure on a live run is surfaced and ends the loop,
        mirroring `receive()`.
        """
        try:
            self.sock.send(bytes(pkt))
            return True
        except OSError as err:
            if self.quit or self.stop:
                return False
            logger.error("SLAC socket error during send: %s", err)
            self.stop = True
            return False

    # This method starts the slac process and will stop
    def start(self):
        # An operator 'q' that landed before/during executor spin-up sets the
        # sticky `quit` flag; honour it instead of re-arming a fresh cycle and
        # hanging the process (issue #40).
        if self.quit:
            return
        self.runID = os.urandom(8)
        # Re-initialise every per-cycle flag so a re-armed cycle (ADR-0005)
        # starts clean. The one-shot code only ever reset these inside
        # `restart()`, so on a second `start()` the handshake booleans would
        # still read True from the prior cycle and `handle_CM_ATTEN_CHAR_IND`
        # would skip sending ATTEN_CHAR_RES / SLAC_MATCH_REQ — stalling the
        # second SLAC. `stop` clears here; the sticky `quit` deliberately does
        # not (issue #40).
        self.stop = False
        self.stopSounds = False
        self.CM_ATTEN_CHAR_IND_recved = False
        self.CM_START_ATTEN_CHAR_IND_sent = False
        self.timeSinceLastPkt = int(time.time())

        # Thread to determine if PEV timed out or SLAC error occured and restart SLAC process
        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()

        self.neighborSolicitationThread = AsyncSniffer(
            iface=self.iface, lfilter=lambda x: x.haslayer("ICMPv6ND_NS") and x[ICMPv6ND_NS].tgt == self.sourceIP, prn=self.sendNeighborSoliciation
        )
        self.neighborSolicitationThread.start()
        
        try:
            self.create_socket()
            self.handleSLAC()
        finally:
            # However handleSLAC ended — matched, operator quit, socket
            # failure, or an exception on a peer frame — this cycle's SLAC is
            # over, so the timer must not outlive it. Without this a failed
            # run left checkForTimeout re-sending CM_SLAC_PARM.REQ forever and
            # stacked a second timer onto the next cycle (issue #137). `stop`
            # ends the current cycle only; the sticky `quit` is untouched.
            self.stop = True
            self.timeoutThread.join(TIMEOUT_JOIN_TIMEOUT)
            if self.timeoutThread.is_alive():
                logger.error(
                    "SLAC timeout thread did not exit within %ss", TIMEOUT_JOIN_TIMEOUT
                )
            if self.neighborSolicitationThread.running:
                self.neighborSolicitationThread.stop()

    # The EVSE sometimes fails the SLAC process, so this automatically restarts it from the beginning
    def checkForTimeout(self):
        # `not self.quit` guards the re-arm race: if a quit lands after `start()`
        # reset `stop` to False, this thread must still exit rather than spin
        # forever and block the executor join (issue #40).
        while not self.stop and not self.quit:
            if int(time.time()) - self.timeSinceLastPkt > self.timeout:
                self.restart()
            if self.CM_START_ATTEN_CHAR_IND_sent and not self.stopSounds:
                now = int(time.time() * 1000)
                if now - self.slac_sound_start > (self.pev.slacSoundTimeout):
                    self.restart()
            time.sleep(0.01)
                    
    def restart(self):
        self.CM_ATTEN_CHAR_IND_recved = False
        self.CM_START_ATTEN_CHAR_IND_sent = False
        self.stopSounds = False
        if self.stop:
            return
        logger.info("Timed out... Sending SLAC_PARM_REQ")
        if not self._send(self.buildSlacParmReq()):
            return
        self.timeSinceLastPkt = int(time.time())
                
    def handleSLAC(self):
        # A quit may land between start()'s re-arm check and here; bail before
        # touching the socket so the operator quit isn't undone (issue #40).
        if self.quit:
            return
        logger.info("Sending CM_SLAC_PARM_REQ")
        self._send(self.buildSlacParmReq())
        while not self.stop and not self.quit:
            packet = self.receive()
            if not packet:
                continue
            if packet.haslayer("CM_SLAC_PARM_CNF"):
                self.handle_CM_SLAC_PARM_CNF(packet)
            elif packet.haslayer("CM_ATTEN_CHAR_IND"):
                self.handle_CM_ATTEN_CHAR_IND()
            elif packet.haslayer("CM_SLAC_MATCH_CNF"):
                self.handle_CM_SLAC_MATCH_CNF(packet)
        
    def max_num_sounds(self) -> int:
        """Most M-sounds the sound phase can send before the sound timeout."""
        return self.pev.slacSoundTimeout // SOUND_INTERVAL_MS

    def handle_CM_SLAC_PARM_CNF(self, packet: Packet):
        logger.info("Recieved CM_SLAC_PARM_CNF")
        num_sounds = packet[CM_SLAC_PARM_CNF].NumberMSounds
        max_sounds = self.max_num_sounds()
        if not MIN_NUM_SOUNDS <= num_sounds <= max_sounds:
            # Deviating content: ignore the frame as if it never arrived and
            # keep waiting; the timeout thread re-sends CM_SLAC_PARM.REQ.
            discard_out_of_spec(
                "CM_SLAC_PARM_CNF",
                "NUM_SOUNDS",
                num_sounds,
                f"{MIN_NUM_SOUNDS}..{max_sounds} (sendable within the "
                f"{self.pev.slacSoundTimeout} ms sound timeout at "
                f"{SOUND_INTERVAL_MS} ms per sound)",
            )
            return
        if num_sounds != SPEC_NUM_SOUNDS:
            accept_out_of_spec(
                "CM_SLAC_PARM_CNF",
                "NUM_SOUNDS",
                num_sounds,
                f"{SPEC_NUM_SOUNDS} (ISO 15118-3 Table A.1, C_EV_match_MNBC)",
            )
        self.destinationMAC = packet[Ether].src
        self.pev.destinationMAC = packet[Ether].src
        self.numSounds = num_sounds
        self.numRemainingSounds = self.numSounds
        
        logger.info("Sending 3 CM_START_ATTEN_CHAR_IND")
        self.slac_sound_start = int(time.time() * 1000)
        self.CM_START_ATTEN_CHAR_IND_sent = True
        self._send(self.buildStartAttenCharInd())
        for i in range(2):
            time.sleep(SOUND_INTERVAL_MS / 1000)
            self._send(self.buildStartAttenCharInd())

        logger.info(f"Sending {self.numSounds} CM_MNBC_SOUND_IND")
        self._send(self.buildMNBCSoundInd())
        for i in range(self.numSounds - 1):
            time.sleep(SOUND_INTERVAL_MS / 1000)
            self._send(self.buildMNBCSoundInd())
        return

    def handle_CM_ATTEN_CHAR_IND(self):
        self.stopSounds = True
        logger.info("Recieved CM_ATTEN_CHAR_IND")
        logger.info(f"Time taken for SLAC sound: {int(time.time() * 1000) - self.slac_sound_start} ms")
        if self.CM_ATTEN_CHAR_IND_recved == False:
            self.CM_ATTEN_CHAR_IND_recved = True
            logger.info("Sending ATTEN_CHAR_RES")
            self._send(self.buildAttenCharRes())
            logger.info("Sending SLAC_MATCH_REQ")
            self._send(self.buildSlacMatchReq())
        self.timeSinceLastPkt = int(time.time())
        return

    def handle_CM_SLAC_MATCH_CNF(self, packet: Packet):
        logger.info("Recieved SLAC_MATCH_CNF")
        self.NID = packet[CM_SLAC_MATCH_CNF].VariableField.NetworkID
        self.NMK = packet[CM_SLAC_MATCH_CNF].VariableField.NMK
        logger.info("Sending SET_KEY_REQ")
        self._send(self.buildSetKeyReq())
        self.stop = True
        return

    def buildSlacParmReq(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "ff:ff:ff:ff:ff:ff"

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        homePlugLayer = CM_SLAC_PARM_REQ()
        homePlugLayer.RunID = self.runID

        pkt = ethLayer / homePlugAVLayer / homePlugLayer
        return pkt

    def buildStartAttenCharInd(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "ff:ff:ff:ff:ff:ff"

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        homePlugLayer = CM_START_ATTEN_CHAR_IND()
        homePlugLayer.NumberOfSounds = self.numSounds
        homePlugLayer.TimeOut = 0x06
        homePlugLayer.ResponseType = 0x01
        homePlugLayer.ForwardingSTA = self.sourceMAC
        homePlugLayer.RunID = self.runID

        pkt = ethLayer / homePlugAVLayer / homePlugLayer
        return pkt

    def buildMNBCSoundInd(self):
        self.numRemainingSounds = self.numRemainingSounds - 1

        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "ff:ff:ff:ff:ff:ff"

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        homePlugLayer = CM_MNBC_SOUND_IND()
        homePlugLayer.Countdown = self.numRemainingSounds
        homePlugLayer.RunID = self.runID
        homePlugLayer.RandomValue = os.urandom(16)

        pkt = ethLayer / homePlugAVLayer / homePlugLayer
        return pkt

    def buildAttenCharRes(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        homePlugLayer = CM_ATTEN_CHAR_RSP()
        homePlugLayer.SourceAdress = self.sourceMAC
        homePlugLayer.RunID = self.runID
        homePlugLayer.Result = 0x00

        pkt = ethLayer / homePlugAVLayer / homePlugLayer
        return pkt

    def buildSlacMatchReq(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        homePlugLayer = CM_SLAC_MATCH_REQ()
        homePlugLayer.MatchVariableFieldLen = 0x3E00

        slacVars = SLAC_varfield()
        slacVars.EVMAC = self.sourceMAC
        slacVars.EVSEMAC = self.destinationMAC
        slacVars.RunID = self.runID

        homePlugLayer.VariableField = slacVars

        pkt = ethLayer / homePlugAVLayer / homePlugLayer
        return pkt

    # This packet is proof that I'm not allowed to have a good time
    def buildSetKeyReq(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "00:b0:52:00:00:01"  # Some AtherosC MAC for whatever reason

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        homePlugLayer = CM_SET_KEY_REQ()
        homePlugLayer.KeyType = 0x1
        homePlugLayer.MyNonce = 0xAAAAAAAA
        homePlugLayer.YourNonce = 0x00000000
        homePlugLayer.PID = 0x4
        homePlugLayer.NetworkID = self.NID
        homePlugLayer.NewEncKeySelect = 0x1
        homePlugLayer.NewKey = self.NMK

        responsePacket = ethLayer / homePlugAVLayer / homePlugLayer
        return responsePacket

    def buildNeighborAdvertisement(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = self.destinationIP
        ipLayer.plen = 32
        ipLayer.hlim = 255

        icmpLayer = ICMPv6ND_NA()
        icmpLayer.type = 136
        icmpLayer.R = 0
        icmpLayer.S = 1
        icmpLayer.tgt = self.sourceIP

        optLayer = ICMPv6NDOptDstLLAddr()
        optLayer.type = 2
        optLayer.len = 1
        optLayer.lladdr = self.sourceMAC

        responsePacket = ethLayer / ipLayer / icmpLayer / optLayer
        return responsePacket

    def sendNeighborSoliciation(self, pkt):
        # if self.stop: exit()
        # if not (pkt.haslayer("ICMPv6ND_NS") and pkt[ICMPv6ND_NS].tgt == self.sourceIP): return
        # self.destinationMAC = pkt[Ether].src
        self.destinationIP = pkt[IPv6].src
        # logger.info("Sending Neighor Advertisement")
        sendp(self.buildNeighborAdvertisement(), iface=self.iface, verbose=0)