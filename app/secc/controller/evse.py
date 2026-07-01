"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
    Copyright 2025, Ford Motor Company
    Copyright 2022, Switch

    This class is used to emulate a EVSE when talking to an PEV. Handles level 2 SLAC communications
    and level 3 UDP and TCP communications to the electric vehicle.
"""

import asyncio
import logging

from app.secc import SECCHandler
from app.secc.controller.interface import ServiceStatus
from app.secc.controller.simulator import SimEVSEController
from app.secc.secc_settings import Config
from app.secc.transport.slac import SLACHandler
from app.shared.console import resolve_console_enabled, run_with_console
from app.shared.expy_exi_codec import EXPyEXICodec
from app.shared.live_control import (
    PHASE_IDLE,
    PHASE_SESSION_ACTIVE,
    PHASE_WAITING_FOR_SLAC,
    LiveControl,
)
from app.shared.logging import _init_logger
from app.shared.network import (
    get_link_local_addr,
    get_nic_mac_address,
    get_tcp_port,
)
from app.shared.personality import (
    SECCPersonality,
    apply_runtime_overrides,
    load_personality,
    load_runtime,
)

logger = logging.getLogger(__name__)


class EVSE:

    # The SECC re-arms by re-listening for SLAC, so [[auto-rearm]] needs no
    # inter-cycle pacing (ADR-0005) — only the EVCC, which initiates, throttles
    # itself. Kept as a symmetric attribute so the shared `_auto_rearm_delay`
    # logic reads identically on both sides.
    _AUTO_REARM_DELAY_S = 0.0

    def __init__(self, args):
        personality = load_personality(args.config, role="secc")
        assert isinstance(personality, SECCPersonality)
        runtime = apply_runtime_overrides(load_runtime(args.runtime), args)
        _init_logger(
            source="SECC",
            console_level=runtime.log.console_level,
            file_level=runtime.log.file_level,
        )

        self.personality = personality
        self.runtime = runtime
        self.config = Config.from_personality(personality, runtime)

        self.iface = self.config.iface
        self.sourceMAC = get_nic_mac_address(self.iface)
        self.sourceIP = str(get_link_local_addr(self.iface))
        self.sourcePort = runtime.source_port if runtime.source_port else 25565

        # NID/NMK come from `personality.residual.slac` (ADR-0006 moved the
        # non-wire SLAC section under residual). The historical `--NID` /
        # `--NMK` CLI flags are gone (personality fields are not CLI-overridable).
        self.NID = bytes.fromhex(personality.residual.slac.nid_hex)
        self.NMK = bytes.fromhex(personality.residual.slac.nmk_hex)
        self.modified_cordset = runtime.modified_cordset

        # Operator console (ADR-0004). The SECC owns the ISO-2 authorization
        # gate, so `stall_authorization` is the stall this role actually
        # consumes; `stall_charge_loop` is carried for the shared LiveControl
        # shape but never read on the SECC side.
        self.live_control = LiveControl(
            console_enabled=resolve_console_enabled(runtime.console.mode),
            stall_charge_loop=runtime.stall.charge_loop,
            stall_authorization=runtime.stall.authorization,
            auto_rearm=runtime.rearm.auto,
        )

        self.destinationMAC = None
        self.destinationIP = None
        self.destinationPort = None
        self.slac = None

        # Operator 'q' quit must stop the SLAC handler, whose blocking recv()
        # and timeout thread run in a thread pool that asyncio cancellation
        # can't reach (issue #40). Late-binds to the current `self.slac` so a
        # future re-armed cycle's handler is the one torn down.
        self.live_control.register_quit_hook(self._teardown_slac)

        self.virtual = self.config.virtual

        if not self.virtual:
            from smbus import SMBus

            # I2C bus for relays
            self.bus = SMBus(1)

            # Constants for i2c controlled relays
            self.I2C_ADDR = 0x20
            self.CONTROL_REG = 0x9
            self.EVSE_CP = 0b1
            self.EVSE_PP = 0b1000
            self.ALL_OFF = 0b0

    # Start the emulator
    def _teardown_slac(self) -> None:
        """Stop the in-flight SLAC handler on operator quit (issue #40)."""
        if self.slac is not None:
            self.slac.stop_handler()

    async def _await_rearm(self) -> None:
        """Block in [[idle]] until the operator advances (re-arm) or quits.

        Polls rather than awaits the re-arm signal so an operator quit pressed
        while idle also breaks the wait (mirrors the gate-release polling on
        LiveControl). Also returns the instant [[auto-rearm]] is flipped on
        live (`r`), so the lifecycle loop re-arms without a manual advance.
        Returns once a re-arm is consumed, auto-rearm turns on, or
        `quit_requested` is set; the caller re-checks `quit_requested` to
        decide whether to loop.
        """
        while not self.live_control.quit_requested:
            if self.live_control.auto_rearm or self.live_control.take_advance():
                return
            await asyncio.sleep(0.05)

    async def _auto_rearm_delay(self) -> None:
        """Pace [[auto-rearm]] before re-arming the next cycle (ADR-0005).

        The SECC's `_AUTO_REARM_DELAY_S` is 0, so this returns immediately —
        it re-listens with no added delay. Kept symmetric with the EVCC so the
        lifecycle loop reads the same on both sides; the poll loop also lets an
        operator quit during any (EVCC) delay break out promptly.
        """
        elapsed = 0.0
        while (
            elapsed < self._AUTO_REARM_DELAY_S
            and not self.live_control.quit_requested
        ):
            await asyncio.sleep(0.05)
            elapsed += 0.05

    async def start(self):
        if not self.virtual:
            # Initialize the smbus for I2C commands
            self.bus.write_byte_data(self.I2C_ADDR, 0x00, 0x00)
            self.toggleProximity()

        self.iface = self.config.iface
        # Reused across cycles: SLAC's `start()` re-initialises its per-cycle
        # state each call (ADR-0005), and the sticky operator-quit flag must
        # survive a re-arm (issue #40), so the handler persists for the whole
        # process lifetime rather than being rebuilt per cycle.
        self.slac = SLACHandler(self)

        logger.info(f"SECC MAC address: {self.sourceMAC}")

        async def _run():
            # Outer lifecycle loop (ADR-0005): run a session cycle, reset to a
            # clean idle state, wait to be re-armed, repeat. The only thing that
            # leaves this loop is an operator quit — neither a clean SessionStop
            # nor a failure exits the process.
            loop = asyncio.get_running_loop()
            while not self.live_control.quit_requested:
                # Start each cycle from a clean gate state: a stall release left
                # pending from a prior cycle must not pre-release this cycle's
                # stall gate (issue #55). Arm flags persist (a CLI-armed stall
                # engages every cycle); only the one-shot releases are reset.
                self.live_control.begin_cycle()
                # The full per-cycle body runs under one return-to-idle guard
                # (ADR-0005, #56): SLAC (run in an executor), the session, and
                # the electrical-state writes all sit here, so an unexpected
                # exception in any of them is logged and drops the side back to
                # idle for a harmless retry rather than propagating out of the
                # loop and exiting the process. Only an operator quit leaves it.
                try:
                    # Re-assert the relay-closed ("present") state so the EV side
                    # is seen before SLAC. The pre-loop toggleProximity() does
                    # this for the first cycle; on re-arm we're returning from the
                    # relay-open state set at the end of the prior cycle
                    # (openProximity below), so the cycle-end open + this re-close
                    # is the edge real hardware needs — without it cycle 2+ SLAC
                    # never engages (#52). No-op under --virtual (closeProximity
                    # guards on it); the outer guard keeps the virtual log stream
                    # unchanged.
                    if not self.virtual:
                        self.closeProximity()  # proximity closed
                    # Console is already live when SLAC begins; re-performed every
                    # cycle (the SECC re-arms by re-listening for SLAC).
                    self.live_control.phase = PHASE_WAITING_FOR_SLAC
                    await loop.run_in_executor(None, self.doSLAC)
                    if self.live_control.quit_requested:
                        break
                    self.live_control.phase = PHASE_SESSION_ACTIVE
                    # Fresh controller + handler per cycle so no stale session
                    # context carries over; the handler's receive loop returns
                    # once the session terminates (ADR-0005).
                    sim_evse_controller = SimEVSEController(
                        personality=self.personality, live_control=self.live_control
                    )
                    await sim_evse_controller.set_status(ServiceStatus.STARTING)
                    await SECCHandler(
                        exi_codec=EXPyEXICodec(),
                        evse_controller=sim_evse_controller,
                        config=self.config,
                    ).start(self.config.iface)
                except Exception as exc:  # noqa: BLE001 - failures return to idle
                    # An unexpected SLAC exception, an SDP failure, a mid-session
                    # error, or a relay write failure all drop the side back to
                    # idle for a harmless retry (ADR-0005) rather than killing the
                    # process.
                    logger.error(f"SECC session cycle ended with an error: {exc}")
                # Session cycle ended (clean or failure) -> reset to clean idle.
                # The relay reset is itself guarded so an openProximity I2C error
                # also returns to idle, and it runs after a clean session or a
                # failure so the next cycle gets its present-state edge (#52).
                try:
                    self.openProximity()  # proximity open
                except Exception as exc:  # noqa: BLE001 - failures return to idle
                    logger.error(
                        f"SECC failed to reset to idle electrical state: {exc}"
                    )
                if self.live_control.quit_requested:
                    break
                self.live_control.phase = PHASE_IDLE
                if self.live_control.auto_rearm:
                    # Auto-rearm (ADR-0005): skip the idle wait and re-listen
                    # immediately. The SECC needs no inter-cycle delay (its
                    # `_auto_rearm_delay` is a no-op); only the initiating EVCC
                    # paces itself.
                    await self._auto_rearm_delay()
                else:
                    await self._await_rearm()

        if self.live_control.console_enabled:
            await run_with_console(self.live_control, _run(), source="SECC")
        else:
            await _run()

    def doSLAC(self):
        self.slac.start()
        logger.info("Done SLAC")

    def closeProximity(self):
        if self.modified_cordset:
            logger.info("Closing CP/PP relay connections")
            if not self.virtual:
                self.bus.write_byte_data(
                    self.I2C_ADDR, self.CONTROL_REG, self.EVSE_PP | self.EVSE_CP
                )
        else:
            logger.info("Closing CP relay connection")
            if not self.virtual:
                self.bus.write_byte_data(
                    self.I2C_ADDR, self.CONTROL_REG, self.EVSE_CP
                )

    def openProximity(self):
        logger.info("Opening CP/PP relay connections")
        if not self.virtual:
            self.bus.write_byte_data(self.I2C_ADDR, self.CONTROL_REG, self.ALL_OFF)

    def toggleProximity(self, t: int = 5):
        import time

        self.openProximity()
        time.sleep(t)
        self.closeProximity()
