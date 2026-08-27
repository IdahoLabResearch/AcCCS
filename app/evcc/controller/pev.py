"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
    Copyright 2025, Ford Motor Company
    Copyright 2022, Switch

    This class is used to emulate a PEV when talking to an EVSE. Handles level 2 SLAC communications
    and level 3 UDP and TCP communications to the charging station.
"""

import asyncio
import logging

from app.evcc import Config, EVCCHandler
from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.evcc.transport.slac import SLACHandler
from app.shared.console import resolve_console_enabled, run_with_console
from app.shared.EmulatorEnum import PEVState
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
    EVCCPersonality,
    Runtime,
    apply_runtime_overrides,
    load_personality,
    load_runtime,
)
from app.shared.relays import EvccRelays

logger = logging.getLogger(__name__)


class PEV:

    # Inter-cycle delay (seconds) before [[auto-rearm]] re-arms the EVCC for
    # the next cycle (ADR-0005). The EVCC initiates SLAC, so a fast-failing
    # setup would otherwise hammer in a tight loop and bury the logs; a short
    # beat keeps the output readable. The SECC only re-listens, so its delay
    # is 0 (see EVSE._AUTO_REARM_DELAY_S).
    _AUTO_REARM_DELAY_S = 1.5

    def __init__(self, args):
        # Load personality + runtime first so the logger can pick up the
        # operator's chosen levels before we emit anything.
        personality = load_personality(args.config, role="evcc")
        assert isinstance(personality, EVCCPersonality)
        runtime = apply_runtime_overrides(load_runtime(args.runtime), args)
        _init_logger(
            source="EVCC",
            console_level=runtime.log.console_level,
            file_level=runtime.log.file_level,
        )

        self.personality = personality
        self.runtime = runtime
        self.config = Config.from_personality(personality, runtime)
        self.evcc_config = EVCCConfig.from_personality(personality)

        # Operator console + live control (ADR-0004). Resolved once at startup:
        # console activation honours TTY auto-detection, and the charge-loop
        # stall is armable from runtime.yaml / CLI here (the footer can also
        # arm it live). The EVCC owns the charge-loop gate; `stall_authorization`
        # is carried for the shared LiveControl shape but never read here.
        self.live_control = LiveControl(
            console_enabled=resolve_console_enabled(runtime.console.mode),
            stall_charge_loop=runtime.stall.charge_loop,
            stall_authorization=runtime.stall.authorization,
            auto_rearm=runtime.rearm.auto,
        )

        self.iface = self.config.iface
        self.sourceMAC = get_nic_mac_address(self.iface)
        self.sourceIP = str(get_link_local_addr(self.iface))
        self.sourcePort = runtime.source_port if runtime.source_port else get_tcp_port()
        self.slacSoundTimeout = personality.residual.slac.sound_timeout_ms

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

        # Relay wiring lives entirely in `app/shared/relays.py` (issue #108):
        # the EV side touches only the pins it owns, so a SECC on the same box
        # keeps its relays.
        self.relays = EvccRelays(virtual=self.virtual)

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

        Sleeps `_AUTO_REARM_DELAY_S` (the EVCC's inter-cycle beat) so a
        fast-failing setup does not hammer in a tight loop. Polled in small
        steps so an operator quit during the delay still breaks out promptly.
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
            # Claim only this role's pins as outputs (the other role's and the
            # unused spares keep their direction), then assert the startup
            # State A -> B edge.
            self.relays.initialize()
            self.toggleProximity()

        # Reused across cycles: SLAC's `start()` re-initialises its per-cycle
        # state each call (ADR-0005), and the sticky operator-quit flag must
        # survive a re-arm (issue #40), so the handler persists for the whole
        # process lifetime rather than being rebuilt per cycle.
        self.slac = SLACHandler(self)

        logger.info(f"EVCC MAC address: {self.sourceMAC}")

        async def _run():
            # Outer lifecycle loop (ADR-0005): run a session cycle, drop back to
            # idle, wait to be re-armed, repeat. The only thing that leaves this
            # loop is an operator quit — neither a clean SessionStop nor a
            # failure exits the process.
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
                    # Re-assert CP State B ("EV present") so the EVSE detects the
                    # EV before SLAC. The pre-loop toggleProximity() does this for
                    # the first cycle; on re-arm we're returning from the State A
                    # set at the end of the prior cycle (openProximity below), so
                    # the cycle-end open + this re-close is the unplug→replug edge
                    # real hardware needs — without it cycle 2+ SLAC never engages
                    # (#52). Under --virtual the relay module attempts no bus
                    # operation; the guard keeps the log stream unchanged too.
                    if not self.virtual:
                        self.closeProximity()  # CP line State B
                    # Console is already live when SLAC begins; re-performed every
                    # cycle (the EVCC re-arms by re-initiating SLAC).
                    self.live_control.phase = PHASE_WAITING_FOR_SLAC
                    await loop.run_in_executor(None, self.doSLAC)
                    if self.live_control.quit_requested:
                        break
                    self.live_control.phase = PHASE_SESSION_ACTIVE
                    # Fresh handler per cycle: its SDP retry-cycle budget and
                    # session state must start clean (a reused handler would
                    # exhaust its retry cycles after a few sessions).
                    await EVCCHandler(
                        evcc_config=self.evcc_config,
                        iface=self.config.iface,
                        exi_codec=EXPyEXICodec(),
                        ev_controller=SimEVController(
                            self.evcc_config, self.live_control
                        ),
                        live_control=self.live_control,
                        ongoing_poll_interval=(
                            self.runtime.poll.ongoing_interval_seconds
                        ),
                    ).start()
                except Exception as exc:  # noqa: BLE001 - failures return to idle
                    # An unexpected SLAC exception, an SDP failure, a mid-session
                    # error, or a CP-line write failure all drop the side back to
                    # idle for a harmless retry (ADR-0005) rather than killing the
                    # process.
                    logger.error(f"EVCC session cycle ended with an error: {exc}")
                # Session cycle ended (clean or failure) -> return to idle. The
                # CP-line reset is itself guarded so an openProximity I2C error
                # also returns to idle, and it runs after a clean session or a
                # failure so the next cycle gets its State A->B edge (#52).
                try:
                    self.openProximity()  # CP line State A
                except Exception as exc:  # noqa: BLE001 - failures return to idle
                    logger.error(
                        f"EVCC failed to reset to idle electrical state: {exc}"
                    )
                if self.live_control.quit_requested:
                    break
                self.live_control.phase = PHASE_IDLE
                if self.live_control.auto_rearm:
                    # Auto-rearm (ADR-0005): skip the idle wait and re-arm
                    # immediately, after a short inter-cycle delay so the EVCC
                    # doesn't hammer SLAC when a setup fails fast.
                    await self._auto_rearm_delay()
                else:
                    await self._await_rearm()

        if self.live_control.console_enabled:
            await run_with_console(self.live_control, _run(), source="EVCC")
        else:
            await _run()

    def doSLAC(self):
        logger.info("Starting SLAC")
        self.slac.start()
        logger.info("Done SLAC")

    def closeProximity(self):
        self.setState(PEVState.B)

    def openProximity(self):
        self.setState(PEVState.A)

    def setState(self, state: PEVState):
        self.relays.set_state(state)

    def toggleProximity(self, t: int = 5):
        self.relays.toggle_proximity(t)
