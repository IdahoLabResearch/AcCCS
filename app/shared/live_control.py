"""Shared live-control state for the operator console.

Per ADR-0004 (`docs/adr/0004-operator-console-live-control.md`) the operator
console is the project's single, deliberate exception to the otherwise
load-once configuration story: a `LiveControl` object is created once at
startup, injected into the controller, and reachable from `comm_session`. The
footer mutates it; controllers and state machines read it each loop cycle.

Started as the tracer-bullet slice (issue #28) with one capability — the EVCC
charge-loop [[stall]] arm flag plus its one-shot `asyncio.Event` release signal.
Since then it has grown the live-override values (issue #29) and the SECC
authorization-gate stall (issue #30) onto the same object: per ADR-0004 it
holds role-aware override values, a per-gate stall arm flag, and a per-gate
`asyncio.Event` release signal.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Lifecycle phases surfaced by the operator-console footer (ADR-0005). The
# string is the literal footer text. `advance()` compares the live phase against
# PHASE_IDLE to make the [a] key phase-dependent, and the controllers set these
# same values as they move through a session cycle — so the dispatch and the
# indicator must agree on the exact string, which is why they share a constant
# rather than each spelling out a literal.
PHASE_WAITING_FOR_SLAC = "Waiting for SLAC"
PHASE_SESSION_ACTIVE = "Session active"
PHASE_IDLE = "Idle - press 'a' to start"


class LiveControl:
    """One source of truth for live, mid-session operator intent.

    `console_enabled` records whether the interactive footer is active for
    this run (resolved once at startup from `runtime.console.mode` + TTY
    detection). Each stall gate is armable three ways — `runtime.yaml`, a CLI
    flag, and the live footer toggle — which converge on `stall_charge_loop`
    (the EVCC's forceful hold over the ISO-2 DC CurrentDemand loop) and
    `stall_authorization` (the SECC's forceful hold over the ISO-2
    Authorization gate). The protocol assigns each gate to one role, so a given
    run only ever consumes the gate its role owns; the object carries both so
    the one footer surface can drive either.

    Each release signal is modelled as an `asyncio.Event` per ADR-0004. The
    holder polls it (rather than awaiting): the charge loop must keep cycling
    real CurrentDemand traffic on the wire while the gate is held — blocking
    would starve the peer and trip its receive timeout — and the SECC reads it
    once per inbound AuthorizationReq. `take_*` consumes the signal as a
    one-shot: there is no auto-release, timeout, or cycle cap.
    """

    def __init__(
        self,
        *,
        console_enabled: bool = False,
        stall_charge_loop: bool = False,
        stall_authorization: bool = False,
        override_current_a: Optional[float] = None,
        override_voltage_v: Optional[float] = None,
        phase: str = PHASE_WAITING_FOR_SLAC,
    ) -> None:
        self.console_enabled = console_enabled
        # Current lifecycle phase, surfaced by the operator-console footer.
        # Direct assignment transitions the phase; later slices add phases such
        # as "Idle" and auto-rearm states without changing the mechanism.
        self.phase = phase
        # Set to True when the operator presses 'q'; run_with_console inspects
        # this to return normally (rather than re-raising CancelledError) so the
        # run scripts' teardown code (setState A / openProximity) still executes.
        self.quit_requested: bool = False
        # Teardown callbacks run synchronously when the operator presses 'q'.
        # The controller registers one here to stop in-flight background work
        # the asyncio layer can't reach — chiefly the SLAC handler, whose
        # blocking recv() and timeout thread run in a thread pool that task
        # cancellation cannot interrupt (issue #40). Without this, 'q' tears
        # down only the TUI while SLAC keeps sending and the process hangs.
        self._quit_hooks: list[Callable[[], None]] = []
        self.stall_charge_loop = stall_charge_loop
        # SECC authorization-gate stall (ADR-0004, issue #30): while armed the
        # SECC holds EVSEProcessing.ONGOING on the ISO-2 Authorization loop,
        # keeping the EVCC polling until the operator passes the gate.
        self.stall_authorization = stall_authorization
        # Live current/voltage override for the ISO 15118-2 DC charge loop
        # (ADR-0004, issue #29). `None` means "use the personality-derived
        # value". The override is role-aware *at the read site*: an EVCC reads
        # these as its requested target (CurrentDemandReq), an SECC as its
        # reported present/delivered value (CurrentDemandRes). Values are
        # unchecked — whatever the operator types is sent as long as the EXI
        # codec can encode it (no clamping to the personality envelope).
        self.override_current_a = override_current_a
        self.override_voltage_v = override_voltage_v
        # One-shot release for the charge-loop exit gate. Constructed without a
        # running loop (PEV.__init__ runs before asyncio.run); asyncio.Event on
        # Python 3.10+ binds to the loop lazily, and we only ever poll
        # (is_set/clear) and set() it — never await it — so no loop is required.
        self._charge_loop_release = asyncio.Event()
        # One-shot release for the Authorization gate. Same lazy-loop-binding
        # rationale as the charge-loop release above: it is constructed before
        # asyncio.run and only ever polled/set, never awaited.
        self._authorization_release = asyncio.Event()
        # One-shot re-arm signal for the idle-and-re-arm lifecycle (ADR-0005).
        # Distinct from the per-gate releases above: those pass a stall gate
        # mid-session, whereas this re-arms a side sitting in [[idle]] to begin
        # the next session cycle. Same lazy-loop-binding / poll-not-await
        # rationale — the controller's idle wait polls `take_advance` so an
        # operator quit can break the wait too. Only ever set while idle (see
        # `advance`), so it can't leak into the next idle stretch.
        self._advance_signal = asyncio.Event()

    # -- charge-loop stall arming -------------------------------------------

    def arm_charge_loop_stall(self) -> None:
        """Arm the charge-loop gate, discarding any stale release signal.

        Clearing the event on arm means a release pressed while disarmed can
        never leak into the next armed stretch and end it prematurely.
        """
        self.stall_charge_loop = True
        self._charge_loop_release.clear()

    def disarm_charge_loop_stall(self) -> None:
        self.stall_charge_loop = False

    def toggle_charge_loop_stall(self) -> None:
        """Flip the charge-loop stall arm flag (the footer's ``[s]`` action)."""
        if self.stall_charge_loop:
            self.disarm_charge_loop_stall()
        else:
            self.arm_charge_loop_stall()

    # -- charge-loop release (the gate) -------------------------------------

    def release_charge_loop(self) -> None:
        """Pass the charge-loop gate once (the footer's ``[a]dvance`` action)."""
        self._charge_loop_release.set()

    def take_charge_loop_release(self) -> bool:
        """Consume a pending release. Returns True exactly once per signal."""
        if self._charge_loop_release.is_set():
            self._charge_loop_release.clear()
            return True
        return False

    # -- authorization stall arming -----------------------------------------

    def arm_authorization_stall(self) -> None:
        """Arm the authorization gate, discarding any stale release signal.

        Clearing the event on arm means a release pressed while disarmed can
        never leak into the next armed stretch and end it prematurely (mirrors
        `arm_charge_loop_stall`).
        """
        self.stall_authorization = True
        self._authorization_release.clear()

    def disarm_authorization_stall(self) -> None:
        self.stall_authorization = False

    def toggle_authorization_stall(self) -> None:
        """Flip the authorization stall arm flag (the SECC footer's ``[s]`` action)."""
        if self.stall_authorization:
            self.disarm_authorization_stall()
        else:
            self.arm_authorization_stall()

    # -- authorization release (the gate) -----------------------------------

    def release_authorization(self) -> None:
        """Pass the authorization gate once (the SECC footer's ``[a]dvance`` action)."""
        self._authorization_release.set()

    def take_authorization_release(self) -> bool:
        """Consume a pending release. Returns True exactly once per signal."""
        if self._authorization_release.is_set():
            self._authorization_release.clear()
            return True
        return False

    # -- lifecycle advance (re-arm from idle) -------------------------------

    def advance(self, *, is_secc: bool) -> None:
        """Dispatch the operator advance (the footer's ``[a]``) by lifecycle phase.

        The [a] key is phase-dependent (ADR-0005): while the side sits in
        [[idle]] it re-arms to begin the next [[session cycle]]; during an
        active session it releases this role's stall gate once (the ADR-0004
        behaviour, unchanged). The live `phase` field is the single source of
        truth for that decision, so the same string that drives the footer
        indicator also drives the dispatch here. The role owns exactly one gate
        — the EVCC the charge loop, the SECC the Authorization gate — so the
        caller passes which one this run is.
        """
        if self.phase == PHASE_IDLE:
            self.signal_advance()
        elif is_secc:
            self.release_authorization()
        else:
            self.release_charge_loop()

    def signal_advance(self) -> None:
        """Re-arm the side from idle to begin the next session cycle (ADR-0005)."""
        self._advance_signal.set()

    def take_advance(self) -> bool:
        """Consume a pending re-arm signal. Returns True exactly once per signal."""
        if self._advance_signal.is_set():
            self._advance_signal.clear()
            return True
        return False

    # -- live current/voltage override --------------------------------------

    def set_override_current(self, value: float) -> None:
        """Set the live current override (amperes). Persists until changed/cleared."""
        self.override_current_a = value

    def set_override_voltage(self, value: float) -> None:
        """Set the live voltage override (volts). Persists until changed/cleared."""
        self.override_voltage_v = value

    def clear_overrides(self) -> None:
        """Clear both overrides so the read site falls back to the personality value."""
        self.override_current_a = None
        self.override_voltage_v = None

    # -- operator quit ---------------------------------------------------------

    def register_quit_hook(self, hook: Callable[[], None]) -> None:
        """Register a teardown callback invoked synchronously on operator quit.

        Hooks run on the console's event-loop thread inside `request_quit`, so
        they must be quick and thread-safe. The canonical hook closes the SLAC
        raw socket to unblock a thread parked in `recv()` — work that lives in a
        thread pool and is therefore beyond the reach of asyncio task
        cancellation (issue #40).
        """
        self._quit_hooks.append(hook)

    def request_quit(self) -> None:
        """Signal that the operator has requested a graceful quit (the 'q' key).

        Sets `quit_requested` (which `run_with_console` inspects after the TUI
        exits, returning normally instead of re-raising CancelledError so the
        run scripts' teardown — setState A / openProximity — still executes) and
        runs every registered teardown hook. Hooks are best-effort: a raising
        hook is logged and the rest still run, so one failure can't strand the
        quit.
        """
        self.quit_requested = True
        for hook in self._quit_hooks:
            try:
                hook()
            except Exception:  # noqa: BLE001 - teardown is best-effort
                logger.debug("Operator-quit teardown hook raised", exc_info=True)
