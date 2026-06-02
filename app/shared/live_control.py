"""Shared live-control state for the operator console.

Per ADR-0004 (`docs/adr/0004-operator-console-live-control.md`) the operator
console is the project's single, deliberate exception to the otherwise
load-once configuration story: a `LiveControl` object is created once at
startup, injected into the controller, and reachable from `comm_session`. The
footer mutates it; controllers and state machines read it each loop cycle.

This is the tracer-bullet slice (issue #28). `LiveControl` carries exactly one
capability so far — the EVCC charge-loop [[stall]] arm flag plus its one-shot
`asyncio.Event` release signal. Subsequent slices add the live-override values
and the SECC authorization-gate stall to this same object.
"""

from __future__ import annotations

import asyncio


class LiveControl:
    """One source of truth for live, mid-session operator intent.

    `console_enabled` records whether the interactive footer is active for
    this run (resolved once at startup from `runtime.console.mode` + TTY
    detection). The charge-loop stall is armable three ways — `runtime.yaml`,
    a CLI flag, and the live footer toggle — all of which converge on
    `stall_charge_loop`.

    The release signal is modelled as an `asyncio.Event` per ADR-0004. The
    charge loop polls it (rather than awaiting) because the loop must keep
    cycling real CurrentDemand traffic on the wire while the gate is held —
    blocking would starve the peer and trip its receive timeout. `take_*`
    consumes the signal as a one-shot: there is no auto-release, timeout, or
    cycle cap.
    """

    def __init__(
        self,
        *,
        console_enabled: bool = False,
        stall_charge_loop: bool = False,
    ) -> None:
        self.console_enabled = console_enabled
        self.stall_charge_loop = stall_charge_loop
        # One-shot release for the charge-loop exit gate. Constructed without a
        # running loop (PEV.__init__ runs before asyncio.run); asyncio.Event on
        # Python 3.10+ binds to the loop lazily, and we only ever poll
        # (is_set/clear) and set() it — never await it — so no loop is required.
        self._charge_loop_release = asyncio.Event()

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
