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
from typing import Optional


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
        override_current_a: Optional[float] = None,
        override_voltage_v: Optional[float] = None,
    ) -> None:
        self.console_enabled = console_enabled
        self.stall_charge_loop = stall_charge_loop
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
