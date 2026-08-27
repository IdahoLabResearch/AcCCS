#!/usr/bin/env python3
"""Interactive control of the EVCC control-pilot relays, no emulator attached.

Bench helper for exercising the I2C relay board and the CP/PP wiring in
isolation: it drives the relays through the same shared module the emulator
uses (`app/shared/relays.py`) but without loading a personality, running SLAC,
or opening a session. Type a state, watch the EVSE react.

Like the emulator it touches only the EV side's pins (issue #108), so a SECC
running on the same box keeps its relays while you drive states here.

States (as seen by the EVSE):

    A  all relays off               -> no vehicle present
    B  PP + CP1                     -> vehicle present, not ready to charge
    C  PP + CP1 + CP2               -> vehicle present, ready to charge

Usage:

    python scripts/evcc_relays.py

    state> b        # or 'B' - close PP + CP1
    state> c        # add CP2
    state> a        # all relays open
    state> q        # quit (relays opened on the way out)

The relays are ALWAYS opened on exit - a clean quit, Ctrl-C, Ctrl-D, a
`kill`, or the terminal window being closed (SIGHUP) all reset the line to
state A, so a walked-away-from session never leaves the EVSE seeing a
plugged-in EV.

Needs the real hardware: an SMBus-capable host (the Pi) with the relay board
on I2C bus 1, run as a user with access to /dev/i2c-1.
"""

from __future__ import annotations

import atexit
import signal
import sys
from pathlib import Path

# Run straight out of the repo (`python scripts/evcc_relays.py`): only the
# script's own directory lands on sys.path, so put the repo root there too and
# the shared relay module imports the same way it does for the emulator.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from app.shared.EmulatorEnum import PEVState  # noqa: E402
from app.shared.relays import (  # noqa: E402
    EVCC_MASK,
    I2C_ADDR,
    I2C_BUS,
    EvccRelays,
)

STATES = {"A": PEVState.A, "B": PEVState.B, "C": PEVState.C}

PROMPT = "state> "
HELP = "Enter a state (a/b/c), '?' for this help, or 'q' to quit."


def say(message: str) -> None:
    """Print, tolerating a stdout that has already gone away.

    On a terminal close the write side can be dead before our SIGHUP handler
    runs; the relay reset matters, a failed print does not.
    """
    try:
        print(message, flush=True)
    except OSError:
        pass


class RelayBoard:
    """The EV side's relays, with a guaranteed open-on-exit.

    A thin bench wrapper over the shared `EvccRelays`: the bus handle, the
    masks, and the read-modify-write live there, so this script cannot drift
    from what the emulator actually writes — or clobber the SECC's pins.
    """

    def __init__(self):
        try:
            import smbus  # noqa: F401 - presence check, EvccRelays opens the bus
        except ImportError:
            sys.exit(
                "smbus is not available - this script only runs on the "
                "hardware host (the Pi)."
            )

        self.relays = EvccRelays(virtual=False)
        # Claim only the EV side's pins as outputs; the SECC's and the unused
        # spares keep their direction.
        self.relays.initialize()
        self.state = None
        self._closed = False

    def set_state(self, state: str) -> None:
        pev_state = STATES[state]
        self.relays.set_state(pev_state)
        self.state = state
        say(
            f"Going to state {state} "
            f"(EV bits = {EvccRelays.STATE_BITS[pev_state]:#07b})"
        )

    def open_all(self) -> None:
        """Open our relays and close the bus. Safe to call more than once."""
        if self._closed:
            return
        self._closed = True
        try:
            self.relays.open_proximity()
            self.state = "A"
            say("All EV relays open (state A).")
        except OSError as exc:
            say(f"Failed to open relays: {exc}")
        finally:
            try:
                self.relays.close()
            except OSError:
                pass


def install_exit_hooks(board: RelayBoard) -> None:
    """Open the relays on every way out of this process.

    `atexit` covers the normal returns and uncaught exceptions; the signal
    handlers cover the ones that would otherwise bypass it - a closed terminal
    window (SIGHUP), a `kill` (SIGTERM), and Ctrl-\\ (SIGQUIT). Each handler
    raises SystemExit so unwinding runs the atexit hook exactly once.
    """
    atexit.register(board.open_all)

    def _bail(signum, _frame):
        say(f"\nGot signal {signum} - opening relays.")
        raise SystemExit(128 + signum)

    for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGQUIT):
        signal.signal(sig, _bail)


def main() -> int:
    board = RelayBoard()
    install_exit_hooks(board)

    say(
        f"EVCC relay control on I2C bus {I2C_BUS}, address {I2C_ADDR:#04x}, "
        f"driving only the EV side's pins (mask {EVCC_MASK:#010b})."
    )
    say(HELP)
    # Start from a known line state rather than whatever the board was left in.
    board.set_state("A")

    while True:
        try:
            entry = input(PROMPT).strip().upper()
        except EOFError:  # Ctrl-D
            say("")
            return 0
        except KeyboardInterrupt:  # Ctrl-C
            say("")
            return 130

        if not entry:
            continue
        if entry in ("Q", "QUIT", "EXIT"):
            return 0
        if entry in ("?", "H", "HELP"):
            say(HELP)
            say(f"Current state: {board.state}")
            continue
        if entry in STATES:
            try:
                board.set_state(entry)
            except OSError as exc:
                say(f"I2C write failed: {exc}")
            continue
        say(f"Unknown input {entry!r}. {HELP}")


if __name__ == "__main__":
    raise SystemExit(main())
