#!/usr/bin/env python3
"""Interactive control of the EVCC control-pilot relays, no emulator attached.

Bench helper for exercising the I2C relay board and the CP/PP wiring in
isolation: it writes the same register values `PEV.setState()` writes
(`app/evcc/controller/pev.py`) but without loading a personality, running
SLAC, or opening a session. Type a state, watch the EVSE react.

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

# I2C relay board wiring, mirrored from PEV.__init__ so this script stays
# usable when the emulator itself won't start. Keep the two in sync.
I2C_BUS = 1
I2C_ADDR = 0x20
CONTROL_REG = 0x9
PEV_CP1 = 0b10
PEV_CP2 = 0b100
PEV_PP = 0b10000
ALL_OFF = 0b0

STATE_MASKS = {
    "A": ALL_OFF,
    "B": PEV_PP | PEV_CP1,
    "C": PEV_PP | PEV_CP1 | PEV_CP2,
}

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
    """The I2C relay board, with a guaranteed open-on-exit."""

    def __init__(self):
        try:
            from smbus import SMBus
        except ImportError:
            sys.exit(
                "smbus is not available - this script only runs on the "
                "hardware host (the Pi)."
            )

        self.bus = SMBus(I2C_BUS)
        # Same initialisation PEV.start() performs before its first write.
        self.bus.write_byte_data(I2C_ADDR, 0x00, 0x00)
        self.state = None
        self._closed = False

    def set_state(self, state: str) -> None:
        mask = STATE_MASKS[state]
        self.bus.write_byte_data(I2C_ADDR, CONTROL_REG, mask)
        self.state = state
        say(f"Going to state {state} (control reg = {mask:#07b})")

    def open_all(self) -> None:
        """Open every relay and close the bus. Safe to call more than once."""
        if self._closed:
            return
        self._closed = True
        try:
            self.bus.write_byte_data(I2C_ADDR, CONTROL_REG, ALL_OFF)
            self.state = "A"
            say("All relays open (state A).")
        except OSError as exc:
            say(f"Failed to open relays: {exc}")
        finally:
            try:
                self.bus.close()
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

    say(f"EVCC relay control on I2C bus {I2C_BUS}, address {I2C_ADDR:#04x}.")
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
        if entry in STATE_MASKS:
            try:
                board.set_state(entry)
            except OSError as exc:
                say(f"I2C write failed: {exc}")
            continue
        say(f"Unknown input {entry!r}. {HELP}")


if __name__ == "__main__":
    raise SystemExit(main())
