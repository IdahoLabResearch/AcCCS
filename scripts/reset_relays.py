#!/usr/bin/env python3
"""Turn every relay on the shared expander off - orphan-relay recovery.

When an emulator is hard-killed (a `kill -9`, a yanked terminal, a panic) it
never runs its own relay teardown, so its relays stay latched closed. Because
each role now clears only the pins it owns (issue #108, ADR-0007), nothing
started afterwards clears the orphaned bits: a hard-killed EV-side emulator
leaves the EVSE side seeing a phantom vehicle plugged in indefinitely, until
someone starts an EV-side emulator again or power-cycles the board. This tool
is the deliberate way out - it drives *every* relay off in one whole-register
write, regardless of which role set the bits.

That whole-register write (`app.shared.relays.reset_all_relays`) is the ONE
sanctioned exception to the ownership rule the shared module otherwise
enforces: everything else touches only a single role's mask, precisely so the
two roles can run side by side without clobbering each other. This tool
ignores the masks on purpose, because recovering bits an owner is no longer
around to clear is exactly the case masking cannot handle.

    WARNING: do not run this while an emulator is live. It will clear that
    running session's relays out from under it - the same broad write that
    recovers an orphaned board will disrupt a healthy one. Use it only when no
    emulator is running.

It leaves the pin-direction configuration alone: turning relays off is not the
same as reconfiguring the expander.

Needs the real hardware: an SMBus-capable host (the Pi) with the relay board
on I2C bus 1, run as a user with access to /dev/i2c-1. Anywhere else - no
smbus, no bus, or no permission on it - it exits with a one-line explanation
rather than a traceback.

Usage:

    python scripts/reset_relays.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Run straight out of the repo (`python scripts/reset_relays.py`): only the
# script's own directory lands on sys.path, so put the repo root there too and
# the shared relay module imports the same way it does for the emulator.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from app.shared.relays import (  # noqa: E402
    I2C_ADDR,
    I2C_BUS,
    open_bus,
    reset_all_relays,
)

WARNING = (
    "WARNING: do not run this while an emulator is live - it clears that "
    "running session's relays too. Use it only when no emulator is running."
)


def main() -> int:
    argparse.ArgumentParser(
        description=(
            "Turn every relay on the shared I2C expander off in one deliberate "
            "whole-register write, regardless of which role set the bits. "
            "Recovers a board whose relays a hard-killed emulator left latched. "
            + WARNING
        )
    ).parse_args()

    # The exact import the shared bus handle performs, so this check fails in
    # every case its own would: no smbus at all, and an smbus without the
    # SMBus its handle comes from. An ImportError is not an OSError, so one
    # escaping the open below would land as a traceback.
    try:
        from smbus import SMBus  # noqa: F401 - presence check only
    except ImportError:
        sys.exit(
            "smbus is not available - this tool only runs on the hardware "
            "host (the Pi)."
        )

    # Opening the bus is the first thing that can fail on an otherwise healthy
    # host - no expander wired up, or /dev/i2c-1 there but not readable by this
    # user. Both are ordinary bench conditions, so they get a message, not a
    # traceback.
    try:
        bus = open_bus()
    except OSError as exc:
        sys.exit(
            f"Cannot reach the relay board at {I2C_ADDR:#04x} on I2C bus "
            f"{I2C_BUS}: {exc}. Check the board is wired up and that this user "
            f"can read /dev/i2c-{I2C_BUS}."
        )

    # The reads inside reset_all_relays can also hit a permission wall (the
    # realistic Pi failure: /dev/i2c-1 exists, the user is not in `i2c`).
    # Close the handle on the way out either way.
    try:
        driven = reset_all_relays(bus)
    except OSError as exc:
        _close(bus)
        sys.exit(
            f"Cannot drive the relay board at {I2C_ADDR:#04x} on I2C bus "
            f"{I2C_BUS}: {exc}. Check that this user can read /dev/i2c-"
            f"{I2C_BUS}."
        )
    _close(bus)

    where = f"at {I2C_ADDR:#04x} on I2C bus {I2C_BUS}"
    if driven:
        print(
            f"Reset: cleared relays {where} (was driving {driven:#010b}); "
            f"every relay is now off."
        )
    else:
        print(f"No-op: no relay {where} was on.")
    return 0


def _close(bus) -> None:
    """Drop the bus handle, tolerating one that has already gone away."""
    try:
        bus.close()
    except OSError:
        pass


if __name__ == "__main__":
    raise SystemExit(main())
