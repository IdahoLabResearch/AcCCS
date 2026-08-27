"""Role-scoped ownership of the shared I2C GPIO expander (ADR-0007, issue #108).

See `docs/adr/0007-role-scoped-relay-ownership.md` for the options weighed and
the decision recorded; this module is that decision in code.

Both emulator roles can be live on one AcCCS box at the same time — re-arm
*requires* the SECC to be listening before the EVCC initiates — and both drive
the same GPIO expander at `I2C_ADDR`. The two roles own a disjoint set of its
pins:

    bit 0  EVSE CP      bit 1  PEV CP1     bit 5..7  unused spares
    bit 3  EVSE PP      bit 2  PEV CP2
                        bit 4  PEV PP

Ownership model
---------------
**One role owns a fixed bit mask — its [[relay bank]] — and touches nothing
else.** Every write is a read-modify-write confined to that mask: the role
reads the latch, changes only its own bits, and writes the byte back, so the
other role's relays survive any startup, state change, or return to idle. The
direction register is masked
the same way — a role claims only its own pins as outputs, leaving the other
role's direction bits as it found them and the unused spares at their power-on
input default, so wiring a spare as an input later cannot meet a process that
has conscripted it as an output.

Before this module the wiring lived in per-role copies (`PEV.__init__`,
`EVSE.__init__`, `scripts/evcc_relays.py`), each writing the whole register with
only its own bits set. That duplication is what let the bug exist, so the bus
handle, the address, the register numbers, and the masks live here and nowhere
else.

The lost-update race
--------------------
Two processes share one register with no arbitration, so role A can read
between role B's read and write; B's change is then lost. That race is
**knowingly accepted rather than locked against** — a cross-process lock (a
file lock, say) would have to be held across a bus round-trip on every
electrical transition, and a stale lock left by a killed emulator would wedge
the other role's relays, which is a worse failure than the one it prevents.

The mitigation is write-verify: after each output write the role reads the
latch back and, if its own bits did not stick, logs a warning naming the
collision and re-applies **once**. That turns a silent loss into a logged,
usually self-healing event. "Usually" is exact: the read-back catches a foreign
write that lands *before* it, which is the wide half of the window, and misses
one that lands after — that one survives until the next transition re-asserts
our bits. It is deliberately one retry and not a loop: a disagreement that
outlives the re-apply means something else is fighting for the pins, and
spinning on the bus would only make that harder to see.

Under `--virtual` no bus is opened and no bus operation is attempted; the
relay log lines are still emitted so the virtual demo's log stream is
identical to the hardware one.

The one sanctioned exception
----------------------------
`reset_all_relays` is the single write in the codebase that ignores the
ownership rule and drives the whole register off at once, to recover a board
whose relays a hard-killed process left latched. It is deliberately the only
such write, and `scripts/reset_relays.py` is the operator tool that invokes
it; both say plainly that running it against a live emulator will clear that
session's relays.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from app.shared.EmulatorEnum import PEVState

logger = logging.getLogger(__name__)

# The expander, as wired on the AcCCS box: I2C bus 1, address 0x20
# (docs/CurrentImplementation.md). Its register file is the MCP23008 one the
# emulator has always driven — direction at 0x00 (a 0 bit per output pin),
# the pin register at 0x09 that a write drives the outputs through.
#
# Reads come off the *latch* at 0x0A, not off 0x09. A read of 0x09 returns pin
# levels, which for a pin still configured as an input is whatever the wire
# happens to sit at; a read-modify-write sourced from there would latch that
# stray level into the bits we do not own, and the moment the other role
# claimed one of those pins as an output it would drive a relay nobody
# commanded. The latch only ever holds what was written, and powers up clear.
I2C_BUS = 1
I2C_ADDR = 0x20
DIRECTION_REG = 0x00
OUTPUT_REG = 0x09
LATCH_REG = 0x0A

# The SECC's pins: the control-pilot relay, plus the proximity-pilot relay that
# only a modified cordset closes.
EVSE_CP = 0b00000001
EVSE_PP = 0b00001000
SECC_MASK = EVSE_CP | EVSE_PP

# The EVCC's pins: two control-pilot relays (CP1 alone is State B, CP1+CP2 is
# State C) plus proximity pilot.
PEV_CP1 = 0b00000010
PEV_CP2 = 0b00000100
PEV_PP = 0b00010000
EVCC_MASK = PEV_CP1 | PEV_CP2 | PEV_PP

_BYTE = 0xFF


def open_bus():
    """Open the shared expander's I2C bus.

    The single place `SMBus(I2C_BUS)` is called: `RelayBank` opens its handle
    through here, and the standalone reset tool (`scripts/reset_relays.py`)
    borrows it to reach the bus without taking on a role. Keeping the one bus
    constructor here is what lets the module docstring's claim — the bus handle,
    the address, and the register numbers live here and nowhere else — stay
    true even for a tool that owns no `RelayBank`.

    The `smbus` import is deferred to the call so importing this module off the
    hardware host (where the dependency is absent) does not fail.
    """
    from smbus import SMBus

    return SMBus(I2C_BUS)


def reset_all_relays(bus) -> int:
    """Turn every relay off in one deliberate whole-register write.

    THE ONE SANCTIONED EXCEPTION to the ownership rule the rest of this module
    enforces. Every other write is masked to a single role's [[relay bank]]
    (see the module docstring); this one drives all eight output bits to zero,
    so it clears relays no matter which role — or which now-dead process that
    left them latched — set them. That is exactly what recovers a board
    orphaned by a hard-killed emulator, and exactly why running it against a
    *live* emulator clears that session's relays out from under it. Nothing
    else in the codebase may write outside a role's mask: the per-role writes
    are deliberately narrow, so the recovery that undoes them has to be
    deliberately wide, and lives in exactly one named place.

    Returns the bits that were actually driving relays — the prior latch
    masked to the pins currently configured as outputs — so the caller can
    tell a real reset (some relay was on) from a no-op (nothing was). A bit
    latched high on a pin still configured as an *input* drives no relay, so it
    is not counted; that is why the direction register is read. It is only
    read, never written — turning relays off is not the same as reconfiguring
    the expander.
    """
    latch = bus.read_byte_data(I2C_ADDR, LATCH_REG)
    direction = bus.read_byte_data(I2C_ADDR, DIRECTION_REG)
    driven = latch & ~direction & _BYTE
    bus.write_byte_data(I2C_ADDR, OUTPUT_REG, 0x00)
    return driven


class RelayBank:
    """The bits of the shared expander that one role owns.

    Holds the only bus handle in the project. `mask` is the role's pins; every
    operation is masked to it, and `write` verifies the result and re-applies
    once on a collision (see the module docstring for why exactly once).
    """

    def __init__(self, *, mask: int, virtual: bool, bus=None, name: str = "relay"):
        self.mask = mask & _BYTE
        self.virtual = virtual
        self.name = name
        # Under --virtual the smbus import itself never happens: the dependency
        # is absent off the hardware host, and a virtual run must attempt no
        # bus operation at all.
        if virtual:
            self.bus = None
        elif bus is not None:
            self.bus = bus
        else:
            self.bus = open_bus()

    def configure(self) -> None:
        """Claim this role's pins as outputs, leaving every other pin alone."""
        if self.virtual:
            return
        direction = self.bus.read_byte_data(I2C_ADDR, DIRECTION_REG)
        self.bus.write_byte_data(
            I2C_ADDR, DIRECTION_REG, direction & ~self.mask & _BYTE
        )

    def write(self, bits: int) -> None:
        """Drive this role's bits to `bits`, preserving every foreign bit.

        Reads the latch back afterwards; a collision (another process's write
        landing between our read and our write) is logged and re-applied once.
        """
        if self.virtual:
            return
        bits &= self.mask
        self._apply(bits)
        latched = self.bus.read_byte_data(I2C_ADDR, LATCH_REG)
        if latched & self.mask != bits:
            logger.warning(
                f"{self.name}: expander collision on {I2C_ADDR:#04x} — "
                f"wrote {bits:#010b}, read back {latched & self.mask:#010b} "
                f"within our mask {self.mask:#010b}; another process wrote "
                f"between our read and write. Re-applying once."
            )
            self._apply(bits)

    def _apply(self, bits: int) -> None:
        """One read-modify-write, masked to our pins: read the latch, drive
        the pins. Reading the latch (not the pin register) is what keeps a
        floating input's level out of the bits we do not own."""
        current = self.bus.read_byte_data(I2C_ADDR, LATCH_REG)
        self.bus.write_byte_data(
            I2C_ADDR, OUTPUT_REG, (current & ~self.mask & _BYTE) | bits
        )

    def close(self) -> None:
        """Release the bus handle. Safe to call when there is none."""
        if self.bus is not None:
            self.bus.close()
            self.bus = None


class _RoleRelays:
    """Shared shape for the two role facades: a bank plus semantic states."""

    MASK: int = 0

    def __init__(self, *, virtual: bool, bus=None):
        self._bank = RelayBank(
            mask=self.MASK, virtual=virtual, bus=bus, name=type(self).__name__
        )

    @property
    def bus(self):
        """The bus handle, or None under `--virtual`. For tests and teardown."""
        return self._bank.bus

    def initialize(self) -> None:
        """Claim this role's pins as outputs before the first state write."""
        self._bank.configure()

    def close(self) -> None:
        self._bank.close()

    def close_proximity(self) -> None:  # pragma: no cover - role override
        raise NotImplementedError

    def open_proximity(self) -> None:  # pragma: no cover - role override
        raise NotImplementedError

    def toggle_proximity(self, t: float = 5) -> None:
        """Open this role's relays, dwell `t` seconds, then close them again.

        The startup unplug→replug edge real hardware needs. Only this role's
        bits move: the dwell used to be a multi-second window in which the
        other role's relays sat cleared (issue #108).
        """
        self.open_proximity()
        time.sleep(t)
        self.close_proximity()


class EvccRelays(_RoleRelays):
    """The EV side's control-pilot and proximity relays."""

    MASK = EVCC_MASK

    STATE_BITS = {
        PEVState.A: 0,
        PEVState.B: PEV_PP | PEV_CP1,
        PEVState.C: PEV_PP | PEV_CP1 | PEV_CP2,
    }

    def set_state(self, state: PEVState) -> None:
        logger.info(f"Going to state {state.name}")
        self._bank.write(self.STATE_BITS[state])

    def close_proximity(self) -> None:
        self.set_state(PEVState.B)

    def open_proximity(self) -> None:
        self.set_state(PEVState.A)


class SeccRelays(_RoleRelays):
    """The EVSE side's control-pilot relay (plus PP on a modified cordset)."""

    MASK = SECC_MASK

    def __init__(self, *, virtual: bool, modified_cordset: bool = False, **kwargs):
        super().__init__(virtual=virtual, **kwargs)
        self.modified_cordset = modified_cordset

    def close_proximity(self) -> None:
        if self.modified_cordset:
            logger.info("Closing CP/PP relay connections")
            self._bank.write(EVSE_PP | EVSE_CP)
        else:
            logger.info("Closing CP relay connection")
            self._bank.write(EVSE_CP)

    def open_proximity(self) -> None:
        logger.info("Opening CP/PP relay connections")
        self._bank.write(0)
