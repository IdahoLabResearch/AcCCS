"""An in-memory stand-in for the shared I2C expander (issue #108).

Lives beside the tests rather than inside one of them because both the
role-scoped relay suite and the bench-script suite drive the same chip, and a
second hand-written copy of its register semantics is the very duplication
issue #108 set out to remove.
"""

from __future__ import annotations

from app.shared.relays import (
    DIRECTION_REG,
    EVCC_MASK,
    LATCH_REG,
    OUTPUT_REG,
    SECC_MASK,
)


class FakeBus:
    """In-memory stand-in for `smbus.SMBus` over the expander's registers.

    Models the part of the chip the distinction rests on: a write to the pin
    register lands in the output *latch*, a read of the latch returns what was
    written, and a read of the pin register returns pin *levels* — the latch on
    the pins we drive, and whatever the wire sits at (`floating`) on the pins
    still configured as inputs.

    Powers on the way the chip does: every pin an input (direction 0xFF) and
    the latch clear. `ops` records every bus operation in order so a test can
    assert on *how* a register was reached, not just where it landed.
    """

    def __init__(
        self, *, direction: int = 0xFF, output: int = 0x00, floating: int = 0x00
    ):
        self.registers = {DIRECTION_REG: direction, LATCH_REG: output}
        self.floating = floating
        self.ops: list[tuple] = []
        self.closed = False

    def read_byte_data(self, addr: int, reg: int) -> int:
        self.ops.append(("read", addr, reg))
        if reg == OUTPUT_REG:
            direction = self.registers[DIRECTION_REG]
            latch = self.registers[LATCH_REG]
            return (latch & ~direction & 0xFF) | (self.floating & direction)
        return self.registers[reg]

    def write_byte_data(self, addr: int, reg: int, value: int) -> None:
        self.ops.append(("write", addr, reg, value))
        # Writing either the pin register or the latch sets the latch.
        self.registers[LATCH_REG if reg == OUTPUT_REG else reg] = value
        self.after_write(reg)

    def after_write(self, reg: int) -> None:
        """Hook for tests simulating a foreign process writing between ops."""

    def close(self) -> None:
        self.closed = True
        self.ops.append(("close",))

    # -- convenience ---------------------------------------------------------

    @property
    def output(self) -> int:
        """The output latch — what each pin drives once it is an output."""
        return self.registers[LATCH_REG]

    @property
    def direction(self) -> int:
        return self.registers[DIRECTION_REG]

    def writes(self, reg: int) -> list[int]:
        return [op[3] for op in self.ops if op[0] == "write" and op[2] == reg]


# The foreign bits each role must never disturb: with a role's own mask
# excluded, everything else on the register belongs to somebody else.
FOREIGN_TO_EVCC = SECC_MASK | 0b11100000  # SECC relays + the unused spare pins
FOREIGN_TO_SECC = EVCC_MASK | 0b11100000
