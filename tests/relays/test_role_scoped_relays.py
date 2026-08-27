"""Role-scoped relay ownership on the shared I2C expander (issue #108).

Both emulator roles can be live on one AcCCS box — re-arm *requires* the SECC
to be listening before the EVCC initiates — and both drive the same GPIO
expander at 0x20. Every write used to be an absolute whole-register write
carrying only the writing role's bits, so either role starting up, changing
state, or returning to idle silently zeroed the other role's relays.

These tests pin the fix: every register write is a read-modify-write confined
to the writing role's mask, the direction register included; a clobber that
slips through the (deliberately unlocked) cross-process race is detected by a
read-back and re-applied once; and `--virtual` touches no bus at all.

The bus is a fake modelling the expander's register file, so the whole suite
runs off the hardware.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from app.shared.EmulatorEnum import PEVState
from app.shared.relays import (
    DIRECTION_REG,
    I2C_ADDR,
    LATCH_REG,
    EVCC_MASK,
    EVSE_CP,
    EVSE_PP,
    OUTPUT_REG,
    PEV_CP1,
    PEV_CP2,
    PEV_PP,
    SECC_MASK,
    EvccRelays,
    SeccRelays,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


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


def _evcc(bus, **kwargs) -> EvccRelays:
    return EvccRelays(virtual=False, bus=bus, **kwargs)


def _secc(bus, **kwargs) -> SeccRelays:
    return SeccRelays(virtual=False, bus=bus, **kwargs)


# -- foreign-bit preservation across every state transition ------------------


@pytest.mark.parametrize(
    "state, own_bits",
    [
        (PEVState.A, 0),
        (PEVState.B, PEV_PP | PEV_CP1),
        (PEVState.C, PEV_PP | PEV_CP1 | PEV_CP2),
    ],
)
def test_evcc_transition_preserves_foreign_bits(state, own_bits):
    bus = FakeBus(output=FOREIGN_TO_EVCC)
    _evcc(bus).set_state(state)

    assert bus.output & EVCC_MASK == own_bits
    assert bus.output & ~EVCC_MASK & 0xFF == FOREIGN_TO_EVCC


@pytest.mark.parametrize(
    "modified_cordset, own_bits",
    [(False, EVSE_CP), (True, EVSE_CP | EVSE_PP)],
)
def test_secc_close_preserves_foreign_bits(modified_cordset, own_bits):
    bus = FakeBus(output=FOREIGN_TO_SECC)
    _secc(bus, modified_cordset=modified_cordset).close_proximity()

    assert bus.output & SECC_MASK == own_bits
    assert bus.output & ~SECC_MASK & 0xFF == FOREIGN_TO_SECC


def test_secc_open_preserves_foreign_bits():
    bus = FakeBus(output=FOREIGN_TO_SECC | EVSE_CP | EVSE_PP)
    _secc(bus).open_proximity()

    assert bus.output & SECC_MASK == 0
    assert bus.output & ~SECC_MASK & 0xFF == FOREIGN_TO_SECC


def test_evcc_full_startup_and_idle_leaves_secc_relays_energised():
    """Acceptance criterion 1, from the SECC's point of view.

    The SECC is mid-session with its relays closed; the EVCC then does its
    whole lifecycle — claim its pins, the startup open/dwell/close toggle, a
    charging state, and the return to idle. The SECC's bits survive all of it.
    """
    bus = FakeBus(output=EVSE_CP | EVSE_PP)
    relays = _evcc(bus)

    relays.initialize()
    relays.toggle_proximity(0)
    relays.set_state(PEVState.C)
    relays.open_proximity()

    assert bus.output & SECC_MASK == EVSE_CP | EVSE_PP
    assert bus.direction & SECC_MASK == 0xFF & SECC_MASK  # never claimed for us


def test_secc_full_startup_and_idle_leaves_evcc_relays_energised():
    """The mirror image: the EVCC is in State C, the SECC cycles around it."""
    bus = FakeBus(output=PEV_PP | PEV_CP1 | PEV_CP2)
    relays = _secc(bus)

    relays.initialize()
    relays.toggle_proximity(0)
    relays.open_proximity()

    assert bus.output & EVCC_MASK == PEV_PP | PEV_CP1 | PEV_CP2


def test_every_output_write_is_a_read_modify_write():
    """No absolute whole-register write survives anywhere in the module."""
    bus = FakeBus(output=FOREIGN_TO_EVCC)
    _evcc(bus).set_state(PEVState.B)

    # Every write to the pin register is preceded by a read of the latch it
    # merges into — never issued cold.
    latch_and_pins = [
        op for op in bus.ops if op[2] in (OUTPUT_REG, LATCH_REG)
    ]
    assert latch_and_pins[0] == ("read", I2C_ADDR, LATCH_REG)
    for previous, current in zip(latch_and_pins, latch_and_pins[1:]):
        if current[0] == "write":
            assert previous == ("read", I2C_ADDR, LATCH_REG)


def test_a_floating_input_pin_is_never_latched_into_a_foreign_bit():
    """A read-modify-write must source the latch, not the pin levels.

    Every pin still reads high here — nothing is driving them yet, which is
    exactly the state the *first* role to start finds the *second* role's pins
    in. Sourcing the merge from the pin register would write those stray highs
    into the latch; the other role's `initialize()` would then flip its pins to
    outputs and immediately close relays nobody commanded.
    """
    bus = FakeBus(direction=0xFF, floating=0xFF)
    evcc = _evcc(bus)
    evcc.initialize()
    evcc.set_state(PEVState.B)

    assert bus.output & ~EVCC_MASK & 0xFF == 0

    # The SECC now starts and claims its pins: they drive open, not closed.
    _secc(bus).initialize()
    assert bus.output & SECC_MASK == 0


# -- masked direction-register writes ----------------------------------------


@pytest.mark.parametrize(
    "factory, mask", [(_evcc, EVCC_MASK), (_secc, SECC_MASK)]
)
def test_initialize_claims_only_owned_pins_as_outputs(factory, mask):
    """Unused pins keep their power-on input default; foreign pins keep theirs.

    A 0 bit in the direction register is an output. Only our mask may be
    cleared — the other role's pins stay as it left them, and the spares stay
    inputs rather than being conscripted by whichever process starts first.
    """
    bus = FakeBus(direction=0xFF)
    factory(bus).initialize()

    assert bus.direction & mask == 0
    assert bus.direction & ~mask & 0xFF == 0xFF & ~mask & 0xFF


def test_initialize_leaves_the_other_roles_direction_bits_alone():
    bus = FakeBus(direction=0xFF)
    _secc(bus).initialize()  # SECC starts first, claims its pins
    _evcc(bus).initialize()  # EVCC joins later

    assert bus.direction & SECC_MASK == 0
    assert bus.direction & EVCC_MASK == 0
    assert bus.direction & 0b11100000 == 0b11100000  # spares still inputs


# -- write-verify and the single re-apply ------------------------------------


class ClobberingBus(FakeBus):
    """A foreign process that zeroes our bits right after each of our writes.

    `times` bounds how many writes get clobbered, so a test can simulate a
    single lost update (self-healing) or a persistent one (logged, given up).
    """

    def __init__(self, *, mask: int, times: int, **kwargs):
        super().__init__(**kwargs)
        self.mask = mask
        self.times = times

    def after_write(self, reg: int) -> None:
        if reg == OUTPUT_REG and self.times > 0:
            self.times -= 1
            self.registers[LATCH_REG] &= ~self.mask & 0xFF


def test_lost_update_is_detected_and_re_applied_once(caplog):
    bus = ClobberingBus(mask=EVCC_MASK, times=1)
    with caplog.at_level(logging.WARNING):
        _evcc(bus).set_state(PEVState.B)

    assert bus.output & EVCC_MASK == PEV_PP | PEV_CP1
    assert len(bus.writes(OUTPUT_REG)) == 2  # first write, then the re-apply
    assert any(
        record.levelno == logging.WARNING for record in caplog.records
    ), "a clobbered write must be logged, not silently lost"


def test_persistent_clobber_gives_up_after_one_re_apply(caplog):
    bus = ClobberingBus(mask=SECC_MASK, times=99)
    with caplog.at_level(logging.WARNING):
        _secc(bus).close_proximity()

    assert len(bus.writes(OUTPUT_REG)) == 2  # exactly one retry, no spin
    assert caplog.records


def test_a_clean_write_needs_no_retry():
    bus = FakeBus(output=FOREIGN_TO_SECC)
    _secc(bus).close_proximity()

    assert len(bus.writes(OUTPUT_REG)) == 1


# -- virtual mode -------------------------------------------------------------


@pytest.mark.parametrize("role", ["evcc", "secc"])
def test_virtual_mode_issues_no_bus_operations(role, caplog):
    """`--virtual` opens no bus and touches none, but still logs identically."""
    relays = (
        EvccRelays(virtual=True) if role == "evcc" else SeccRelays(virtual=True)
    )

    with caplog.at_level(logging.INFO):
        relays.initialize()
        relays.close_proximity()
        relays.open_proximity()

    assert relays.bus is None
    assert caplog.records, "virtual mode must keep the relay log lines"


def test_virtual_evcc_logs_the_unchanged_state_lines(caplog):
    with caplog.at_level(logging.INFO):
        relays = EvccRelays(virtual=True)
        relays.set_state(PEVState.A)
        relays.set_state(PEVState.B)
        relays.set_state(PEVState.C)

    assert [record.getMessage() for record in caplog.records] == [
        "Going to state A",
        "Going to state B",
        "Going to state C",
    ]


@pytest.mark.parametrize(
    "modified_cordset, expected",
    [
        (False, "Closing CP relay connection"),
        (True, "Closing CP/PP relay connections"),
    ],
)
def test_virtual_secc_logs_the_unchanged_relay_lines(
    modified_cordset, expected, caplog
):
    with caplog.at_level(logging.INFO):
        relays = SeccRelays(virtual=True, modified_cordset=modified_cordset)
        relays.close_proximity()
        relays.open_proximity()

    assert [record.getMessage() for record in caplog.records] == [
        expected,
        "Opening CP/PP relay connections",
    ]


# -- the masks themselves -----------------------------------------------------


def test_the_two_role_masks_are_disjoint():
    """The premise the whole ownership model rests on."""
    assert EVCC_MASK & SECC_MASK == 0
    assert EVCC_MASK == PEV_CP1 | PEV_CP2 | PEV_PP
    assert SECC_MASK == EVSE_CP | EVSE_PP


# -- the controllers keep no wiring of their own ------------------------------


class RecordingRelays:
    """Stands in for the shared bank; records the semantic calls made on it."""

    def __init__(self):
        self.calls: list = []

    def initialize(self):
        self.calls.append(("initialize",))

    def set_state(self, state):
        self.calls.append(("set_state", state))

    def close_proximity(self):
        self.calls.append(("close_proximity",))

    def open_proximity(self):
        self.calls.append(("open_proximity",))

    def toggle_proximity(self, t=5):
        self.calls.append(("toggle_proximity", t))


def test_evcc_controller_delegates_every_relay_call():
    from app.evcc.controller.pev import PEV

    pev = PEV.__new__(PEV)
    pev.relays = RecordingRelays()

    pev.closeProximity()
    pev.openProximity()
    pev.setState(PEVState.C)
    pev.toggleProximity(0)

    assert pev.relays.calls == [
        ("set_state", PEVState.B),
        ("set_state", PEVState.A),
        ("set_state", PEVState.C),
        ("toggle_proximity", 0),
    ]


def test_secc_controller_delegates_every_relay_call():
    from app.secc.controller.evse import EVSE

    evse = EVSE.__new__(EVSE)
    evse.relays = RecordingRelays()

    evse.closeProximity()
    evse.openProximity()
    evse.toggleProximity(0)

    assert evse.relays.calls == [
        ("close_proximity",),
        ("open_proximity",),
        ("toggle_proximity", 0),
    ]


@pytest.mark.parametrize(
    "path",
    [
        "app/evcc/controller/pev.py",
        "app/secc/controller/evse.py",
        "scripts/evcc_relays.py",
    ],
)
def test_no_module_outside_the_shared_one_spells_out_the_wiring(path):
    """The duplication is what let the clobbering bug exist (issue #108).

    Per-role copies of the bus handle, address, register numbers, and bit masks
    are what made three absolute whole-register writers possible, so the names
    may appear only in `app/shared/relays.py`.
    """
    source = (REPO_ROOT / path).read_text()

    for forbidden in (
        "SMBus(",
        "write_byte_data",
        "CONTROL_REG",
        "ALL_OFF",
        "PEV_CP1",
        "EVSE_CP",
        "0x20",
    ):
        assert forbidden not in source, f"{path} still spells out {forbidden}"
