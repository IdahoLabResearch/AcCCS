"""The standalone relay-reset recovery tool (issue #110).

`reset_all_relays` and the `scripts/reset_relays.py` wrapper are the one
sanctioned exception to the ownership rule the rest of `app.shared.relays`
enforces (issue #108, ADR-0007): they clear *every* relay in a single
whole-register write, no matter which role — or which now-dead process — set
the bits. That is what recovers a board an orphaned emulator left latched, so
its behaviour is a contract in its own right:

- one deliberate all-bits write, clearing foreign bits a role write would keep;
- the direction register left alone (a reset is not a reconfigure);
- a report an operator can read as reset-vs-no-op;
- off the hardware, a message and never a traceback — no smbus, no bus, or no
  access to it.

The script is loaded by path with a fake `smbus` module in `sys.modules`, so
these run off the hardware and never touch a real bus.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from app.shared.relays import (
    DIRECTION_REG,
    I2C_ADDR,
    LATCH_REG,
    OUTPUT_REG,
    reset_all_relays,
)
from tests.relays.fakes import (
    FOREIGN_TO_EVCC,
    FakeBus,
    fake_smbus,
    load_bench_script,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "reset_relays.py"


# -- the shared write: one all-bits reset, no direction change ---------------


def test_reset_clears_every_bit_including_foreign_ones():
    """A whole-register write, not a role-masked one: even bits no role here
    owns (a spare, or the other role's) go off."""
    bus = FakeBus(direction=0x00, output=0xFF)  # every pin an output, all high

    driven = reset_all_relays(bus)

    assert driven == 0xFF
    assert bus.output == 0x00


def test_reset_is_a_single_write_of_the_output_register():
    bus = FakeBus(output=FOREIGN_TO_EVCC)

    reset_all_relays(bus)

    writes = [op for op in bus.ops if op[0] == "write"]
    assert writes == [("write", I2C_ADDR, OUTPUT_REG, 0x00)]


def test_reset_leaves_the_direction_register_alone():
    bus = FakeBus(direction=0xA5, output=0xFF)

    reset_all_relays(bus)

    assert bus.direction == 0xA5
    assert all(op[2] != DIRECTION_REG for op in bus.ops if op[0] == "write")


def test_reset_reports_the_driven_bits_so_a_no_op_is_distinguishable():
    already_off = FakeBus(direction=0x00, output=0x00)
    assert reset_all_relays(already_off) == 0x00

    some_on = FakeBus(direction=0x00, output=FOREIGN_TO_EVCC)
    assert reset_all_relays(some_on) == FOREIGN_TO_EVCC


def test_a_bit_latched_on_an_input_pin_is_not_reported_as_a_driven_relay():
    """The reset/no-op distinction is by *relay*, not by latch bit: a bit
    latched high on a pin still configured as an input drives nothing, so it is
    a no-op even though the latch is not clear."""
    bus = FakeBus(direction=0xFF, output=0xFF)  # all inputs, latch all high

    driven = reset_all_relays(bus)

    assert driven == 0x00  # nothing was actually driving a relay
    assert bus.output == 0x00  # the write still landed


def test_reset_reads_the_latch_not_the_pin_register():
    """The prior value comes off the latch (0x0A), the register that only ever
    holds what was written — not the pin levels at 0x09."""
    bus = FakeBus(output=0xFF)

    reset_all_relays(bus)

    assert ("read", I2C_ADDR, LATCH_REG) in bus.ops
    assert ("read", I2C_ADDR, OUTPUT_REG) not in bus.ops


# -- the script -------------------------------------------------------------


def _load(monkeypatch, smbus_module):
    """Import `scripts/reset_relays.py` by path with `smbus` stubbed out."""
    return load_bench_script(monkeypatch, SCRIPT, "reset_relays_tool", smbus_module)


@pytest.fixture(autouse=True)
def _no_argv(monkeypatch):
    """`main()` parses argv; keep pytest's own flags out of it."""
    monkeypatch.setattr(sys, "argv", ["reset_relays.py"])


def test_the_tool_turns_every_relay_off_through_the_bus(monkeypatch, capsys):
    bus = FakeBus(direction=0x00, output=0xFF)  # every pin an output, all high
    module = _load(monkeypatch, fake_smbus(lambda _n: bus))

    assert module.main() == 0

    assert bus.output == 0x00
    assert bus.closed
    out = capsys.readouterr().out.lower()
    assert "reset" in out


def test_the_tool_reports_a_reset_distinctly_from_a_no_op(monkeypatch, capsys):
    live = FakeBus(direction=0x00, output=FOREIGN_TO_EVCC)
    module = _load(monkeypatch, fake_smbus(lambda _n: live))
    module.main()
    reset_out = capsys.readouterr().out

    idle = FakeBus(output=0x00)
    module = _load(monkeypatch, fake_smbus(lambda _n: idle))
    module.main()
    noop_out = capsys.readouterr().out

    assert reset_out != noop_out
    assert "no-op" in noop_out.lower()
    assert "reset" in reset_out.lower()


def test_the_tool_does_not_touch_the_direction_register(monkeypatch):
    bus = FakeBus(direction=0x3C, output=0xFF)
    module = _load(monkeypatch, fake_smbus(lambda _n: bus))

    module.main()

    assert bus.direction == 0x3C


def test_a_host_without_smbus_exits_with_a_message(monkeypatch):
    module = _load(monkeypatch, None)

    with pytest.raises(SystemExit) as raised:
        module.main()

    assert isinstance(raised.value.code, str), "raised a traceback, not a message"
    assert "smbus" in raised.value.code


def test_a_useless_smbus_exits_with_a_message(monkeypatch):
    """A module named smbus with no SMBus still fails the presence check."""
    module = _load(monkeypatch, types.ModuleType("smbus"))

    with pytest.raises(SystemExit) as raised:
        module.main()

    assert isinstance(raised.value.code, str), "raised a traceback, not a message"
    assert "smbus" in raised.value.code


def test_a_host_without_the_relay_board_exits_with_a_message(monkeypatch):
    def no_such_bus(_n):
        raise FileNotFoundError(2, "No such file or directory")

    module = _load(monkeypatch, fake_smbus(no_such_bus))

    with pytest.raises(SystemExit) as raised:
        module.main()

    assert isinstance(raised.value.code, str), "raised a traceback, not a message"
    assert "i2c" in raised.value.code.lower()


def test_an_unreadable_relay_board_exits_with_a_message(monkeypatch):
    """/dev/i2c-1 exists, the user is not in `i2c`: the read raises."""

    class Unreadable(FakeBus):
        def read_byte_data(self, addr, reg):
            raise PermissionError(13, "Permission denied")

    bus = Unreadable(output=0xFF)
    module = _load(monkeypatch, fake_smbus(lambda _n: bus))

    with pytest.raises(SystemExit) as raised:
        module.main()

    assert isinstance(raised.value.code, str), "raised a traceback, not a message"
    assert "i2c" in raised.value.code.lower()
    assert bus.closed, "the bus handle was left open on the failure path"


def test_help_text_warns_against_running_while_live(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["reset_relays.py", "--help"])
    module = _load(monkeypatch, fake_smbus(lambda _n: FakeBus()))

    with pytest.raises(SystemExit) as raised:
        module.main()

    assert raised.value.code == 0
    out = capsys.readouterr().out.lower()
    assert "live" in out or "running" in out
