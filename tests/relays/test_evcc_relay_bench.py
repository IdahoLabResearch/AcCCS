"""The EVCC relay bench helper, driven through the shared module (issue #109).

`scripts/evcc_relays.py` exists precisely for the times the emulator will not
start, so its behaviour is a contract in its own right and not a footnote to
the emulator's: whatever it does to the expander it must do through
`app.shared.relays`, touching only the EV side's pins, and it must open those
pins again on *every* way out of the process — a clean quit, EOF, Ctrl-C, and
the signals that would otherwise bypass `atexit`.

Every expected bit pattern is read back out of `EvccRelays` rather than spelled
out here: a suite policing a duplicated copy of the wiring must not keep one.

The script is loaded by path with a fake `smbus` module in `sys.modules`, so
these run off the hardware and never touch a real bus.
"""

from __future__ import annotations

import builtins
import importlib.util
import signal
import sys
import types
from pathlib import Path

import pytest

from app.shared.relays import EVCC_MASK, EvccRelays
from tests.relays.fakes import FOREIGN_TO_EVCC, FakeBus

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "evcc_relays.py"


def _fake_smbus(open_bus):
    """A stand-in `smbus` module whose `SMBus(bus)` calls `open_bus`."""
    module = types.ModuleType("smbus")
    module.SMBus = open_bus
    return module


def _load_bench(monkeypatch, smbus_module):
    """Import `scripts/evcc_relays.py` by path with `smbus` stubbed out.

    Loaded under its own module name so the import does not run `main()` and
    does not collide with anything already imported.
    """
    if smbus_module is None:
        # A None entry in sys.modules is what makes `import smbus` raise
        # ImportError on a host that has never had it installed.
        monkeypatch.setitem(sys.modules, "smbus", None)
    else:
        monkeypatch.setitem(sys.modules, "smbus", smbus_module)

    spec = importlib.util.spec_from_file_location("evcc_relays_bench", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Bench:
    """The loaded script together with the fake expander it is driving.

    The script has no bus of its own to reach for — the handle lives inside
    `EvccRelays` — so the pairing is the test's, not the script's.
    """

    def __init__(self, module, bus: FakeBus):
        self.module = module
        self.bus = bus

    def bits(self, state: str) -> int:
        """The EV bits this state means, straight from the shared module."""
        return EvccRelays.STATE_BITS[self.module.STATES[state]]

    def assert_ev_bits(self, bits: int) -> None:
        """Our pins carry `bits`; every foreign pin is exactly as it was."""
        assert self.bus.output & EVCC_MASK == bits
        assert self.bus.output & ~EVCC_MASK & 0xFF == FOREIGN_TO_EVCC


@pytest.fixture
def bench(monkeypatch):
    """The script, wired to a fake expander that starts with the SECC live.

    The latch powers up carrying every bit the EVCC does *not* own, so any
    write of ours that fails to preserve one shows up immediately.
    """
    bus = FakeBus(output=FOREIGN_TO_EVCC)
    module = _load_bench(monkeypatch, _fake_smbus(lambda _bus_number: bus))
    return Bench(module, bus)


def _drive(bench, monkeypatch, entries):
    """Run `main()` against a scripted stdin, capturing the exit hooks.

    `atexit.register` and `signal.signal` are captured rather than performed:
    a test must not leave a relay-opening hook armed in the pytest process.
    Each entry is either a line of input or an exception class to raise from
    `input()`.
    """
    module = bench.module
    hooks: list = []
    handlers: dict = {}
    monkeypatch.setattr(module.atexit, "register", hooks.append)
    monkeypatch.setattr(
        module.signal, "signal", lambda sig, handler: handlers.setdefault(sig, handler)
    )

    remaining = list(entries)

    def fake_input(_prompt):
        if not remaining:
            raise EOFError
        entry = remaining.pop(0)
        if isinstance(entry, type) and issubclass(entry, BaseException):
            raise entry
        return entry

    monkeypatch.setattr(builtins, "input", fake_input)
    return module.main(), hooks, handlers


# -- the shared module does the driving --------------------------------------


@pytest.mark.parametrize("state", ["A", "B", "C"])
def test_setting_a_state_leaves_the_seccs_bits_untouched(bench, state):
    """Criterion: safe to use alongside a running SECC emulator."""
    board = bench.module.RelayBoard()

    board.set_state(state)

    bench.assert_ev_bits(bench.bits(state))


def test_construction_claims_only_the_evcc_pins_as_outputs(bench):
    bench.module.RelayBoard()

    # Direction is 0 per output pin: ours are claimed, everything else keeps
    # its power-on input default.
    assert bench.bus.direction == 0xFF & ~EVCC_MASK


def test_the_bench_never_writes_the_register_absolutely(bench):
    """Every write is a read-modify-write, the same as the emulator's."""
    board = bench.module.RelayBoard()
    board.set_state("C")

    for index, op in enumerate(bench.bus.ops):
        if op[0] != "write":
            continue
        assert index and bench.bus.ops[index - 1][0] == "read", (
            f"write {op} was not preceded by a read of the register"
        )


# -- open-on-exit, on every way out ------------------------------------------


def test_open_all_clears_only_the_evcc_bits(bench):
    board = bench.module.RelayBoard()
    board.set_state("C")

    board.open_all()

    bench.assert_ev_bits(0)
    assert bench.bus.closed


def test_open_all_is_idempotent(bench):
    """atexit and a signal handler can both reach it; the bus closes once."""
    board = bench.module.RelayBoard()
    board.set_state("C")

    board.open_all()
    board.open_all()

    assert [op for op in bench.bus.ops if op[0] == "close"] == [("close",)]


@pytest.mark.parametrize(
    "entries, code",
    [
        (["c", "q"], 0),
        (["c", "quit"], 0),
        (["c", EOFError], 0),
        (["c", KeyboardInterrupt], 130),
    ],
)
def test_every_interactive_exit_opens_the_relays(bench, monkeypatch, entries, code):
    """A clean quit, EOF (Ctrl-D) and Ctrl-C all reach the atexit hook."""
    exit_code, hooks, _ = _drive(bench, monkeypatch, entries)

    assert exit_code == code
    bench.assert_ev_bits(bench.bits("C"))  # left as the operator set it

    assert hooks, "no exit hook was registered"
    for hook in hooks:
        hook()

    bench.assert_ev_bits(0)


@pytest.mark.parametrize("sig", [signal.SIGHUP, signal.SIGTERM, signal.SIGQUIT])
def test_every_handled_signal_opens_the_relays(bench, monkeypatch, sig):
    """The signals that would otherwise bypass `atexit` unwind through it."""
    _, hooks, handlers = _drive(bench, monkeypatch, ["c", "q"])

    assert sig in handlers, f"no handler installed for {sig}"
    with pytest.raises(SystemExit) as raised:
        handlers[sig](sig, None)
    assert raised.value.code == 128 + sig

    for hook in hooks:
        hook()

    bench.assert_ev_bits(0)


# -- no hardware: a message, never a traceback -------------------------------


def test_a_host_without_smbus_exits_with_a_message(monkeypatch):
    module = _load_bench(monkeypatch, None)

    with pytest.raises(SystemExit) as raised:
        module.RelayBoard()

    assert isinstance(raised.value.code, str)
    assert "smbus" in raised.value.code


def test_a_useless_smbus_exits_with_a_message(monkeypatch):
    """The check must be the import `RelayBank` actually performs.

    `EvccRelays` opens the bus with `from smbus import SMBus`, so a module
    named smbus that has no `SMBus` still fails - and an ImportError is not an
    OSError, so it would sail past the bus guard below as a traceback.
    """
    module = _load_bench(monkeypatch, types.ModuleType("smbus"))

    with pytest.raises(SystemExit) as raised:
        module.RelayBoard()

    assert isinstance(raised.value.code, str), "raised a traceback, not a message"
    assert "smbus" in raised.value.code


def test_a_host_without_the_relay_board_exits_with_a_message(monkeypatch):
    """smbus installed but no expander on the bus — /dev/i2c-1 is not there."""

    def no_such_bus(_bus_number):
        raise FileNotFoundError(2, "No such file or directory")

    module = _load_bench(monkeypatch, _fake_smbus(no_such_bus))

    with pytest.raises(SystemExit) as raised:
        module.RelayBoard()

    assert isinstance(raised.value.code, str), "raised a traceback, not a message"
    assert "i2c" in raised.value.code.lower()


def test_an_unreadable_relay_board_exits_with_a_message(monkeypatch):
    """The realistic Pi failure: /dev/i2c-1 exists, the user is not in `i2c`."""

    class Unreadable(FakeBus):
        def read_byte_data(self, addr, reg):
            raise PermissionError(13, "Permission denied")

    module = _load_bench(monkeypatch, _fake_smbus(lambda _n: Unreadable()))

    with pytest.raises(SystemExit) as raised:
        module.RelayBoard()

    assert isinstance(raised.value.code, str), "raised a traceback, not a message"


# -- the operator-facing vocabulary is unchanged -----------------------------


def test_the_prompt_and_state_vocabulary_are_unchanged(bench):
    assert bench.module.PROMPT == "state> "
    assert set(bench.module.STATES) == {"A", "B", "C"}
    assert bench.module.HELP == (
        "Enter a state (a/b/c), '?' for this help, or 'q' to quit."
    )


def test_the_printed_feedback_names_the_state_and_its_ev_bits(
    bench, monkeypatch, capsys
):
    """The feedback lines, with the two the scoping change deliberately reworded.

    Issue #109 asks for the printed feedback to be unchanged; two lines are
    not, and both were reworded by the #108 cutover on purpose, because the
    wording they replaced is now false. The script no longer writes a whole
    control register (`control reg = ` became `EV bits = `) and no longer opens
    every relay (`All relays open` became `All EV relays open`) - saying either
    of the old things would misreport what the bench just did to a board it
    shares with a live SECC. The prompt and the state vocabulary, which the
    same criterion also pins, are asserted unchanged above.
    """
    _drive(bench, monkeypatch, ["b", "x", "?", "q"])

    out = capsys.readouterr().out
    assert f"Going to state A (EV bits = {bench.bits('A'):#07b})" in out
    assert f"Going to state B (EV bits = {bench.bits('B'):#07b})" in out
    assert "Unknown input 'X'." in out
    assert bench.module.HELP in out
    assert "Current state: B" in out
