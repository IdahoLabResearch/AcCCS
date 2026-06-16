"""The footer's [s]/[a] key bindings drive LiveControl (ADR-0004, issue #28).

These exercise the live-toggle path without needing a real TTY: build the
prompt_toolkit Application and invoke its bound handlers directly, asserting
they mutate the shared LiveControl. (Actual rendering + physical keypresses
are the one piece that requires a human terminal.)
"""

from __future__ import annotations

import types

from app.shared.console import _apply_override, _build_application
from app.shared.live_control import LiveControl


class _FakeEvent:
    """Minimal stand-in for a prompt_toolkit key-press event."""

    def __init__(self):
        self.exit_called = False
        self.app = types.SimpleNamespace(invalidate=lambda: None)
        self.app.exit = self._on_exit

    def _on_exit(self):
        self.exit_called = True


def _handler_for(app, key: str):
    for binding in app.key_bindings.bindings:
        if any(str(k) == key for k in binding.keys):
            return binding.handler
    raise AssertionError(f"no key binding registered for {key!r}")


def test_s_toggles_charge_loop_stall():
    lc = LiveControl()
    app = _build_application(lc, "EVCC").app
    handler = _handler_for(app, "s")

    handler(_FakeEvent())
    assert lc.stall_charge_loop is True
    handler(_FakeEvent())
    assert lc.stall_charge_loop is False


def test_a_releases_charge_loop_gate():
    lc = LiveControl(stall_charge_loop=True)
    app = _build_application(lc, "EVCC").app
    handler = _handler_for(app, "a")

    handler(_FakeEvent())
    # The advance handler set the one-shot release.
    assert lc.take_charge_loop_release() is True


# -- role-aware stall gate (ADR-0004, issue #30) ----------------------------


def test_secc_s_toggles_authorization_stall_not_charge_loop():
    """On the SECC, [s] drives the auth gate (the gate that role owns)."""
    lc = LiveControl()
    app = _build_application(lc, "SECC").app
    handler = _handler_for(app, "s")

    handler(_FakeEvent())
    assert lc.stall_authorization is True
    assert lc.stall_charge_loop is False  # the EVCC's gate is untouched
    handler(_FakeEvent())
    assert lc.stall_authorization is False


def test_secc_a_releases_authorization_gate():
    lc = LiveControl(stall_authorization=True)
    app = _build_application(lc, "SECC").app
    handler = _handler_for(app, "a")

    handler(_FakeEvent())
    assert lc.take_authorization_release() is True
    # The charge-loop gate saw no release.
    assert lc.take_charge_loop_release() is False


def test_evcc_s_still_toggles_charge_loop_stall():
    """The EVCC footer keeps driving the charge-loop gate."""
    lc = LiveControl()
    app = _build_application(lc, "EVCC").app
    _handler_for(app, "s")(_FakeEvent())
    assert lc.stall_charge_loop is True
    assert lc.stall_authorization is False


# -- auto-rearm toggle (ADR-0005, issue #43) --------------------------------


def test_r_toggles_auto_rearm_evcc():
    """[r] flips auto-rearm on the EVCC console in both directions."""
    lc = LiveControl()
    app = _build_application(lc, "EVCC").app
    handler = _handler_for(app, "r")

    handler(_FakeEvent())
    assert lc.auto_rearm is True
    handler(_FakeEvent())
    assert lc.auto_rearm is False


def test_r_toggles_auto_rearm_secc():
    """[r] is available on the SECC console too (auto-rearm is role-symmetric)."""
    lc = LiveControl()
    app = _build_application(lc, "SECC").app
    _handler_for(app, "r")(_FakeEvent())
    assert lc.auto_rearm is True


def test_r_is_suppressed_during_entry():
    """[r] must not fire while the operator is typing a numeric override."""
    lc = LiveControl()
    console = _build_application(lc, "EVCC")
    _handler_for(console.app, "c")(_FakeEvent())  # enter current-input mode
    r_binding = next(
        b
        for b in console.app.key_bindings.bindings
        if any(str(k) == "r" for k in b.keys)
    )
    assert not r_binding.filter()  # 'r' disabled while entering


def test_footer_reflects_auto_rearm_state():
    """The footer shows the live auto-rearm state (ON/off), per ADR-0005."""
    lc = LiveControl()
    console = _build_application(lc, "EVCC")
    footer = console.app.layout.container.children[1].content

    text_off = "".join(seg[1] for seg in footer.text())
    assert "auto-rearm: off" in text_off

    lc.toggle_auto_rearm()
    text_on = "".join(seg[1] for seg in footer.text())
    assert "auto-rearm: ON" in text_on


# -- live override set/clear (ADR-0004, issue #29) --------------------------


def test_apply_override_current_sets_value():
    lc = LiveControl()
    msg = _apply_override(lc, "current", "250")
    assert lc.override_current_a == 250.0
    assert "250" in msg


def test_apply_override_voltage_accepts_float():
    lc = LiveControl()
    _apply_override(lc, "voltage", "800.5")
    assert lc.override_voltage_v == 800.5


def test_apply_override_out_of_envelope_value_is_unchecked():
    """No clamping: an out-of-envelope value is stored verbatim (issue #29)."""
    lc = LiveControl()
    _apply_override(lc, "voltage", "99999")
    assert lc.override_voltage_v == 99999.0


def test_apply_override_rejects_non_numeric_without_raising():
    lc = LiveControl()
    msg = _apply_override(lc, "current", "abc")
    # Bad input leaves the override untouched and reports the problem.
    assert lc.override_current_a is None
    assert "abc" in msg or "invalid" in msg.lower()


def test_x_clears_overrides():
    lc = LiveControl(override_current_a=10.0, override_voltage_v=20.0)
    app = _build_application(lc, "EVCC").app
    handler = _handler_for(app, "x")

    handler(_FakeEvent())
    assert lc.override_current_a is None
    assert lc.override_voltage_v is None


def _type(console, digits: str) -> None:
    """Drive the per-character entry handlers, as real keystrokes would."""
    for ch in digits:
        _handler_for(console.app, ch)(_FakeEvent())


def test_c_then_typed_digits_then_commit_sets_current_override():
    """Pressing [c], typing digits, then Enter applies the value end-to-end.

    This drives the real key handlers (not a buffer set directly), so it guards
    the keystroke->entry-string->commit path that the live console depends on.
    """
    lc = LiveControl()
    console = _build_application(lc, "EVCC")

    _handler_for(console.app, "c")(_FakeEvent())  # enter current-input mode
    assert console.entry.mode == "current"
    _type(console, "175")
    assert console.entry.text == "175"
    console.commit(_FakeEvent())

    assert lc.override_current_a == 175.0
    assert console.entry.mode is None  # back to action mode


def test_v_then_typed_digits_then_commit_sets_voltage_override():
    lc = LiveControl()
    console = _build_application(lc, "EVCC")

    _handler_for(console.app, "v")(_FakeEvent())  # enter voltage-input mode
    _type(console, "430")
    console.commit(_FakeEvent())

    assert lc.override_voltage_v == 430.0


def test_action_keys_are_inert_while_entering_a_value():
    """A stray [s] while typing a value must not toggle the stall."""
    lc = LiveControl()
    console = _build_application(lc, "EVCC")

    _handler_for(console.app, "c")(_FakeEvent())  # in entry mode now
    # The stall toggle is filtered out in entry mode, so fetching+calling it is
    # not how a real keystroke routes; assert via the filter instead.
    stall_binding = next(
        b
        for b in console.app.key_bindings.bindings
        if any(str(k) == "s" for k in b.keys)
    )
    assert not stall_binding.filter()  # 's' action disabled while entering


# -- quit key (issue #40) ---------------------------------------------------


def test_q_sets_quit_requested_and_exits_evcc():
    """[q] on the EVCC console sets quit_requested and exits the app."""
    lc = LiveControl()
    console = _build_application(lc, "EVCC")
    event = _FakeEvent()
    _handler_for(console.app, "q")(event)
    assert lc.quit_requested is True
    assert event.exit_called is True


def test_q_sets_quit_requested_and_exits_secc():
    """[q] on the SECC console sets quit_requested and exits the app."""
    lc = LiveControl()
    console = _build_application(lc, "SECC")
    event = _FakeEvent()
    _handler_for(console.app, "q")(event)
    assert lc.quit_requested is True
    assert event.exit_called is True


def test_q_is_suppressed_during_entry():
    """[q] must not fire while the operator is typing a numeric override."""
    lc = LiveControl()
    console = _build_application(lc, "EVCC")
    _handler_for(console.app, "c")(_FakeEvent())  # enter current-input mode
    q_binding = next(
        b
        for b in console.app.key_bindings.bindings
        if any(str(k) == "q" for k in b.keys)
    )
    assert not q_binding.filter()  # 'q' disabled while entering
