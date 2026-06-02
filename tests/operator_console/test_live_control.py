"""Unit tests for the shared LiveControl object (ADR-0004, issue #28)."""

from __future__ import annotations

from app.shared.live_control import LiveControl


def test_defaults_are_inert():
    lc = LiveControl()
    assert lc.console_enabled is False
    assert lc.stall_charge_loop is False
    # No release pending out of the gate.
    assert lc.take_charge_loop_release() is False


def test_arm_via_constructor():
    lc = LiveControl(console_enabled=True, stall_charge_loop=True)
    assert lc.console_enabled is True
    assert lc.stall_charge_loop is True


def test_toggle_flips_arm_flag():
    lc = LiveControl()
    lc.toggle_charge_loop_stall()
    assert lc.stall_charge_loop is True
    lc.toggle_charge_loop_stall()
    assert lc.stall_charge_loop is False


def test_release_is_one_shot():
    lc = LiveControl(stall_charge_loop=True)
    lc.release_charge_loop()
    # First take consumes it; the second sees nothing.
    assert lc.take_charge_loop_release() is True
    assert lc.take_charge_loop_release() is False


def test_arm_clears_stale_release():
    """A release pressed while disarmed must not leak into the next arm."""
    lc = LiveControl()
    lc.release_charge_loop()  # stray [a] while not armed
    lc.arm_charge_loop_stall()
    # Fresh arm starts with no pending release.
    assert lc.take_charge_loop_release() is False


def test_toggle_on_clears_stale_release():
    lc = LiveControl()
    lc.release_charge_loop()
    lc.toggle_charge_loop_stall()  # off -> on
    assert lc.stall_charge_loop is True
    assert lc.take_charge_loop_release() is False
