"""Unit tests for the shared LiveControl object (ADR-0004, issue #28)."""

from __future__ import annotations

from app.shared.live_control import (
    PHASE_IDLE,
    PHASE_SESSION_ACTIVE,
    PHASE_WAITING_FOR_SLAC,
    LiveControl,
)


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


# -- authorization stall (ADR-0004, issue #30) ------------------------------


def test_authorization_defaults_are_inert():
    lc = LiveControl()
    assert lc.stall_authorization is False
    assert lc.take_authorization_release() is False


def test_arm_authorization_via_constructor():
    lc = LiveControl(stall_authorization=True)
    assert lc.stall_authorization is True


def test_toggle_flips_authorization_arm_flag():
    lc = LiveControl()
    lc.toggle_authorization_stall()
    assert lc.stall_authorization is True
    lc.toggle_authorization_stall()
    assert lc.stall_authorization is False


def test_authorization_release_is_one_shot():
    lc = LiveControl(stall_authorization=True)
    lc.release_authorization()
    assert lc.take_authorization_release() is True
    assert lc.take_authorization_release() is False


def test_arm_authorization_clears_stale_release():
    """A release pressed while disarmed must not leak into the next arm."""
    lc = LiveControl()
    lc.release_authorization()  # stray [a] while not armed
    lc.arm_authorization_stall()
    assert lc.take_authorization_release() is False


def test_toggle_authorization_on_clears_stale_release():
    lc = LiveControl()
    lc.release_authorization()
    lc.toggle_authorization_stall()  # off -> on
    assert lc.stall_authorization is True
    assert lc.take_authorization_release() is False


def test_two_gates_are_independent():
    """Releasing the charge-loop gate must not satisfy the auth gate, or vice versa."""
    lc = LiveControl(stall_charge_loop=True, stall_authorization=True)
    lc.release_charge_loop()
    assert lc.take_authorization_release() is False  # auth gate untouched
    assert lc.take_charge_loop_release() is True
    lc.release_authorization()
    assert lc.take_charge_loop_release() is False  # charge gate untouched
    assert lc.take_authorization_release() is True


# -- lifecycle advance / re-arm (ADR-0005, issue #41) -----------------------


def test_default_phase_is_waiting_for_slac():
    assert LiveControl().phase == PHASE_WAITING_FOR_SLAC


def test_advance_signal_defaults_inert():
    assert LiveControl().take_advance() is False


def test_advance_signal_is_one_shot():
    lc = LiveControl()
    lc.signal_advance()
    assert lc.take_advance() is True
    assert lc.take_advance() is False


def test_advance_while_idle_rearms_not_releases_gate():
    """While idle, [a] arms the re-arm signal and touches no stall gate."""
    lc = LiveControl(phase=PHASE_IDLE)
    lc.advance(is_secc=False)
    assert lc.take_advance() is True
    # The charge-loop gate must not have been pulsed by an idle advance.
    assert lc.take_charge_loop_release() is False


def test_advance_while_idle_secc_rearms_not_releases_gate():
    lc = LiveControl(phase=PHASE_IDLE)
    lc.advance(is_secc=True)
    assert lc.take_advance() is True
    assert lc.take_authorization_release() is False


def test_advance_during_active_session_releases_evcc_gate():
    """During a session [a] keeps its ADR-0004 meaning: release the role's gate."""
    lc = LiveControl(phase=PHASE_SESSION_ACTIVE, stall_charge_loop=True)
    lc.advance(is_secc=False)
    assert lc.take_charge_loop_release() is True
    assert lc.take_advance() is False  # no re-arm queued mid-session


def test_advance_during_active_session_releases_secc_gate():
    lc = LiveControl(phase=PHASE_SESSION_ACTIVE, stall_authorization=True)
    lc.advance(is_secc=True)
    assert lc.take_authorization_release() is True
    assert lc.take_advance() is False


def test_advance_while_waiting_for_slac_does_not_rearm():
    """A pre-session [a] is non-idle, so it must not queue a re-arm."""
    lc = LiveControl(phase=PHASE_WAITING_FOR_SLAC)
    lc.advance(is_secc=False)
    assert lc.take_advance() is False


def test_advance_while_waiting_for_slac_does_not_release_evcc_gate():
    """A pre-session [a] must not pre-release the EVCC's stall gate (issue #55).

    The charge loop hasn't started yet, so there is no gate to pass. Pulsing the
    release here persists on the one-shot Event and is consumed by the *next*
    session's first poll, silently skipping the stall the operator armed.
    """
    lc = LiveControl(phase=PHASE_WAITING_FOR_SLAC, stall_charge_loop=True)
    lc.advance(is_secc=False)
    assert lc.take_charge_loop_release() is False


def test_advance_while_waiting_for_slac_does_not_release_secc_gate():
    """A pre-session [a] must not pre-release the SECC's auth gate (issue #55)."""
    lc = LiveControl(phase=PHASE_WAITING_FOR_SLAC, stall_authorization=True)
    lc.advance(is_secc=True)
    assert lc.take_authorization_release() is False


# -- per-cycle gate reset (ADR-0005, issue #55) -----------------------------


def test_begin_cycle_clears_pending_charge_loop_release():
    """A release left pending from a prior cycle must not leak into the next.

    Mirrors the cross-cycle hazard of issue #55: a second [a] after the gate
    already passed sets the Event again, and without a per-cycle reset the next
    session consumes it on its first poll and skips the armed stall.
    """
    lc = LiveControl(stall_charge_loop=True)
    lc.release_charge_loop()  # stale release carried over from a prior cycle
    lc.begin_cycle()
    assert lc.take_charge_loop_release() is False


def test_begin_cycle_clears_pending_authorization_release():
    lc = LiveControl(stall_authorization=True)
    lc.release_authorization()
    lc.begin_cycle()
    assert lc.take_authorization_release() is False


def test_begin_cycle_preserves_arm_flags():
    """The standing stall intent persists across cycles; only releases reset.

    A CLI-armed stall must engage on every cycle (acceptance #2), so begin_cycle
    clears the one-shot releases without disarming the gates.
    """
    lc = LiveControl(stall_charge_loop=True, stall_authorization=True)
    lc.begin_cycle()
    assert lc.stall_charge_loop is True
    assert lc.stall_authorization is True


# -- auto-rearm mode (ADR-0005, issue #43) ----------------------------------


def test_auto_rearm_defaults_off():
    """Auto-rearm is opt-in: a bare LiveControl has it off."""
    assert LiveControl().auto_rearm is False


def test_auto_rearm_via_constructor():
    """The controller seeds auto_rearm from runtime.rearm.auto at startup."""
    assert LiveControl(auto_rearm=True).auto_rearm is True


def test_toggle_auto_rearm_flips_in_both_directions():
    lc = LiveControl()
    lc.toggle_auto_rearm()
    assert lc.auto_rearm is True
    lc.toggle_auto_rearm()
    assert lc.auto_rearm is False


def test_toggle_auto_rearm_does_not_queue_advance():
    """Flipping the mode is not a one-shot advance — no re-arm signal is queued.

    The idle wait reads `auto_rearm` directly, so toggling must not also pulse
    `_advance_signal` (which would leak a spurious advance into a later cycle).
    """
    lc = LiveControl()
    lc.toggle_auto_rearm()
    assert lc.take_advance() is False


# -- live override (ADR-0004, issue #29) ------------------------------------


def test_override_defaults_are_none():
    """No override set => fields are None, meaning 'use the personality value'."""
    lc = LiveControl()
    assert lc.override_current_a is None
    assert lc.override_voltage_v is None


def test_override_via_constructor():
    lc = LiveControl(override_current_a=125.0, override_voltage_v=420.0)
    assert lc.override_current_a == 125.0
    assert lc.override_voltage_v == 420.0


def test_set_override_current_and_voltage():
    lc = LiveControl()
    lc.set_override_current(250.0)
    assert lc.override_current_a == 250.0
    assert lc.override_voltage_v is None  # voltage untouched
    lc.set_override_voltage(800.0)
    assert lc.override_voltage_v == 800.0


def test_set_override_persists_and_can_change():
    """An override persists until changed (loop iterations don't reset it)."""
    lc = LiveControl()
    lc.set_override_current(100.0)
    assert lc.override_current_a == 100.0
    lc.set_override_current(150.0)
    assert lc.override_current_a == 150.0


def test_clear_overrides_restores_none():
    """Clearing restores None on both fields => fall back to personality value."""
    lc = LiveControl(override_current_a=10.0, override_voltage_v=20.0)
    lc.clear_overrides()
    assert lc.override_current_a is None
    assert lc.override_voltage_v is None


# -- operator quit + teardown hooks (issue #40) -----------------------------


def test_request_quit_sets_flag():
    lc = LiveControl()
    assert lc.quit_requested is False
    lc.request_quit()
    assert lc.quit_requested is True


def test_request_quit_runs_registered_hooks():
    """The controller registers SLAC teardown here; quit must invoke it.

    Without this, 'q' tears down only the TUI while the SLAC thread keeps
    sending and the process hangs (issue #40).
    """
    lc = LiveControl()
    calls = []
    lc.register_quit_hook(lambda: calls.append("a"))
    lc.register_quit_hook(lambda: calls.append("b"))
    lc.request_quit()
    assert calls == ["a", "b"]


def test_request_quit_hooks_are_best_effort():
    """A raising hook is swallowed so it can't strand the quit or block siblings."""
    lc = LiveControl()
    calls = []

    def _boom():
        raise RuntimeError("teardown blew up")

    lc.register_quit_hook(_boom)
    lc.register_quit_hook(lambda: calls.append("ran"))
    lc.request_quit()  # must not raise
    assert lc.quit_requested is True
    assert calls == ["ran"]  # sibling hook still ran
