"""The EVCC charge-loop stall gate, exercised through the controller.

This is the behavioural core of issue #28: while the charge-loop gate is
armed, `SimEVController.continue_charging()` must keep the CurrentDemand loop
cycling indefinitely — ignoring the cycle cap and SOC completion — until the
operator presses [a]dvance (one-shot release), after which it returns False so
the state machine sends PowerDelivery(STOP). No TTY / footer is involved here,
so the gate logic is fully verifiable headless.
"""

from __future__ import annotations

import pytest

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.shared.live_control import LiveControl
from app.shared.personality import EVCCPersonality


def _controller(live_control: LiveControl | None) -> SimEVController:
    config = EVCCConfig.from_personality(EVCCPersonality())
    return SimEVController(config, live_control)


async def test_no_live_control_behaves_normally():
    """Without a LiveControl the loop runs the cycle cap, then stops."""
    ctrl = _controller(None)
    ctrl.charging_loop_cycles = 2
    assert await ctrl.continue_charging() is True
    assert await ctrl.continue_charging() is True
    assert await ctrl.continue_charging() is False


async def test_armed_gate_ignores_cycle_cap_and_soc():
    lc = LiveControl(stall_charge_loop=True)
    ctrl = _controller(lc)
    # Conditions that would normally end the loop immediately:
    ctrl.charging_loop_cycles = 0
    ctrl._soc = 100  # is_charging_complete() would be True
    # ...are ignored while the gate is armed.
    for _ in range(50):
        assert await ctrl.continue_charging() is True


async def test_advance_releases_gate_once():
    lc = LiveControl(stall_charge_loop=True)
    ctrl = _controller(lc)
    ctrl.charging_loop_cycles = 0

    assert await ctrl.continue_charging() is True  # held
    lc.release_charge_loop()  # operator presses [a]
    assert await ctrl.continue_charging() is False  # released -> stop


async def test_disarm_falls_back_to_normal_path():
    lc = LiveControl(stall_charge_loop=True)
    ctrl = _controller(lc)
    ctrl.charging_loop_cycles = 0
    ctrl._soc = 100

    assert await ctrl.continue_charging() is True  # held while armed
    lc.disarm_charge_loop_stall()
    # Now the normal completion conditions apply again.
    assert await ctrl.continue_charging() is False
