"""The EVCC drives the control pilot through its enable hook (issue #144).

Conformance finding SC-001: `enable_charging` was a no-op, so the pilot sat in
State B for the whole session and every real DC charger failed us at
CableCheck. The controller now takes an injected control-pilot setter (wired to
the role-scoped `EvccRelays` in `pev.py`) and drives State C when charging is
enabled, State B when it is disabled. SC-066 adds the two stop-side
refinements: EVReady goes false once the EV is stopping, and a settle delay
separates the State-B write from the next request.
"""

from __future__ import annotations

import time

import pytest

from app.evcc.controller import simulator
from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.shared.EmulatorEnum import PEVState
from app.shared.personality import EVCCPersonality


def _controller(setter=None) -> SimEVController:
    config = EVCCConfig.from_personality(EVCCPersonality())
    return SimEVController(config, cp_state_setter=setter)


@pytest.fixture(autouse=True)
def _short_settle(monkeypatch):
    monkeypatch.setattr(simulator, "CP_STATE_B_SETTLE_S", 0.05)


async def test_enable_drives_state_c_and_disable_drives_state_b():
    states = []
    ctrl = _controller(states.append)

    await ctrl.enable_charging(True)
    await ctrl.enable_charging(False)

    assert states == [PEVState.C, PEVState.B]


async def test_controller_without_a_setter_still_runs():
    ctrl = _controller()

    await ctrl.enable_charging(True)
    await ctrl.enable_charging(False)


async def test_state_b_write_is_followed_by_a_settle_delay():
    written_at = {}

    def setter(state):
        written_at[state] = time.monotonic()

    ctrl = _controller(setter)
    await ctrl.enable_charging(False)
    returned_at = time.monotonic()

    assert returned_at - written_at[PEVState.B] >= simulator.CP_STATE_B_SETTLE_S


async def test_ev_ready_true_while_charging():
    ctrl = _controller(lambda _: None)
    await ctrl.enable_charging(True)

    assert (await ctrl.get_dc_ev_status()).ev_ready is True
    assert (await ctrl.get_dc_ev_status_dinspec()).ev_ready is True


@pytest.mark.parametrize(
    "stop",
    [lambda c: c.stop_charging(), lambda c: c.enable_charging(False)],
    ids=["stop_charging", "disable"],
)
async def test_ev_ready_false_once_stopping(stop):
    ctrl = _controller(lambda _: None)
    await ctrl.enable_charging(True)

    await stop(ctrl)

    assert (await ctrl.get_dc_ev_status()).ev_ready is False
    assert (await ctrl.get_dc_ev_status_dinspec()).ev_ready is False
    params = await ctrl.get_dc_ev_power_delivery_parameter()
    assert params.dc_ev_status.ev_ready is False


async def test_re_enabling_charging_clears_the_stop():
    # ISO-20 service renegotiation drops to State B, then the next schedule
    # exchange re-enables charging: the new charge loop must run, not end on
    # its first poll with a stop left over from the previous one.
    ctrl = _controller(lambda _: None)
    await ctrl.enable_charging(True)
    await ctrl.enable_charging(False)

    await ctrl.enable_charging(True)

    assert await ctrl.continue_charging() is True
    assert (await ctrl.get_dc_ev_status()).ev_ready is True
