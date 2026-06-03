"""EVCC ISO 15118-20 AC charge-loop stall (ADR-0004, issue #36).

ISO-20 *AC* parity for the operator charge-loop stall proven on the -20 DC
loop in #32. #32 met its acceptance criterion for AC by a manual
``--stall-charge-loop`` run only; this drives the real EVCC ISO-20
``ACChargeLoop`` state through ``process_message()`` at the ADR-0003
state-machine seam so the AC loop's stall behaviour has an automated guard.

The stall rides the protocol-agnostic ``continue_charging()`` gate (already
covered headless at the controller seam by
``tests/operator_console/test_charge_loop_stall.py``); what these tests add is
the proof that the *AC* state wiring consults that gate and translates its
verdict into the right state trajectory:

- unarmed -> the loop runs its cycle cap and then stops at ``PowerDelivery``;
- armed -> the loop holds open, re-sending ``ACChargeLoopReq`` and staying in
  ``ACChargeLoop`` even with the cycle cap exhausted and SOC at 100% (the gate
  is forceful, not a wait-for-completion);
- pressing ``[a]dvance`` -> the gate releases once and the loop ends via
  ``PowerDelivery``;
- disarmed -> the normal completion path is restored.

Live current/voltage override is DC-only (the ISO-20 AC charge-loop messages
carry no current/voltage field), so AC is stall-only — no override coverage
here, matching the #36 scope note.
"""

from __future__ import annotations

from time import time
from types import SimpleNamespace

import pytest

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.evcc.states.iso15118_20_states import ACChargeLoop, PowerDelivery
from app.shared.live_control import LiveControl
from app.shared.messages.enums import ControlMode, Protocol, ServiceV20
from app.shared.messages.iso15118_20.ac import (
    ACChargeLoopRes,
    ScheduledACChargeLoopResParams,
)
from app.shared.messages.iso15118_20.common_types import (
    MessageHeader,
    ResponseCode,
)
from app.shared.personality import EVCCPersonality
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession


def _evcc_session(live_control: LiveControl | None) -> StubCommSession:
    controller = SimEVController(
        EVCCConfig.from_personality(EVCCPersonality()), live_control
    )
    # Keep the held-loop assertions fast: the held branch awaits
    # charge_loop_delay() before rebuilding the request.
    controller.charge_loop_delay_time = 0
    session = StubCommSession(
        protocol=Protocol.ISO_15118_20_COMMON_MESSAGES, session_id=bytes(1).hex()
    )
    session.ev_controller = controller
    # ACChargeLoop only reads `.service` off the selected energy service; a
    # scheduled-mode AC service is all the state needs to rebuild the req.
    session.selected_energy_service = SimpleNamespace(service=ServiceV20.AC)
    session.control_mode = ControlMode.SCHEDULED
    return session


def _ac_charge_loop_res(session: StubCommSession) -> ACChargeLoopRes:
    # No evse_status -> the state skips renegotiation and consults the gate.
    return ACChargeLoopRes(
        header=MessageHeader(session_id=session.session_id, timestamp=int(time())),
        response_code=ResponseCode.OK,
        scheduled_params=ScheduledACChargeLoopResParams(),
    )


@pytest.mark.asyncio
async def test_unarmed_loop_runs_cycle_cap_then_stops(exi_codec):
    """Baseline: with no stall the AC loop cycles once then stops at PowerDelivery."""
    session = _evcc_session(LiveControl())  # stall_charge_loop False
    session.ev_controller.charging_loop_cycles = 1
    peer = ScriptedPeer(session, start_state=ACChargeLoop)

    held = await peer.feed(_ac_charge_loop_res(session))
    assert held.next_state is ACChargeLoop  # one cycle left -> keep looping
    assert held.outbound_v2gtp is not None  # a fresh ACChargeLoopReq went out

    stopped = await peer.feed(_ac_charge_loop_res(session))
    assert stopped.next_state is PowerDelivery  # cycle cap hit -> stop


@pytest.mark.asyncio
async def test_armed_gate_holds_loop_open(exi_codec):
    """While armed the AC loop keeps re-sending ACChargeLoopReq indefinitely."""
    session = _evcc_session(LiveControl(stall_charge_loop=True))
    # Conditions that would normally end the loop immediately are ignored
    # while the gate is armed.
    session.ev_controller.charging_loop_cycles = 0
    session.ev_controller._soc = 100
    peer = ScriptedPeer(session, start_state=ACChargeLoop)

    for _ in range(5):
        result = await peer.feed(_ac_charge_loop_res(session))
        assert result.next_state is ACChargeLoop
        assert result.outbound_v2gtp is not None


@pytest.mark.asyncio
async def test_advance_releases_loop_to_power_delivery(exi_codec):
    """[a]dvance passes the gate once -> the loop ends via PowerDelivery."""
    lc = LiveControl(stall_charge_loop=True)
    session = _evcc_session(lc)
    session.ev_controller.charging_loop_cycles = 0
    session.ev_controller._soc = 100
    peer = ScriptedPeer(session, start_state=ACChargeLoop)

    held = await peer.feed(_ac_charge_loop_res(session))
    assert held.next_state is ACChargeLoop

    lc.release_charge_loop()  # operator presses [a]
    released = await peer.feed(_ac_charge_loop_res(session))
    assert released.next_state is PowerDelivery


@pytest.mark.asyncio
async def test_disarm_restores_normal_stop(exi_codec):
    """Disarming the gate falls back to the normal completion path."""
    lc = LiveControl(stall_charge_loop=True)
    session = _evcc_session(lc)
    session.ev_controller.charging_loop_cycles = 0
    session.ev_controller._soc = 100
    peer = ScriptedPeer(session, start_state=ACChargeLoop)

    held = await peer.feed(_ac_charge_loop_res(session))
    assert held.next_state is ACChargeLoop

    lc.disarm_charge_loop_stall()
    stopped = await peer.feed(_ac_charge_loop_res(session))
    assert stopped.next_state is PowerDelivery
