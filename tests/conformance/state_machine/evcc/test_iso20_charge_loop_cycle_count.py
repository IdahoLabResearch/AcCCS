"""ISO-20 EVCC: ``charge_loop_cycle: N`` puts exactly N ChargeLoopReq on the
wire (issue #138, conformance review SC-003).

The DIN and ISO-2 PowerDelivery states consult the loop-continuation routine
before the first CurrentDemandReq, so every loop request costs one cycle. The
ISO-20 PowerDelivery state sent its first ACChargeLoopReq unconditionally and
only started counting at the first response, which is one request too many
once the simulated state of charge ramps to 100 over exactly N cycles. This
drives the real ``PowerDelivery`` and ``ACChargeLoop`` states at the ADR-0003
``process_message()`` seam and counts the loop requests.
"""

from __future__ import annotations

from time import time
from types import SimpleNamespace

import pytest

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.evcc.states.iso15118_20_states import ACChargeLoop, PowerDelivery
from app.shared.messages.enums import ControlMode, Protocol, ServiceV20
from app.shared.messages.iso15118_20.ac import (
    ACChargeLoopRes,
    ScheduledACChargeLoopResParams,
)
from app.shared.messages.iso15118_20.common_messages import PowerDeliveryRes
from app.shared.messages.iso15118_20.common_types import (
    MessageHeader,
    Processing,
    ResponseCode,
)
from app.shared.personality import EVCCPersonality
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession

CYCLES = 3


def _evcc_session() -> StubCommSession:
    config = EVCCConfig.from_personality(EVCCPersonality())
    config.charge_loop_cycle = CYCLES
    controller = SimEVController(config)
    controller.charge_loop_delay_time = 0
    session = StubCommSession(
        protocol=Protocol.ISO_15118_20_COMMON_MESSAGES, session_id=bytes(1).hex()
    )
    session.ev_controller = controller
    session.ev_processing = Processing.FINISHED
    session.charging_session_stop_v20 = None
    session.selected_energy_service = SimpleNamespace(service=ServiceV20.AC)
    session.control_mode = ControlMode.SCHEDULED
    return session


def _header(session: StubCommSession) -> MessageHeader:
    return MessageHeader(session_id=session.session_id, timestamp=int(time()))


@pytest.mark.asyncio
async def test_power_delivery_start_counts_the_first_loop_request(exi_codec):
    session = _evcc_session()
    peer = ScriptedPeer(session, start_state=PowerDelivery)

    result = await peer.feed(
        PowerDeliveryRes(header=_header(session), response_code=ResponseCode.OK)
    )
    loop_reqs = 0
    while result.next_state is ACChargeLoop:
        loop_reqs += 1
        assert loop_reqs <= CYCLES + 1, "charge loop overran"
        result = await peer.feed(
            ACChargeLoopRes(
                header=_header(session),
                response_code=ResponseCode.OK,
                scheduled_params=ScheduledACChargeLoopResParams(),
            )
        )

    assert loop_reqs == CYCLES
    assert result.next_state is PowerDelivery  # the Stop
    assert session.ev_controller._soc == 100
