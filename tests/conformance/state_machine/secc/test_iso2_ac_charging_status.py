"""SECC ISO 15118-2 AC ChargingStatusRes build guard (#80).

The ISO-15118-2 AC charge loop lives in the `ChargingStatus` state: on a
``ChargingStatusReq`` the SECC builds a ``ChargingStatusRes`` whose
``EVSEMaxCurrent`` comes from ``get_evse_max_current_limit()``. That controller
method has required ``protocol`` since commit ``6401f85``; the AC build site was
calling it with no argument, so the AC path raised
``TypeError: get_evse_max_current_limit() missing 1 required positional
argument: 'protocol'``. The DC sites always passed ``Protocol.ISO_15118_2``.

There is no ISO-2 AC scenario in the E2E/virtual demo, so the crash was dormant
until a cross-file trace surfaced it while auditing #73. This test drives the
real `ChargingStatus` state through the ADR-0003 `process_message()` seam with
the controller in AC mode and asserts the response builds -- exercising the AC
branch of ``get_evse_max_current_limit`` (which returns a ``PVEVSEMaxCurrent``).
"""

from __future__ import annotations

import pytest

from app.secc.controller.evse_data import CurrentType
from app.secc.controller.simulator import SimEVSEController
from app.secc.states.iso15118_2_states import ChargingStatus
from app.shared.messages.datatypes import PVEVSEMaxCurrent
from app.shared.messages.enums import Protocol
from app.shared.messages.iso15118_2.body import (
    Body,
    ChargingStatusReq,
    ChargingStatusRes,
    ResponseCode,
)
from app.shared.messages.iso15118_2.header import MessageHeader
from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession


def _secc_ac_session() -> StubCommSession:
    """A ISO-2 SECC session whose controller is in AC mode.

    ``get_evse_context()`` already seeds AC session limits and a non-zero
    present voltage, so the AC branch of ``get_evse_max_current_limit`` can
    compute a per-phase current. The one thing the CPD state would normally
    set -- ``current_type`` -- is set here directly since this test enters at
    ``ChargingStatus``.
    """
    controller = SimEVSEController()
    controller.set_selected_protocol(Protocol.ISO_15118_2)
    controller.evse_data_context.current_type = CurrentType.AC
    session = StubCommSession(protocol=Protocol.ISO_15118_2, session_id=bytes(1).hex())
    session.evse_controller = controller
    session.selected_schedule = 1
    return session


def _charging_status_req(session: StubCommSession) -> V2GMessageV2:
    return V2GMessageV2(
        header=MessageHeader(session_id=session.session_id),
        body=Body(charging_status_req=ChargingStatusReq()),
    )


@pytest.mark.asyncio
async def test_iso2_ac_charging_status_builds_response(exi_codec):
    """A ChargingStatusReq in the AC loop builds a ChargingStatusRes(OK).

    Before #80 this raised ``TypeError`` at the ``get_evse_max_current_limit()``
    call while building the response. The state stays put (``next_state`` None)
    to await the next ChargingStatusReq / PowerDeliveryReq / MeteringReceiptReq.
    """
    session = _secc_ac_session()
    peer = ScriptedPeer(session, start_state=ChargingStatus)

    result = await peer.feed(_charging_status_req(session))

    res = result.outbound_msg.body.charging_status_res
    assert isinstance(res, ChargingStatusRes)
    assert res.response_code == ResponseCode.OK
    # The AC branch of get_evse_max_current_limit returns a PVEVSEMaxCurrent;
    # its presence is the proof the build site reached the controller without
    # the missing-protocol TypeError.
    assert isinstance(res.evse_max_current, PVEVSEMaxCurrent)
    # ChargingStatus stays resident to await the next request in the AC loop.
    assert result.next_state is None
    assert session.stop_reason is None
