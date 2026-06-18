"""DIN PreCharge enforces PreChargeReq-first ordering, except for teardown (#70).

Follow-on from #69. To accept an EV-initiated ``SessionStopReq`` at any point,
#69 set ``expect_first=False`` uniformly across the DIN pre-charge states. In
``PreCharge`` that also dropped the ``expecting_pre_charge_req`` first-message
guard, so a bare ``PowerDeliveryReq`` arriving *before* any ``PreChargeReq`` was
accepted and delegated to ``PowerDelivery`` instead of being rejected as a
``FAILED_SequenceError`` -- a protocol-sequence loosening beyond #69's goal.

#70 restores that guard while keeping the #69 teardown behaviour: a
``SessionStopReq`` is routed to ``SessionStop`` *before* the ordering gate, so
it is still accepted as the opening message (covered by
``test_din_pre_charge_states_accept_session_stop`` in
``test_session_stop_lifecycle.py``), but a ``PowerDeliveryReq`` that jumps ahead
of any ``PreChargeReq`` is rejected again.

The originating ``PreCharge`` instance handles the rejection directly, so the
rejection oracle is the harness ``StepResult``. The accept-in-order path
delegates to a fresh ``PowerDelivery`` instance whose ``State.__init__``
reassigns ``comm_session.current_state`` (as in the session-stop tests), so the
oracle there is ``session.current_state``.
"""

from __future__ import annotations

import pytest

from app.secc.controller.simulator import SimEVSEController
from app.secc.states.din_spec_states import CurrentDemand, PowerDelivery, PreCharge
from app.shared.messages.datatypes import (
    PVEVTargetCurrentDin,
    PVEVTargetVoltageDin,
)
from app.shared.messages.din_spec.body import (
    Body,
    PowerDeliveryReq,
    PreChargeReq,
)
from app.shared.messages.din_spec.datatypes import (
    DCEVPowerDeliveryParameter,
    DCEVStatus,
    ResponseCode,
)
from app.shared.messages.din_spec.header import MessageHeader
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import DCEVErrorCode, Protocol, UnitSymbol
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession


class _StubWriter:
    """`stop_state_machine` reads `get_extra_info("peername")` for the StopNotification."""

    def get_extra_info(self, _key: str):
        return ("fe80::2", 0)


def _din_session() -> StubCommSession:
    """A DIN SECC session wired for both the PreCharge happy path and rejection.

    The rejection path needs a writer (StopNotification peername) and the
    prebuilt DIN failed-response table; the happy path needs the EVSE
    controller the PreCharge electrical logic drives.
    """
    from app.secc.failed_responses import init_failed_responses_din_spec_70121

    session = StubCommSession(
        protocol=Protocol.DIN_SPEC_70121, session_id=bytes(1).hex()
    )
    session.evse_controller = SimEVSEController()
    session.writer = _StubWriter()
    session.failed_responses_din_spec = init_failed_responses_din_spec_70121()
    session.charge_progress_started = False
    return session


def _pre_charge_req(session: StubCommSession) -> V2GMessageDINSPEC:
    # Target current must be < 2 A (the inrush-current ceiling PreCharge enforces).
    return V2GMessageDINSPEC(
        header=MessageHeader(session_id=session.session_id),
        body=Body(
            pre_charge_req=PreChargeReq(
                dc_ev_status=DCEVStatus(
                    ev_ready=True,
                    ev_error_code=DCEVErrorCode.NO_ERROR,
                    ev_ress_soc=42,
                ),
                ev_target_voltage=PVEVTargetVoltageDin(
                    multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
                ),
                ev_target_current=PVEVTargetCurrentDin(
                    multiplier=0, value=1, unit=UnitSymbol.AMPERE
                ),
            )
        ),
    )


def _power_delivery_req(session: StubCommSession) -> V2GMessageDINSPEC:
    return V2GMessageDINSPEC(
        header=MessageHeader(session_id=session.session_id),
        body=Body(
            power_delivery_req=PowerDeliveryReq(
                ready_to_charge=True,
                dc_ev_power_delivery_parameter=DCEVPowerDeliveryParameter(
                    dc_ev_status=DCEVStatus(
                        ev_ready=True,
                        ev_error_code=DCEVErrorCode.NO_ERROR,
                        ev_ress_soc=42,
                    ),
                    charging_complete=False,
                ),
            )
        ),
    )


@pytest.mark.asyncio
async def test_din_pre_charge_normal_ordering_completes(exi_codec):
    """The normal PreChargeReq -> PowerDeliveryReq ordering still completes (#70).

    A PreChargeReq opens the state (PreChargeRes OK, stay in PreCharge), then a
    PowerDeliveryReq is accepted as the normal exit and delegated to
    PowerDelivery, which advances toward CurrentDemand. Neither message is
    rejected as a sequence error.
    """
    session = _din_session()
    peer = ScriptedPeer(session, start_state=PreCharge)

    first = await peer.feed(_pre_charge_req(session))

    # The opening PreChargeReq is accepted: PreChargeRes(OK), stay in PreCharge
    # (next_state None), session not torn down.
    assert first.next_state is None
    assert first.outbound_msg.body.pre_charge_res.response_code == ResponseCode.OK
    assert session.stop_reason is None

    second = await peer.feed(_power_delivery_req(session))

    # The PowerDeliveryReq is now in order: delegated to PowerDelivery, which
    # advances to CurrentDemand. Routing reassigns comm_session.current_state to
    # the fresh PowerDelivery instance, so that -- not the PreCharge StepResult --
    # is the oracle.
    assert second.next_state is None  # PreCharge itself did not advance.
    assert isinstance(session.current_state, PowerDelivery)
    assert session.current_state.next_state is CurrentDemand
    assert session.stop_reason is None


@pytest.mark.asyncio
async def test_din_pre_charge_rejects_power_delivery_before_pre_charge(exi_codec):
    """A PowerDeliveryReq before any PreChargeReq is a sequence error (#70).

    This is the invariant #69 inadvertently dropped: with no preceding
    PreChargeReq the opening message must be a PreChargeReq (or the SessionStopReq
    teardown), so a bare PowerDeliveryReq is rejected as FAILED_SequenceError and
    the session is torn down, rather than being delegated to PowerDelivery.
    """
    session = _din_session()
    peer = ScriptedPeer(session, start_state=PreCharge)

    result = await peer.feed(_power_delivery_req(session))

    from app.shared.states import Terminate

    assert result.next_state is Terminate
    assert (
        result.outbound_msg.body.power_delivery_res.response_code
        == ResponseCode.FAILED_SEQUENCE_ERROR
    )
    assert session.stop_reason is not None
    assert session.stop_reason.successful is False
    # It was rejected, not delegated: current_state was never reassigned to a
    # PowerDelivery instance.
    assert not isinstance(session.current_state, PowerDelivery)
