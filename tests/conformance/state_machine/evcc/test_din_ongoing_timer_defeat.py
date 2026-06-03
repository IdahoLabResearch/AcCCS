"""EVCC DIN SPEC 70121 ongoing-authorization timer defeat (ADR-0004, issue #31).

DIN parity for the ISO 15118-2 timer defeat proven in issue #30. Drives the
real EVCC DIN `ContractAuthentication` state through `process_message()` at the
ADR-0003 state-machine seam, feeding an ``EVSEProcessing.ONGOING`` response
(what a stalling SECC sends) with the ongoing timer set far enough in the past
that it has already expired.

- Without stall mode the EVCC aborts the session at
  ``V2G_SECC_SEQUENCE_TIMEOUT`` (conformant behaviour — the timer-defeat is
  opt-in only).
- In stall mode the EVCC ignores that timeout and keeps polling
  `ContractAuthenticationReq`, letting a stalling SECC hold it indefinitely.

"EVCC stall mode" is the EVCC's own stall arm (`stall_charge_loop`), exactly as
on the ISO 15118-2 path; the issue adds no separate EVCC flag.
"""

from __future__ import annotations

import types
from time import time

import pytest

from app.evcc.states.din_spec_states import ContractAuthentication
from app.shared.live_control import LiveControl
from app.shared.messages.din_spec.body import (
    Body,
    ContractAuthenticationRes,
    ResponseCode,
)
from app.shared.messages.din_spec.header import MessageHeader
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import EVSEProcessing, Protocol
from app.shared.messages.timeouts import Timeouts as TimeoutsShared
from app.shared.states import Terminate
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession


def _evcc_session(live_control: LiveControl | None) -> StubCommSession:
    session = StubCommSession(
        protocol=Protocol.DIN_SPEC_70121, session_id=bytes(1).hex()
    )
    session.live_control = live_control
    # Timer already started, far enough back that it has expired.
    session.ongoing_timer = time() - (TimeoutsShared.V2G_SECC_SEQUENCE_TIMEOUT + 100)
    # The EVCC's stop_state_machine reads comm_session.writer for the peer name;
    # a stub writer keeps the abort path reachable at this seam.
    session.writer = types.SimpleNamespace(get_extra_info=lambda _name: None)
    return session


def _ongoing_res(session: StubCommSession) -> V2GMessageDINSPEC:
    return V2GMessageDINSPEC(
        header=MessageHeader(session_id=session.session_id),
        body=Body(
            contract_authentication_res=ContractAuthenticationRes(
                response_code=ResponseCode.OK,
                evse_processing=EVSEProcessing.ONGOING,
            )
        ),
    )


@pytest.mark.asyncio
async def test_without_stall_mode_expired_timer_aborts(exi_codec):
    """A conformant EVCC (no stall mode) stops once the ongoing timer expires."""
    session = _evcc_session(LiveControl())  # stall_charge_loop False
    peer = ScriptedPeer(session, start_state=ContractAuthentication)

    result = await peer.feed(_ongoing_res(session))

    assert result.next_state is Terminate
    assert session.stop_reason is not None


@pytest.mark.asyncio
async def test_stall_mode_defeats_expired_timer_and_keeps_polling(exi_codec):
    """In stall mode the EVCC ignores the expired timer and re-sends the req."""
    session = _evcc_session(LiveControl(stall_charge_loop=True))
    peer = ScriptedPeer(session, start_state=ContractAuthentication)

    result = await peer.feed(_ongoing_res(session))

    # next_state None means "stay in ContractAuthentication and poll again".
    assert result.next_state is None
    assert session.stop_reason is None
    assert result.outbound_v2gtp is not None  # a fresh ContractAuthenticationReq
