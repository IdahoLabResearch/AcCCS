"""EVCC ISO 15118-20 ongoing-authorization timer defeat (ADR-0004, issue #32).

ISO-20 parity for the timer defeat proven on ISO 15118-2 (#30) and DIN SPEC
70121 (#31). Drives the real EVCC ISO-20 `Authorization` state through
`process_message()` at the ADR-0003 state-machine seam, feeding a
``Processing.ONGOING`` AuthorizationRes (what a stalling SECC sends) with the
ongoing timer set far enough in the past that it has already expired.

- Without stall mode the EVCC aborts the session at
  ``V2G_EVCC_ONGOING_TIMEOUT`` (conformant behaviour — the timer-defeat is
  opt-in only).
- In stall mode the EVCC ignores that timeout and keeps polling
  `AuthorizationReq`, letting a stalling SECC hold it indefinitely.

"EVCC stall mode" is the EVCC's own stall arm (`stall_charge_loop`), exactly as
on the ISO 15118-2 / DIN paths; the issue adds no separate EVCC flag.
"""

from __future__ import annotations

import types
from time import time

import pytest

from app.evcc.states.iso15118_20_states import Authorization
from app.shared.live_control import LiveControl
from app.shared.messages.enums import AuthEnum, Protocol
from app.shared.messages.iso15118_20.common_messages import (
    AuthorizationReq,
    AuthorizationRes,
    EIMAuthReqParams,
)
from app.shared.messages.iso15118_20.common_types import (
    MessageHeader,
    Processing,
    ResponseCode,
)
from app.shared.messages.timeouts import Timeouts as TimeoutsShared
from app.shared.states import Terminate
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession


def _evcc_session(live_control: LiveControl | None) -> StubCommSession:
    session = StubCommSession(
        protocol=Protocol.ISO_15118_20_COMMON_MESSAGES, session_id=bytes(1).hex()
    )
    session.live_control = live_control
    # Timer already started, far enough back that it has expired.
    session.ongoing_timer = int(time()) - (TimeoutsShared.V2G_EVCC_ONGOING_TIMEOUT + 100)
    # The EVCC's stop_state_machine reads comm_session.writer for the peer name;
    # a stub writer keeps the abort path reachable at this seam.
    session.writer = types.SimpleNamespace(get_extra_info=lambda _name: None)
    # The re-send path rebuilds AuthorizationReq from the cached request message.
    session.authorization_req_message = AuthorizationReq(
        header=MessageHeader(session_id=session.session_id, timestamp=int(time())),
        selected_auth_service=AuthEnum.EIM,
        eim_params=EIMAuthReqParams(),
    )
    return session


def _ongoing_res(session: StubCommSession) -> AuthorizationRes:
    return AuthorizationRes(
        header=MessageHeader(session_id=session.session_id, timestamp=int(time())),
        response_code=ResponseCode.OK,
        evse_processing=Processing.ONGOING,
    )


@pytest.mark.asyncio
async def test_without_stall_mode_expired_timer_aborts(exi_codec):
    """A conformant EVCC (no stall mode) stops once the ongoing timer expires."""
    session = _evcc_session(LiveControl())  # stall_charge_loop False
    peer = ScriptedPeer(session, start_state=Authorization)

    result = await peer.feed(_ongoing_res(session))

    assert result.next_state is Terminate
    assert session.stop_reason is not None


@pytest.mark.asyncio
async def test_stall_mode_defeats_expired_timer_and_keeps_polling(exi_codec):
    """In stall mode the EVCC ignores the expired timer and re-sends AuthorizationReq."""
    session = _evcc_session(LiveControl(stall_charge_loop=True))
    peer = ScriptedPeer(session, start_state=Authorization)

    result = await peer.feed(_ongoing_res(session))

    assert result.next_state is Authorization  # keeps polling, not Terminate
    assert session.stop_reason is None
    assert result.outbound_v2gtp is not None  # a fresh AuthorizationReq went out


@pytest.mark.asyncio
async def test_stall_mode_keeps_a_positive_next_timeout(exi_codec):
    """The defeated path must not poison the per-message timeout with a negative."""
    session = _evcc_session(LiveControl(stall_charge_loop=True))
    peer = ScriptedPeer(session, start_state=Authorization)

    ran_state = peer.state
    await peer.feed(_ongoing_res(session))

    # Once elapsed exceeds the ongoing timeout, the old `min(REQ, ONGOING -
    # elapsed)` would go negative; stall mode pins it to the positive
    # per-message timeout instead.
    assert ran_state.next_msg_timeout > 0
