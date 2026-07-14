"""EVCC pacing of the ONGOING poll loops (issue #88).

While an SECC answers ``EVSEProcessing.ONGOING`` — a real charger does this at
ContractAuthentication for as long as it waits on external payment
authorization (EIM RFID/app/backend) — the EVCC re-sends the same request. It
used to do so with no delay at all: ~3,800 round-trips in ~40 s (~190 req/s)
were observed against a Tellus Power charger before the ongoing timer elapsed.
A conformant EVCC polls at a modest cadence instead.

These tests drive the real EVCC states through `process_message()` at the
ADR-0003 state-machine seam and assert the *rate*, not just the shape:

- repeated ONGOING responses produce a bounded number of requests per window;
- the first FINISHED still advances immediately, with no pacing delay;
- an expired ongoing timer still aborts (and is not slowed down on the way out).

The interval is `runtime.poll.ongoing_interval_seconds`, reaching the states as
`comm_session.ongoing_poll_interval`. The tests set it directly on the stub
session — a small value keeps them fast while still proving the pacing.
"""

from __future__ import annotations

import time
import types
from pathlib import Path

import pytest

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.evcc.states.din_spec_states import (
    ChargeParameterDiscovery,
    ContractAuthentication,
)
from app.evcc.states.iso15118_2_states import Authorization
from app.shared.live_control import LiveControl
from app.shared.messages.din_spec.body import Body as BodyDIN
from app.shared.messages.din_spec.body import (
    ContractAuthenticationRes,
    ResponseCode,
)
from app.shared.messages.din_spec.header import MessageHeader as MessageHeaderDIN
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import EVSEProcessing, Protocol
from app.shared.messages.iso15118_2.body import AuthorizationRes, Body
from app.shared.messages.iso15118_2.body import ResponseCode as ResponseCodeV2
from app.shared.messages.iso15118_2.header import MessageHeader
from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from app.shared.messages.timeouts import Timeouts as TimeoutsShared
from app.shared.personality.loader import load_personality
from app.shared.states import Terminate
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession

PERSONALITIES_DIR = Path(__file__).resolve().parents[4] / "personalities"

# Short enough to keep the suite fast, long enough that a hot spin would blow
# straight past the bounds asserted below.
POLL_INTERVAL = 0.05


def _din_session(poll_interval: float) -> StubCommSession:
    """A DIN EVCC session sitting in ContractAuthentication, timer running."""
    personality = load_personality(
        str(PERSONALITIES_DIR / "din-evcc-baseline.yaml"), "evcc"
    )
    config = EVCCConfig.from_personality(personality)
    session = StubCommSession(
        protocol=Protocol.DIN_SPEC_70121, session_id=bytes(1).hex()
    )
    session.config = config
    session.ev_controller = SimEVController(config)
    session.live_control = None
    session.selected_schedule = None
    session.ongoing_timer = -1
    session.ongoing_poll_interval = poll_interval
    session.writer = types.SimpleNamespace(get_extra_info=lambda _name: None)
    return session


def _din_res(session: StubCommSession, processing: EVSEProcessing):
    return V2GMessageDINSPEC(
        header=MessageHeaderDIN(session_id=session.session_id),
        body=BodyDIN(
            contract_authentication_res=ContractAuthenticationRes(
                response_code=ResponseCode.OK,
                evse_processing=processing,
            )
        ),
    )


def _iso2_session(poll_interval: float) -> StubCommSession:
    session = StubCommSession(protocol=Protocol.ISO_15118_2, session_id=bytes(1).hex())
    session.live_control = LiveControl()
    session.ongoing_timer = -1
    session.ongoing_poll_interval = poll_interval
    session.writer = types.SimpleNamespace(get_extra_info=lambda _name: None)
    return session


def _iso2_ongoing_res(session: StubCommSession) -> V2GMessageV2:
    return V2GMessageV2(
        header=MessageHeader(session_id=session.session_id),
        body=Body(
            authorization_res=AuthorizationRes(
                response_code=ResponseCodeV2.OK,
                evse_processing=EVSEProcessing.ONGOING,
            )
        ),
    )


# -- DIN ContractAuthentication (the loop the issue was raised against) ------


@pytest.mark.asyncio
async def test_din_ongoing_poll_is_rate_bounded(exi_codec):
    """Repeated ONGOING responses yield a bounded request count per window.

    This is the busy-loop guard: an unpaced EVCC re-sent ~190 ContractAuthen-
    ticationReq per second. With a 50 ms cadence a 0.3 s window admits at most
    ~6 requests, so anything near a hot spin fails loudly here.
    """
    session = _din_session(POLL_INTERVAL)
    peer = ScriptedPeer(session, start_state=ContractAuthentication)

    window = 0.3
    deadline = time.monotonic() + window
    requests = 0
    while time.monotonic() < deadline:
        result = await peer.feed(_din_res(session, EVSEProcessing.ONGOING))
        # next_state None means "stay in ContractAuthentication and poll again".
        assert result.next_state is None
        assert result.outbound_v2gtp is not None
        requests += 1

    assert requests >= 1
    assert requests <= int(window / POLL_INTERVAL) + 2


@pytest.mark.asyncio
async def test_din_finished_advances_without_pacing_delay(exi_codec):
    """The first FINISHED advances immediately — pacing costs it nothing."""
    session = _din_session(poll_interval=1.0)
    peer = ScriptedPeer(session, start_state=ContractAuthentication)

    started = time.monotonic()
    result = await peer.feed(_din_res(session, EVSEProcessing.FINISHED))
    elapsed = time.monotonic() - started

    assert result.next_state is ChargeParameterDiscovery
    assert elapsed < 0.5  # nowhere near the 1.0 s poll interval


@pytest.mark.asyncio
async def test_din_zero_interval_disables_pacing(exi_codec):
    """A 0 s interval keeps the un-paced (hot) re-send available for probing."""
    session = _din_session(poll_interval=0.0)
    peer = ScriptedPeer(session, start_state=ContractAuthentication)

    started = time.monotonic()
    result = await peer.feed(_din_res(session, EVSEProcessing.ONGOING))
    elapsed = time.monotonic() - started

    assert result.next_state is None
    assert elapsed < POLL_INTERVAL


@pytest.mark.asyncio
async def test_din_expired_ongoing_timer_still_aborts(exi_codec):
    """The V2G_SECC_SEQUENCE_TIMEOUT abort is unchanged — and not paced."""
    session = _din_session(poll_interval=1.0)
    session.live_control = LiveControl()  # stall_charge_loop False
    session.ongoing_timer = time.time() - (
        TimeoutsShared.V2G_SECC_SEQUENCE_TIMEOUT + 100
    )
    peer = ScriptedPeer(session, start_state=ContractAuthentication)

    started = time.monotonic()
    result = await peer.feed(_din_res(session, EVSEProcessing.ONGOING))
    elapsed = time.monotonic() - started

    assert result.next_state is Terminate
    assert session.stop_reason is not None
    assert elapsed < 0.5  # the abort path never sleeps


@pytest.mark.asyncio
async def test_din_stall_mode_keeps_polling_and_is_paced(exi_codec):
    """Stall-mode timer defeat survives pacing: it polls on, at the cadence."""
    session = _din_session(POLL_INTERVAL)
    session.live_control = LiveControl(stall_charge_loop=True)
    session.ongoing_timer = time.time() - (
        TimeoutsShared.V2G_SECC_SEQUENCE_TIMEOUT + 100
    )
    peer = ScriptedPeer(session, start_state=ContractAuthentication)

    started = time.monotonic()
    result = await peer.feed(_din_res(session, EVSEProcessing.ONGOING))
    elapsed = time.monotonic() - started

    assert result.next_state is None  # keeps polling, not Terminate
    assert session.stop_reason is None
    assert elapsed >= POLL_INTERVAL * 0.9


# -- ISO 15118-2 Authorization (same shape, same fix) -----------------------


@pytest.mark.asyncio
async def test_iso2_ongoing_authorization_is_paced(exi_codec):
    session = _iso2_session(POLL_INTERVAL)
    peer = ScriptedPeer(session, start_state=Authorization)

    started = time.monotonic()
    result = await peer.feed(_iso2_ongoing_res(session))
    elapsed = time.monotonic() - started

    assert result.next_state is Authorization  # still polling
    assert elapsed >= POLL_INTERVAL * 0.9
