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
from app.evcc.states import evcc_state as evcc_state_module
from app.evcc.states import iso15118_20_states as iso20_states
from app.evcc.states.din_spec_states import CableCheck as CableCheckDIN
from app.evcc.states.din_spec_states import (
    ChargeParameterDiscovery,
    ContractAuthentication,
)
from app.evcc.states.iso15118_2_states import Authorization
from app.evcc.states.iso15118_2_states import CableCheck as CableCheckV2
from app.evcc.states.iso15118_2_states import (
    ChargeParameterDiscovery as ChargeParameterDiscoveryV2,
)
from app.evcc.states.iso15118_20_states import Authorization as Iso20Authorization
from app.evcc.states.iso15118_20_states import DCCableCheck, ScheduleExchange
from app.shared.live_control import LiveControl
from app.shared.messages.datatypes import DCEVSEStatus, DCEVSEStatusCode
from app.shared.messages.datatypes import EVSENotification as EVSENotificationV2
from app.shared.messages.din_spec.body import Body as BodyDIN
from app.shared.messages.din_spec.body import CableCheckRes as CableCheckResDIN
from app.shared.messages.din_spec.body import (
    ChargeParameterDiscoveryRes as ChargeParameterDiscoveryResDIN,
)
from app.shared.messages.din_spec.body import (
    ContractAuthenticationRes,
    ResponseCode,
)
from app.shared.messages.din_spec.header import MessageHeader as MessageHeaderDIN
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import (
    AuthEnum,
    EVSEProcessing,
    IsolationLevel,
    Protocol,
)
from app.shared.messages.iso15118_2.body import AuthorizationRes, Body
from app.shared.messages.iso15118_2.body import CableCheckRes as CableCheckResV2
from app.shared.messages.iso15118_2.body import (
    ChargeParameterDiscoveryRes as ChargeParameterDiscoveryResV2,
)
from app.shared.messages.iso15118_2.body import ResponseCode as ResponseCodeV2
from app.shared.messages.iso15118_2.header import MessageHeader
from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from app.shared.messages.iso15118_20.common_messages import (
    AuthorizationReq as AuthorizationReqV20,
)
from app.shared.messages.iso15118_20.common_messages import (
    AuthorizationRes as AuthorizationResV20,
)
from app.shared.messages.iso15118_20.common_messages import (
    EIMAuthReqParams,
    ScheduledScheduleExchangeReqParams,
    ScheduleExchangeReq,
    ScheduleExchangeRes,
)
from app.shared.messages.iso15118_20.common_types import (
    MessageHeader as MessageHeaderV20,
)
from app.shared.messages.iso15118_20.common_types import Processing as ProcessingV20
from app.shared.messages.iso15118_20.common_types import (
    ResponseCode as ResponseCodeV20,
)
from app.shared.messages.iso15118_20.dc import DCCableCheckRes
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


# -- ISO 15118-20 header timestamp is sampled at send time (issue #91) -------
#
# The ISO-20 AuthorizationReq and DCCableCheckReq stamp `timestamp=int(time.
# time())` into their MessageHeader. Before #91 they were built above the
# pacing sleep, so every paced poll carried a header timestamp a full poll
# interval (>= one seconds-resolution tick) in the past. These tests drive a
# real paced re-send under a hand-cranked clock: the pacing sleep advances the
# clock, so a build *after* the sleep must read the later second.

# Fake-time seconds. Both are integral so `int()` at the header is exact, and
# the interval is a comfortable multiple of the header's 1 s resolution.
ISO20_CLOCK_START = 1_000_000.0
ISO20_POLL_INTERVAL = 5.0


class _FakeClock:
    """A hand-cranked stand-in for the `time` module the ISO-20 states read.

    The states only ever call `time.time()`; `_install_fake_clock` wires the
    pacing sleep to advance `now`, so a header built after the sleep reads a
    strictly later second than one built before it — the drift #91 removes.
    """

    def __init__(self, start: float) -> None:
        self.now = start

    def time(self) -> float:
        return self.now


def _install_fake_clock(monkeypatch, clock: _FakeClock) -> None:
    # The ISO-20 states read `time.time()`; the base state's pacing sleep is the
    # only `asyncio.sleep` reached on this path. Swapping both for fakes keeps
    # the test deterministic and instant while exercising the real ordering.
    monkeypatch.setattr(iso20_states, "time", clock)

    async def _advancing_sleep(delay: float) -> None:
        clock.now += delay

    monkeypatch.setattr(
        evcc_state_module,
        "asyncio",
        types.SimpleNamespace(sleep=_advancing_sleep),
    )


def _iso20_session(poll_interval: float = ISO20_POLL_INTERVAL) -> StubCommSession:
    session = StubCommSession(
        protocol=Protocol.ISO_15118_20_COMMON_MESSAGES, session_id=bytes(1).hex()
    )
    session.live_control = LiveControl()  # stall off; the timer never expires here
    session.ongoing_timer = -1  # fresh — the first poll starts it, no abort
    session.ongoing_poll_interval = poll_interval
    session.writer = types.SimpleNamespace(get_extra_info=lambda _name: None)
    return session


@pytest.mark.asyncio
async def test_iso20_authorization_poll_header_is_send_time(exi_codec, monkeypatch):
    """A paced ISO-20 AuthorizationReq stamps its header at send time (issue #91).

    With the build below the pacing sleep the header timestamp lands a full
    poll interval later than the receive-time sample the old ordering produced.
    """
    clock = _FakeClock(ISO20_CLOCK_START)
    _install_fake_clock(monkeypatch, clock)

    session = _iso20_session()
    session.authorization_req_message = AuthorizationReqV20(
        header=MessageHeaderV20(session_id=session.session_id, timestamp=1),
        selected_auth_service=AuthEnum.EIM,
        eim_params=EIMAuthReqParams(),
    )
    peer = ScriptedPeer(session, start_state=Iso20Authorization)

    result = await peer.feed(
        AuthorizationResV20(
            header=MessageHeaderV20(session_id=session.session_id, timestamp=1),
            response_code=ResponseCodeV20.OK,
            evse_processing=ProcessingV20.ONGOING,
        )
    )

    assert result.next_state is Iso20Authorization  # still polling
    timestamp = result.outbound_msg.header.timestamp
    assert timestamp == int(ISO20_CLOCK_START + ISO20_POLL_INTERVAL)  # send time
    assert timestamp != int(ISO20_CLOCK_START)  # not the receive-time sample


@pytest.mark.asyncio
async def test_iso20_cable_check_poll_header_is_send_time(exi_codec, monkeypatch):
    """A paced ISO-20 DCCableCheckReq stamps its header at send time (issue #91)."""
    clock = _FakeClock(ISO20_CLOCK_START)
    _install_fake_clock(monkeypatch, clock)

    session = _iso20_session()
    peer = ScriptedPeer(session, start_state=DCCableCheck)

    result = await peer.feed(
        DCCableCheckRes(
            header=MessageHeaderV20(session_id=session.session_id, timestamp=1),
            response_code=ResponseCodeV20.OK,
            evse_processing=ProcessingV20.ONGOING,
        )
    )

    assert result.next_state is None  # stay in CableCheck and poll again
    timestamp = result.outbound_msg.header.timestamp
    assert timestamp == int(ISO20_CLOCK_START + ISO20_POLL_INTERVAL)  # send time
    assert timestamp != int(ISO20_CLOCK_START)  # not the receive-time sample


# -- All nine paced ONGOING loops wait the interval before re-sending (#92) ---
#
# `pace_ongoing_poll()` is awaited at nine EVCC ONGOING-poll sites, but only two
# had a dedicated pacing assertion (DIN ContractAuthentication and ISO-2
# Authorization, above). Issue #92: the other seven were unguarded — deleting a
# single `await self.pace_ongoing_poll()` from, say, DIN CableCheck or ISO-20
# ScheduleExchange left the suite green. The two ISO-20 sites *looked* covered,
# but only incidentally: the #91 header-timestamp tests above advance a fake
# clock *through* the sleep, which is a guard on the header, not on pacing.
#
# The table below names all nine sites and asserts each one actually sleeps the
# configured interval on its first ONGOING response — real wall-clock, no fake
# clock — so removing any one pace call fails here. The DIN/ISO-2 tests above
# keep their richer assertions (rate bounding, the FINISHED fast-path, the
# abort path); this table is the completeness guard across the whole set.
#
# Each state's "still polling" signal differs and is mirrored, not assumed: the
# DIN and ISO-20 CableCheck-style loops re-send with `next_state is None`
# (`create_next_message(None, ...)`), while the ISO-2 and the ISO-20
# Authorization/ScheduleExchange loops self-transition back to their own state.


def _dc_evse_status() -> DCEVSEStatus:
    """A minimal healthy DC EVSE status — the shape both CableCheckRes flavors
    read unconditionally before branching on `evse_processing`."""
    return DCEVSEStatus(
        evse_notification=EVSENotificationV2.NONE,
        notification_max_delay=0,
        evse_isolation_status=IsolationLevel.VALID,
        evse_status_code=DCEVSEStatusCode.EVSE_READY,
    )


def _iso2_dc_session(poll_interval: float) -> StubCommSession:
    """An ISO 15118-2 DC EVCC session with a controller.

    ISO-2 ChargeParameterDiscovery and CableCheck build their re-send from the
    EV controller after the pacing sleep, so unlike the bare Authorization
    session they need one. Sourced from the shipped `iso2_eim_dc` personality.
    """
    personality = load_personality(
        str(PERSONALITIES_DIR / "iso2_eim_dc.yaml"), "evcc"
    )
    config = EVCCConfig.from_personality(personality)
    session = StubCommSession(protocol=Protocol.ISO_15118_2, session_id=bytes(1).hex())
    session.config = config
    session.ev_controller = SimEVController(config)
    session.live_control = LiveControl()
    session.selected_schedule = None
    session.ongoing_timer = -1
    session.ongoing_poll_interval = poll_interval
    session.writer = types.SimpleNamespace(get_extra_info=lambda _name: None)
    return session


def _iso20_auth_session(poll_interval: float) -> StubCommSession:
    session = _iso20_session(poll_interval)
    session.authorization_req_message = AuthorizationReqV20(
        header=MessageHeaderV20(session_id=session.session_id, timestamp=1),
        selected_auth_service=AuthEnum.EIM,
        eim_params=EIMAuthReqParams(),
    )
    return session


def _iso20_schedule_exchange_session(poll_interval: float) -> StubCommSession:
    session = _iso20_session(poll_interval)
    # The ONGOING branch re-sends this cached request verbatim.
    session.ongoing_schedule_exchange_req = ScheduleExchangeReq(
        header=MessageHeaderV20(session_id=session.session_id, timestamp=1),
        max_supporting_points=12,
        scheduled_params=ScheduledScheduleExchangeReqParams(),
    )
    return session


def _din_cpd_ongoing_res(session: StubCommSession) -> V2GMessageDINSPEC:
    return V2GMessageDINSPEC(
        header=MessageHeaderDIN(session_id=session.session_id),
        body=BodyDIN(
            charge_parameter_discovery_res=ChargeParameterDiscoveryResDIN(
                response_code=ResponseCode.OK,
                evse_processing=EVSEProcessing.ONGOING,
            )
        ),
    )


def _din_cable_check_ongoing_res(session: StubCommSession) -> V2GMessageDINSPEC:
    return V2GMessageDINSPEC(
        header=MessageHeaderDIN(session_id=session.session_id),
        body=BodyDIN(
            cable_check_res=CableCheckResDIN(
                response_code=ResponseCode.OK,
                dc_evse_status=_dc_evse_status(),
                evse_processing=EVSEProcessing.ONGOING,
            )
        ),
    )


def _iso2_cpd_ongoing_res(session: StubCommSession) -> V2GMessageV2:
    return V2GMessageV2(
        header=MessageHeader(session_id=session.session_id),
        body=Body(
            charge_parameter_discovery_res=ChargeParameterDiscoveryResV2(
                response_code=ResponseCodeV2.OK,
                evse_processing=EVSEProcessing.ONGOING,
            )
        ),
    )


def _iso2_cable_check_ongoing_res(session: StubCommSession) -> V2GMessageV2:
    return V2GMessageV2(
        header=MessageHeader(session_id=session.session_id),
        body=Body(
            cable_check_res=CableCheckResV2(
                response_code=ResponseCodeV2.OK,
                dc_evse_status=_dc_evse_status(),
                evse_processing=EVSEProcessing.ONGOING,
            )
        ),
    )


def _iso20_auth_ongoing_res(session: StubCommSession) -> AuthorizationResV20:
    return AuthorizationResV20(
        header=MessageHeaderV20(session_id=session.session_id, timestamp=1),
        response_code=ResponseCodeV20.OK,
        evse_processing=ProcessingV20.ONGOING,
    )


def _iso20_schedule_exchange_ongoing_res(
    session: StubCommSession,
) -> ScheduleExchangeRes:
    return ScheduleExchangeRes(
        header=MessageHeaderV20(session_id=session.session_id, timestamp=1),
        response_code=ResponseCodeV20.OK,
        evse_processing=ProcessingV20.ONGOING,
    )


def _iso20_cable_check_ongoing_res(session: StubCommSession) -> DCCableCheckRes:
    return DCCableCheckRes(
        header=MessageHeaderV20(session_id=session.session_id, timestamp=1),
        response_code=ResponseCodeV20.OK,
        evse_processing=ProcessingV20.ONGOING,
    )


# (id, session factory, start state, ONGOING-response builder, expected next
# state). `next_state is None` means "self-loop and poll again"; a state class
# means the loop self-transitions back to itself.
_ONGOING_POLL_CASES = [
    (
        "din-contract-authentication",
        _din_session,
        ContractAuthentication,
        lambda s: _din_res(s, EVSEProcessing.ONGOING),
        None,
    ),
    (
        "din-charge-parameter-discovery",
        _din_session,
        ChargeParameterDiscovery,
        _din_cpd_ongoing_res,
        None,
    ),
    (
        "din-cable-check",
        _din_session,
        CableCheckDIN,
        _din_cable_check_ongoing_res,
        None,
    ),
    (
        "iso2-authorization",
        _iso2_session,
        Authorization,
        _iso2_ongoing_res,
        Authorization,
    ),
    (
        "iso2-charge-parameter-discovery",
        _iso2_dc_session,
        ChargeParameterDiscoveryV2,
        _iso2_cpd_ongoing_res,
        ChargeParameterDiscoveryV2,
    ),
    (
        "iso2-cable-check",
        _iso2_dc_session,
        CableCheckV2,
        _iso2_cable_check_ongoing_res,
        CableCheckV2,
    ),
    (
        "iso20-authorization",
        _iso20_auth_session,
        Iso20Authorization,
        _iso20_auth_ongoing_res,
        Iso20Authorization,
    ),
    (
        "iso20-schedule-exchange",
        _iso20_schedule_exchange_session,
        ScheduleExchange,
        _iso20_schedule_exchange_ongoing_res,
        ScheduleExchange,
    ),
    (
        "iso20-dc-cable-check",
        _iso20_session,
        DCCableCheck,
        _iso20_cable_check_ongoing_res,
        None,
    ),
]


@pytest.mark.parametrize(
    "make_session, start_state, make_ongoing_res, expected_next_state",
    [case[1:] for case in _ONGOING_POLL_CASES],
    ids=[case[0] for case in _ONGOING_POLL_CASES],
)
@pytest.mark.asyncio
async def test_ongoing_poll_waits_configured_interval(
    exi_codec, make_session, start_state, make_ongoing_res, expected_next_state
):
    """Each paced ONGOING loop sleeps the configured interval before re-sending.

    Removing that site's `await self.pace_ongoing_poll()` drops the elapsed time
    below the bound and fails this case — the guard #92 asks for.
    """
    session = make_session(POLL_INTERVAL)
    peer = ScriptedPeer(session, start_state=start_state)

    started = time.monotonic()
    result = await peer.feed(make_ongoing_res(session))
    elapsed = time.monotonic() - started

    assert result.next_state is expected_next_state  # still polling
    assert result.outbound_v2gtp is not None  # a re-send was queued
    assert elapsed >= POLL_INTERVAL * 0.9
