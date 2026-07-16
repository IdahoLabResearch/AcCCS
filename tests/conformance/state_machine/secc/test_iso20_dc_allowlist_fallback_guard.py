"""Every ISO-20 DC SECC allowlist entry has a real builder fallback (empty tree).

ADR-0006 #83 (extended to ISO-20 DC in #98) makes the optional-field allowlist a
**standalone** statement of which required ISO-15118-20 DC SECC wire fields the
emulator produces on its own at runtime — so they may be omitted from the
message field tree. This test is the guard that the ISO-20 DC list cannot lie: it
drives the SECC ISO-20 states through `process_message()` (or, for the charge
loop, its `_build_dc_charge_loop_res()` builder) with an **empty-tree**
personality (`SECCPersonality()`), so every message is built purely from the
builders' computed values, then asserts each allowlisted leaf still populates. A
liar entry — a field claimed emulator-produced that the builder does *not* set —
would either fail message construction outright (the fields are Pydantic-
required) or surface here as a `None`.

The `header` envelope (SessionID, timestamp) is *not* on the allowlist — it is
excluded structurally from the completeness walk (`_ENVELOPE_ROOT_FIELDS`) as a
deferred/compute-only field, so it is not guarded here. The config-owned
`SessionSetupRes.EVSEID` is likewise not allowlisted (it is the tree value the
baseline pins), so it is not guarded here either.

The load-time behaviour of the check itself lives in
`tests/personality/test_completeness.py`; the DIN / ISO-2 counterparts are
`test_din_allowlist_fallback_guard.py` / `test_iso2_allowlist_fallback_guard.py`.
"""

from __future__ import annotations

from time import time

import pytest

from app.secc.controller.simulator import SimEVSEController
from app.secc.states.iso15118_20_states import (
    AuthorizationSetup,
    Authorization,
    DCCableCheck,
    DCChargeLoop,
    DCPreCharge,
    DCWeldingDetection,
    ScheduleExchange,
    ServiceDetail,
    ServiceDiscovery,
)
from app.shared.live_control import LiveControl
from app.shared.messages.enums import AuthEnum, ControlMode, Protocol, ServiceV20
from app.shared.messages.iso15118_20.common_messages import (
    AuthorizationReq,
    AuthorizationSetupReq,
    DynamicScheduleExchangeReqParams,
    EIMAuthReqParams,
    Parameter,
    ParameterSet,
    ScheduleExchangeReq,
    SelectedEnergyService,
    ServiceDetailReq,
    ServiceDiscoveryReq,
)
from app.shared.messages.iso15118_20.common_types import (
    MessageHeader,
    Processing,
    RationalNumber,
)
from app.shared.messages.iso15118_20.dc import (
    DCCableCheckReq,
    DCPreChargeReq,
    DCWeldingDetectionReq,
)
from app.shared.personality.completeness import allowlist_for
from app.shared.personality.model import SECCPersonality
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession

_ISO20_DC = "ISO_15118_20_DC"


def _resolve(obj, path):
    cursor = obj
    for name in path:
        if cursor is None:
            return None
        cursor = getattr(cursor, name, None)
    return cursor


def _allow(message_name):
    return allowlist_for("secc", _ISO20_DC)[message_name]


def _assert_populated(res, message_name, paths):
    missing = [
        f"{message_name} -> {' -> '.join(p)}"
        for p in paths
        if _resolve(res, p) is None
    ]
    assert not missing, (
        f"ISO-20 DC SECC allowlist entries not populated by the empty-tree "
        f"builder: {missing}"
    )


def _secc_session() -> StubCommSession:
    from app.secc.secc_settings import Config
    from app.shared.personality.model import Runtime

    personality = SECCPersonality()
    controller = SimEVSEController(personality=personality, live_control=LiveControl())
    controller.set_selected_protocol(Protocol.ISO_15118_20_DC)
    session = StubCommSession(
        protocol=Protocol.ISO_15118_20_DC, session_id=bytes(1).hex()
    )
    session.evse_controller = controller
    session.config = Config.from_personality(personality, Runtime())
    session.selected_auth_option = AuthEnum.EIM
    session.matched_services_v20 = []
    session.offered_auth_options = []
    session.selected_energy_service = None
    session.control_mode = ControlMode.DYNAMIC
    return session


def _hdr(session) -> MessageHeader:
    return MessageHeader(session_id=session.session_id, timestamp=int(time()))


def _rn(value: int) -> RationalNumber:
    return RationalNumber.get_rational_repr(value)


# ---------------------------------------------------------------------------
# Each allowlisted message, built from an empty-tree personality
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authorization_setup_res_allowlist_populates(exi_codec):
    session = _secc_session()
    peer = ScriptedPeer(session, AuthorizationSetup)
    res = (await peer.feed(AuthorizationSetupReq(header=_hdr(session)))).outbound_msg
    _assert_populated(res, "AuthorizationSetupRes", _allow("AuthorizationSetupRes"))


@pytest.mark.asyncio
async def test_authorization_res_allowlist_populates(exi_codec):
    session = _secc_session()
    peer = ScriptedPeer(session, Authorization)
    req = AuthorizationReq(
        header=_hdr(session),
        selected_auth_service=AuthEnum.EIM,
        eim_params=EIMAuthReqParams(),
    )
    res = (await peer.feed(req)).outbound_msg
    _assert_populated(res, "AuthorizationRes", _allow("AuthorizationRes"))


@pytest.mark.asyncio
async def test_service_discovery_res_allowlist_populates(exi_codec):
    session = _secc_session()
    peer = ScriptedPeer(session, ServiceDiscovery)
    res = (await peer.feed(ServiceDiscoveryReq(header=_hdr(session)))).outbound_msg
    _assert_populated(res, "ServiceDiscoveryRes", _allow("ServiceDiscoveryRes"))


@pytest.mark.asyncio
async def test_service_detail_res_allowlist_populates(exi_codec):
    session = _secc_session()
    peer = ScriptedPeer(session, ServiceDetail)
    req = ServiceDetailReq(header=_hdr(session), service_id=ServiceV20.DC.id)
    res = (await peer.feed(req)).outbound_msg
    _assert_populated(res, "ServiceDetailRes", _allow("ServiceDetailRes"))


@pytest.mark.asyncio
async def test_schedule_exchange_res_allowlist_populates(exi_codec):
    session = _secc_session()
    # ScheduleExchange consults selected_energy_service.service for next-state
    # routing after the Res is built.
    session.selected_energy_service = SelectedEnergyService(
        service=ServiceV20.DC_BPT,
        is_free=False,
        parameter_set=ParameterSet(
            id=1, parameters=[Parameter(name="ControlMode", int_value=2)]
        ),
    )
    peer = ScriptedPeer(session, ScheduleExchange)
    req = ScheduleExchangeReq(
        header=_hdr(session),
        max_supporting_points=1024,
        dynamic_params=DynamicScheduleExchangeReqParams(
            departure_time=3600,
            ev_target_energy_request=_rn(30000),
            ev_max_energy_request=_rn(40000),
            ev_min_energy_request=_rn(0),
        ),
    )
    res = (await peer.feed(req)).outbound_msg
    _assert_populated(res, "ScheduleExchangeRes", _allow("ScheduleExchangeRes"))


@pytest.mark.asyncio
async def test_dc_cable_check_res_allowlist_populates(exi_codec):
    session = _secc_session()
    peer = ScriptedPeer(session, DCCableCheck)
    res = (await peer.feed(DCCableCheckReq(header=_hdr(session)))).outbound_msg
    _assert_populated(res, "DCCableCheckRes", _allow("DCCableCheckRes"))


@pytest.mark.asyncio
async def test_dc_pre_charge_res_allowlist_populates(exi_codec):
    session = _secc_session()
    peer = ScriptedPeer(session, DCPreCharge)
    req = DCPreChargeReq(
        header=_hdr(session),
        ev_processing=Processing.ONGOING,
        ev_present_voltage=_rn(400),
        ev_target_voltage=_rn(400),
    )
    res = (await peer.feed(req)).outbound_msg
    _assert_populated(res, "DCPreChargeRes", _allow("DCPreChargeRes"))


@pytest.mark.asyncio
async def test_dc_welding_detection_res_allowlist_populates(exi_codec):
    session = _secc_session()
    peer = ScriptedPeer(session, DCWeldingDetection)
    req = DCWeldingDetectionReq(header=_hdr(session), ev_processing=Processing.ONGOING)
    res = (await peer.feed(req)).outbound_msg
    _assert_populated(res, "DCWeldingDetectionRes", _allow("DCWeldingDetectionRes"))


@pytest.mark.asyncio
async def test_dc_charge_loop_res_allowlist_populates(exi_codec):
    # The charge loop's inbound processing mutates data contexts and sends a
    # charging command; the allowlisted leaves come from its Res *builder*, so
    # exercise that directly with a DC-BPT / Dynamic selection — the same seam
    # the state uses, minus the req plumbing.
    session = _secc_session()
    session.selected_energy_service = SelectedEnergyService(
        service=ServiceV20.DC_BPT,
        is_free=False,
        parameter_set=ParameterSet(
            id=1, parameters=[Parameter(name="ControlMode", int_value=2)]
        ),
    )
    state = DCChargeLoop(session)
    res = await state._build_dc_charge_loop_res(meter_info_requested=False)
    _assert_populated(res, "DCChargeLoopRes", _allow("DCChargeLoopRes"))
