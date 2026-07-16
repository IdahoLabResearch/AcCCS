"""Every ISO-20 AC EVCC allowlist entry has a real builder fallback (empty tree).

ADR-0006 #83 (extended to the ISO-20 AC EVCC in #101) makes the optional-field
allowlist a **standalone** statement of which required ISO-15118-20 AC EVCC wire
fields the emulator produces on its own at runtime — so they may be omitted from
the message field tree. This test is the guard that the ISO-20 AC EVCC list
cannot lie: it drives the EVCC ISO-20 states through `process_message()` (or, for
the messages built by a helper, that builder) with an **empty-tree** personality
(`message_field_tree` unset) negotiated as ``ISO_15118_20_AC``, so every `*Req` is
built purely from the builders' computed values, then asserts each allowlisted
leaf still populates. A liar entry — a field claimed emulator-produced that the
builder does *not* set — would either fail message construction outright (the
fields are Pydantic-required) or surface here as a `None`.

The vehicle-side mirror of the ISO-20 AC SECC guard (#100) and the AC sibling of
the ISO-20 DC EVCC guard (#99): the common ``*Req`` are the same models keyed to
the ``ISO_15118_20_AC`` allowlist table so *its* entries cannot lie, plus the one
AC-specific entry — ``ACChargeLoopReq.MeterInfoRequested`` (the DC guard's
DC-specific analogue). The AC-specific ``ACChargeParameterDiscoveryReq`` carries
no message-specific entry (its only body leaf is the Optional
``AC_CPDReqEnergyTransferMode`` sub-model, which the baseline pins in the tree), so
— like the DC guard's treatment of ``DCChargeParameterDiscoveryReq`` — it is not
driven here.

The `header` envelope (SessionID, timestamp, signature) is *not* on the allowlist
— it is excluded structurally from the completeness walk (`_ENVELOPE_ROOT_FIELDS`)
as a deferred/compute-only field, so it is not guarded here. `SessionSetupReq` is
built in `sap_states` (the SupportedAppProtocol handshake), before this state
seam, so — as on the ISO-2 / DC EVCC guards — its lone allowlisted leaf (EVCCID,
the NIC MAC) is not driven here; the E2E covers it end to end. `CertificateInstall-
ationReq` is PnC-only and carries no allowlist entry (the EIM baseline never
sources it), so it is not driven either.

The load-time behaviour of the check itself lives in
`tests/personality/test_completeness.py`; the SECC counterpart is
`tests/conformance/state_machine/secc/test_iso20_ac_allowlist_fallback_guard.py`.
"""

from __future__ import annotations

from time import time

import pytest

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.evcc.states.iso15118_20_states import (
    ACChargeParameterDiscovery,
    AuthorizationSetup,
    PowerDelivery,
    ServiceDetail,
    ServiceDiscovery,
)
from app.shared.messages.enums import AuthEnum, ControlMode, Protocol, ServiceV20
from app.shared.messages.iso15118_20.common_messages import (
    AuthorizationSetupRes,
    ChargeProgress,
    ChargingSession,
    DynamicScheduleExchangeResParams,
    EIMAuthSetupResParams,
    ParameterSet,
    PowerDeliveryRes,
    ScheduleExchangeRes,
    SelectedEnergyService,
    Service,
    ServiceDiscoveryRes,
    ServiceList,
)
from app.shared.messages.iso15118_20.common_types import (
    MessageHeader,
    Processing,
    RationalNumber,
)
from app.shared.personality.completeness import allowlist_for
from app.shared.personality.model import EVCCPersonality
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession

_ISO20_AC = "ISO_15118_20_AC"


def _resolve(obj, path):
    cursor = obj
    for name in path:
        if cursor is None:
            return None
        cursor = getattr(cursor, name, None)
    return cursor


def _allow(message_name):
    return allowlist_for("evcc", _ISO20_AC)[message_name]


def _assert_populated(req, message_name, paths):
    missing = [
        f"{message_name} -> {' -> '.join(p)}"
        for p in paths
        if _resolve(req, p) is None
    ]
    assert not missing, (
        f"ISO-20 AC EVCC allowlist entries not populated by the empty-tree "
        f"builder: {missing}"
    )


def _evcc_session() -> StubCommSession:
    """An empty-tree EVCC ISO-20 AC session at the state-machine seam.

    The personality is empty-*tree* (no ``message_field_tree``) so every wire
    field is builder-produced — but it advertises the AC energy service so the
    ISO-20 AC path (which the default DC personality would not take) is driven.
    """
    personality = EVCCPersonality.model_validate(
        {"capabilities": {"supported_energy_services": ["AC"]}}
    )
    config = EVCCConfig.from_personality(personality)
    session = StubCommSession(
        protocol=Protocol.ISO_15118_20_AC, session_id=bytes(1).hex()
    )
    session.config = config
    session.ev_controller = SimEVController(config)
    session.live_control = None
    session.matched_services_v20 = []
    session.service_details_to_request = []
    session.selected_vas_list_v20 = []
    session.selected_energy_service = None
    session.selected_charging_type_is_ac = True
    session.control_mode = ControlMode.DYNAMIC
    session.service_renegotiation_supported = False
    session.renegotiation_requested = False
    session.charging_session_stop_v20 = None
    session.ev_processing = Processing.FINISHED
    session.ongoing_timer = -1
    session.authorization_req_message = None
    session.schedule_exchange_res = None
    return session


def _hdr(session) -> MessageHeader:
    return MessageHeader(session_id=session.session_id, timestamp=int(time()))


def _ac_service() -> SelectedEnergyService:
    return SelectedEnergyService(
        service=ServiceV20.AC,
        is_free=False,
        parameter_set=ParameterSet(id=1, parameters=[]),
    )


# ---------------------------------------------------------------------------
# State-driven messages (fed a scripted SECC *Res, capture the emitted *Req)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authorization_req_allowlist_populates(exi_codec):
    session = _evcc_session()
    peer = ScriptedPeer(session, AuthorizationSetup)
    res = AuthorizationSetupRes(
        header=_hdr(session),
        response_code="OK",
        auth_services=[AuthEnum.EIM],
        cert_install_service=False,
        eim_as_res=EIMAuthSetupResParams(),
    )
    req = (await peer.feed(res)).outbound_msg
    _assert_populated(req, "AuthorizationReq", _allow("AuthorizationReq"))


@pytest.mark.asyncio
async def test_service_detail_req_allowlist_populates(exi_codec):
    # ServiceDiscovery matches the SECC's advertised energy services against the
    # EVCC's supported set (AC here) and pops a ServiceID into the emitted
    # ServiceDetailReq — the runtime echo the allowlist covers.
    session = _evcc_session()
    peer = ScriptedPeer(session, ServiceDiscovery)
    res = ServiceDiscoveryRes(
        header=_hdr(session),
        response_code="OK",
        service_renegotiation_supported=False,
        energy_service_list=ServiceList(
            services=[Service(service_id=ServiceV20.AC.id, free_service=False)]
        ),
    )
    req = (await peer.feed(res)).outbound_msg
    _assert_populated(req, "ServiceDetailReq", _allow("ServiceDetailReq"))


@pytest.mark.asyncio
async def test_power_delivery_req_allowlist_populates(exi_codec, monkeypatch):
    # PowerDeliveryReq's EVProcessing / ChargeProgress come from the shared
    # `create_new_power_delivery_req` builder (reached via PowerDelivery with
    # ev_processing ONGOING). `process_dynamic_se_params` gates readiness on
    # `random`, so pin the not-ready branch to make this guard deterministic (the
    # ready branch's #104 type bug is fixed; the pin now only removes the
    # randomness). Both branches set `ev_processing` + `charge_progress`.
    session = _evcc_session()
    session.selected_energy_service = _ac_service()
    session.ev_processing = Processing.ONGOING
    session.schedule_exchange_res = ScheduleExchangeRes(
        header=_hdr(session),
        response_code="OK",
        evse_processing=Processing.FINISHED,
        dynamic_params=DynamicScheduleExchangeResParams(),
        go_to_pause=False,
    )

    async def _not_ready(dynamic_params, pause):
        return None, ChargeProgress.START

    monkeypatch.setattr(session.ev_controller, "process_dynamic_se_params", _not_ready)
    peer = ScriptedPeer(session, PowerDelivery)
    req = (
        await peer.feed(PowerDeliveryRes(header=_hdr(session), response_code="OK"))
    ).outbound_msg
    _assert_populated(req, "PowerDeliveryReq", _allow("PowerDeliveryReq"))


@pytest.mark.asyncio
async def test_ac_charge_loop_req_allowlist_populates(exi_codec):
    # PowerDelivery with ev_processing FINISHED and no stop pending routes into the
    # AC charge loop, emitting ACChargeLoopReq — the MeterInfoRequested the
    # allowlist covers (a constant `False` the builder always sets).
    session = _evcc_session()
    session.selected_energy_service = _ac_service()
    session.ev_processing = Processing.FINISHED
    session.charging_session_stop_v20 = None
    peer = ScriptedPeer(session, PowerDelivery)
    pdr = PowerDeliveryRes(header=_hdr(session), response_code="OK")
    req = (await peer.feed(pdr)).outbound_msg
    assert type(req).__name__ == "ACChargeLoopReq", (
        f"PowerDelivery did not emit an ACChargeLoopReq: got {type(req).__name__}"
    )
    _assert_populated(req, "ACChargeLoopReq", _allow("ACChargeLoopReq"))


@pytest.mark.asyncio
async def test_session_stop_req_allowlist_populates(exi_codec):
    # PowerDelivery with a TERMINATE stop pending emits SessionStopReq (the AC path
    # skips the DC WeldingDetection detour) — the ChargingSession the allowlist
    # covers.
    session = _evcc_session()
    session.selected_energy_service = _ac_service()
    session.ev_processing = Processing.FINISHED
    session.charging_session_stop_v20 = ChargingSession.TERMINATE
    peer = ScriptedPeer(session, PowerDelivery)
    pdr = PowerDeliveryRes(header=_hdr(session), response_code="OK")
    req = (await peer.feed(pdr)).outbound_msg
    assert type(req).__name__ == "SessionStopReq", (
        f"PowerDelivery did not emit a SessionStopReq: got {type(req).__name__}"
    )
    _assert_populated(req, "SessionStopReq", _allow("SessionStopReq"))


# ---------------------------------------------------------------------------
# Builder-driven messages (the leaves come from a *Req helper, not a *Res)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_schedule_exchange_req_allowlist_populates(exi_codec):
    session = _evcc_session()
    session.selected_energy_service = _ac_service()
    req = await ACChargeParameterDiscovery(session).build_schedule_exchange_request()
    _assert_populated(req, "ScheduleExchangeReq", _allow("ScheduleExchangeReq"))


@pytest.mark.asyncio
async def test_service_selection_req_allowlist_populates(exi_codec):
    session = _evcc_session()
    session.selected_energy_service = _ac_service()
    req = await ServiceDetail(session).build_service_selection_req()
    _assert_populated(req, "ServiceSelectionReq", _allow("ServiceSelectionReq"))


def test_meter_info_requested_is_a_real_false_not_missing(exi_codec):
    # `meter_info_requested` is allowlisted and the builder always sets it to the
    # constant False; guard that the entry is present (a `None` at the charge-loop
    # build site would be the liar case the allowlist must not hide). Covered
    # structurally by the charge-loop test above, but asserted explicitly because
    # `False` is falsy.
    assert ("meter_info_requested",) in _allow("ACChargeLoopReq")
