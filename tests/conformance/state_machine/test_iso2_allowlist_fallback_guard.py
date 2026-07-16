"""Every ISO-2 SECC allowlist entry has a real builder fallback (empty tree).

ADR-0006 #83 (extended to ISO-2 in #96) makes the optional-field allowlist a
**standalone** statement of which required ISO-15118-2 SECC wire fields the
emulator produces on its own at runtime — so they may be omitted from the
message field tree. This test is the guard that the ISO-2 list cannot lie: it
drives the SECC DC states through `process_message()` with an **empty-tree**
personality (`SECCPersonality()`), so every message is built purely from the
builders' computed values, then asserts each allowlisted leaf still populates. A
liar entry — a field claimed emulator-produced that the builder does *not* set —
would either fail message construction outright (the fields are Pydantic-
required) or surface here as a `None`.

The load-time behaviour of the check itself lives in
`tests/personality/test_completeness.py`; the DIN counterpart is
`test_din_allowlist_fallback_guard.py`.
"""

from __future__ import annotations

import pytest

from app.secc.controller.simulator import SimEVSEController
from app.secc.states.iso15118_2_states import (
    Authorization,
    CableCheck,
    ChargeParameterDiscovery,
    CurrentDemand,
    PreCharge,
    WeldingDetection,
)
from app.shared.live_control import LiveControl
from app.shared.messages.datatypes import (
    PVEVTargetCurrent,
    PVEVTargetVoltage,
)
from app.shared.messages.enums import (
    AuthEnum,
    DCEVErrorCode,
    EnergyTransferModeEnum,
    Protocol,
    UnitSymbol,
)
from app.shared.messages.iso15118_2.body import (
    AuthorizationReq,
    Body,
    CableCheckReq,
    ChargeParameterDiscoveryReq,
    CurrentDemandReq,
    PreChargeReq,
    WeldingDetectionReq,
)
from app.shared.messages.iso15118_2.datatypes import (
    DCEVChargeParameter,
    DCEVStatus,
    PVEVMaxCurrentLimit,
    PVEVMaxPowerLimit,
    PVEVMaxVoltageLimit,
)
from app.shared.messages.iso15118_2.header import MessageHeader
from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from app.shared.personality.completeness import allowlist_for
from app.shared.personality.model import SECCPersonality
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession


def _resolve(obj, path):
    cursor = obj
    for name in path:
        if cursor is None:
            return None
        cursor = getattr(cursor, name, None)
    return cursor


def _secc_session() -> StubCommSession:
    from app.secc.secc_settings import Config
    from app.shared.personality.model import Runtime

    personality = SECCPersonality()
    controller = SimEVSEController(personality=personality, live_control=LiveControl())
    controller.set_selected_protocol(Protocol.ISO_15118_2)
    session = StubCommSession(protocol=Protocol.ISO_15118_2, session_id=bytes(1).hex())
    session.evse_controller = controller
    session.config = Config.from_personality(personality, Runtime())
    session.selected_auth_option = AuthEnum.EIM_V2
    session.selected_charging_type_is_ac = False
    session.selected_schedule = 1
    session.contactor_status = None
    session.offered_schedules = []
    session.ev_session_context = _EVSessionContext()
    return session


class _EVSessionContext:
    """Minimal stand-in for the resumed-session context the states consult."""

    sa_schedule_tuple_id = None
    charge_service = None
    auth_options = None


def _hdr(session) -> MessageHeader:
    return MessageHeader(session_id=session.session_id)


def _dc_ev_status() -> DCEVStatus:
    return DCEVStatus(
        ev_ready=True, ev_error_code=DCEVErrorCode.NO_ERROR, ev_ress_soc=42
    )


def _assert_populated(res, message_name, paths):
    missing = [
        f"{message_name} -> {' -> '.join(p)}"
        for p in paths
        if _resolve(res, p) is None
    ]
    assert not missing, (
        f"ISO-2 SECC allowlist entries not populated by the empty-tree "
        f"builder: {missing}"
    )


# ---------------------------------------------------------------------------
# Each allowlisted DC message, built from an empty-tree personality
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authorization_res_allowlist_populates(exi_codec):
    session = _secc_session()
    peer = ScriptedPeer(session, Authorization)
    result = await peer.feed(
        V2GMessageV2(header=_hdr(session), body=Body(authorization_req=AuthorizationReq()))
    )
    res = result.outbound_msg.body.authorization_res
    _assert_populated(res, "AuthorizationRes", allowlist_for("secc", "ISO_15118_2")["AuthorizationRes"])


@pytest.mark.asyncio
async def test_charge_parameter_discovery_res_allowlist_populates(exi_codec):
    session = _secc_session()
    peer = ScriptedPeer(session, ChargeParameterDiscovery)
    req = ChargeParameterDiscoveryReq(
        requested_energy_mode=EnergyTransferModeEnum.DC_EXTENDED,
        dc_ev_charge_parameter=DCEVChargeParameter(
            dc_ev_status=_dc_ev_status(),
            ev_maximum_current_limit=PVEVMaxCurrentLimit(
                multiplier=0, value=200, unit=UnitSymbol.AMPERE
            ),
            ev_maximum_power_limit=PVEVMaxPowerLimit(
                multiplier=1, value=10000, unit=UnitSymbol.WATT
            ),
            ev_maximum_voltage_limit=PVEVMaxVoltageLimit(
                multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
            ),
        ),
    )
    result = await peer.feed(
        V2GMessageV2(header=_hdr(session), body=Body(charge_parameter_discovery_req=req))
    )
    res = result.outbound_msg.body.charge_parameter_discovery_res
    _assert_populated(
        res,
        "ChargeParameterDiscoveryRes",
        allowlist_for("secc", "ISO_15118_2")["ChargeParameterDiscoveryRes"],
    )


@pytest.mark.asyncio
async def test_cable_check_res_allowlist_populates(exi_codec):
    session = _secc_session()
    peer = ScriptedPeer(session, CableCheck)
    result = await peer.feed(
        V2GMessageV2(
            header=_hdr(session),
            body=Body(cable_check_req=CableCheckReq(dc_ev_status=_dc_ev_status())),
        )
    )
    res = result.outbound_msg.body.cable_check_res
    _assert_populated(res, "CableCheckRes", allowlist_for("secc", "ISO_15118_2")["CableCheckRes"])


@pytest.mark.asyncio
async def test_pre_charge_res_allowlist_populates(exi_codec):
    session = _secc_session()
    peer = ScriptedPeer(session, PreCharge)
    req = PreChargeReq(
        dc_ev_status=_dc_ev_status(),
        ev_target_voltage=PVEVTargetVoltage(multiplier=0, value=390, unit=UnitSymbol.VOLTAGE),
        ev_target_current=PVEVTargetCurrent(multiplier=0, value=1, unit=UnitSymbol.AMPERE),
    )
    result = await peer.feed(V2GMessageV2(header=_hdr(session), body=Body(pre_charge_req=req)))
    res = result.outbound_msg.body.pre_charge_res
    _assert_populated(res, "PreChargeRes", allowlist_for("secc", "ISO_15118_2")["PreChargeRes"])


@pytest.mark.asyncio
async def test_current_demand_res_allowlist_populates(exi_codec):
    session = _secc_session()
    peer = ScriptedPeer(session, CurrentDemand)
    req = CurrentDemandReq(
        dc_ev_status=_dc_ev_status(),
        ev_target_current=PVEVTargetCurrent(multiplier=0, value=60, unit=UnitSymbol.AMPERE),
        ev_target_voltage=PVEVTargetVoltage(multiplier=0, value=390, unit=UnitSymbol.VOLTAGE),
        charging_complete=False,
    )
    result = await peer.feed(V2GMessageV2(header=_hdr(session), body=Body(current_demand_req=req)))
    res = result.outbound_msg.body.current_demand_res
    _assert_populated(
        res, "CurrentDemandRes", allowlist_for("secc", "ISO_15118_2")["CurrentDemandRes"]
    )


@pytest.mark.asyncio
async def test_welding_detection_res_allowlist_populates(exi_codec):
    session = _secc_session()
    peer = ScriptedPeer(session, WeldingDetection)
    result = await peer.feed(
        V2GMessageV2(
            header=_hdr(session),
            body=Body(welding_detection_req=WeldingDetectionReq(dc_ev_status=_dc_ev_status())),
        )
    )
    res = result.outbound_msg.body.welding_detection_res
    _assert_populated(
        res, "WeldingDetectionRes", allowlist_for("secc", "ISO_15118_2")["WeldingDetectionRes"]
    )
