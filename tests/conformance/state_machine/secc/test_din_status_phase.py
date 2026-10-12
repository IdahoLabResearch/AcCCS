"""DIN SECC status values follow the spec's phase rules (issue #140, SC-070/071).

- An ONGOING CableCheckRes reports Invalid / EVSE_IsolationMonitoringActive and
  the completing one Valid / EVSE_Ready, even with an empty message field tree
  (the builder, not only the baseline personality, is phase-correct).
- Every DIN FAILED-response template encodes with EVSENotification None —
  DIN SPEC 70121 [V2G-DC-500] fixes the notification to None.
- CurrentDemandRes.EVSECurrentLimitAchieved reflects the charger's advertised
  maximum against the EV's requested current, not the EV's ChargingComplete.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.secc.controller.simulator import SimEVSEController
from app.secc.failed_responses import init_failed_responses_din_spec_70121
from app.secc.states.din_spec_states import CableCheck, CurrentDemand
from app.shared.exi_codec import EXI
from app.shared.messages.datatypes import (
    PVEVTargetCurrentDin,
    PVEVTargetVoltageDin,
)
from app.shared.messages.din_spec.body import Body, CableCheckReq, CurrentDemandReq
from app.shared.messages.din_spec.datatypes import (
    DCEVSEStatusCode,
    DCEVStatus,
    EVSENotification,
)
from app.shared.messages.din_spec.header import MessageHeader
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import (
    DCEVErrorCode,
    EVSEProcessing,
    IsolationLevel,
    Namespace,
    Protocol,
    UnitSymbol,
)
from app.shared.personality.loader import load_personality
from tests.conformance.state_machine.harness import (
    ScriptedPeer,
    StubCommSession,
    StubWriter,
)

PERSONALITIES_DIR = Path(__file__).resolve().parents[4] / "personalities"


def _session(personality_file: str) -> StubCommSession:
    from app.secc.secc_settings import Config
    from app.shared.personality.model import Runtime

    personality = load_personality(str(PERSONALITIES_DIR / personality_file), "secc")
    session = StubCommSession(
        protocol=Protocol.DIN_SPEC_70121, session_id=bytes(1).hex()
    )
    session.evse_controller = SimEVSEController(personality=personality)
    session.evse_controller.set_selected_protocol(Protocol.DIN_SPEC_70121)
    session.config = Config.from_personality(personality, Runtime())
    session.writer = StubWriter()
    session.failed_responses_din_spec = init_failed_responses_din_spec_70121()
    return session


def _dc_ev_status() -> DCEVStatus:
    return DCEVStatus(
        ev_ready=True, ev_error_code=DCEVErrorCode.NO_ERROR, ev_ress_soc=42
    )


def _decode(result):
    payload = result.outbound_v2gtp.payload
    return EXI().from_exi_document(payload, Namespace.DIN_MSG_DEF).body.get_message()


@pytest.mark.asyncio
async def test_ongoing_cable_check_reports_monitoring_active_with_empty_tree(
    exi_codec,
):
    # default-secc ships an empty message field tree: every status leaf on the
    # wire is the builder's own value.
    session = _session("default-secc.yaml")
    hdr = MessageHeader(session_id=session.session_id)
    req = V2GMessageDINSPEC(
        header=hdr,
        body=Body(cable_check_req=CableCheckReq(dc_ev_status=_dc_ev_status())),
    )
    cc = ScriptedPeer(session, CableCheck)

    res = _decode(await cc.feed(req))
    assert res.evse_processing == EVSEProcessing.ONGOING
    assert res.dc_evse_status.evse_isolation_status == IsolationLevel.INVALID
    assert (
        res.dc_evse_status.evse_status_code
        == DCEVSEStatusCode.EVSE_ISOLATION_MONITORING_ACTIVE
    )

    res = _decode(await cc.feed(req))
    assert res.evse_processing == EVSEProcessing.FINISHED
    assert res.dc_evse_status.evse_isolation_status == IsolationLevel.VALID
    assert res.dc_evse_status.evse_status_code == DCEVSEStatusCode.EVSE_READY


def _body_field_for(res) -> str:
    """The Body slot (an Optional[<message type>] field) that holds `res`."""
    return next(
        name
        for name, info in Body.model_fields.items()
        if isinstance(res, info.annotation.__args__[0])
    )


@pytest.mark.parametrize(
    "req_type",
    list(init_failed_responses_din_spec_70121()),
    ids=lambda t: t.__name__,
)
def test_din_failed_template_round_trips_without_notification(exi_codec, req_type):
    # Templates without a DC_EVSEStatus (SessionSetupRes, ...) carry no
    # notification; they still have to encode.
    template = init_failed_responses_din_spec_70121()[req_type]
    message = V2GMessageDINSPEC(
        header=MessageHeader(session_id=bytes(1).hex()),
        body=Body(**{_body_field_for(template): template}),
    )
    exi = EXI().to_exi_document(message, Namespace.DIN_MSG_DEF)
    decoded = EXI().from_exi_document(exi, Namespace.DIN_MSG_DEF).body.get_message()

    status = getattr(decoded, "dc_evse_status", None)
    if status is None and getattr(decoded, "dc_charge_parameter", None):
        status = decoded.dc_charge_parameter.dc_evse_status
    if status is not None:
        assert status.evse_notification == EVSENotification.NONE


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "requested_a, expected",
    [(10, False), (59, False), (60, True), (75, True)],
)
async def test_current_limit_achieved_tracks_advertised_maximum(
    requested_a, expected
):
    # din-secc-baseline advertises EVSEMaximumCurrentLimit 60 A.
    session = _session("din-secc-baseline.yaml")
    controller = session.evse_controller
    controller.ev_data_context.target_current = requested_a
    assert await controller.is_evse_current_limit_achieved() is expected


@pytest.mark.asyncio
async def test_current_demand_res_limit_flag_ignores_ev_charging_complete(exi_codec):
    session = _session("din-secc-baseline.yaml")
    hdr = MessageHeader(session_id=session.session_id)

    def req(current_a: int, charging_complete: bool):
        return V2GMessageDINSPEC(
            header=hdr,
            body=Body(
                current_demand_req=CurrentDemandReq(
                    dc_ev_status=_dc_ev_status(),
                    ev_target_current=PVEVTargetCurrentDin(
                        multiplier=0, value=current_a, unit=UnitSymbol.AMPERE
                    ),
                    ev_target_voltage=PVEVTargetVoltageDin(
                        multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
                    ),
                    charging_complete=charging_complete,
                )
            ),
        )

    res = _decode(await ScriptedPeer(session, CurrentDemand).feed(req(10, True)))
    assert res.evse_current_limit_achieved is False

    res = _decode(await ScriptedPeer(session, CurrentDemand).feed(req(60, False)))
    assert res.evse_current_limit_achieved is True
