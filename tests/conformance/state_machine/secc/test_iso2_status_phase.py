"""ISO-2 SECC status values follow the phase rules (SC-070, the #140 follow-up).

- The shipped ``iso2-secc-baseline`` ChargeParameterDiscoveryRes carries
  EVSE_Ready, not the reference capture's IsolationMonitoringActive.
- An ONGOING CableCheckRes reports Invalid / EVSE_IsolationMonitoringActive and
  the completing one Valid / EVSE_Ready, even with an empty message field tree.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from app.secc.controller.simulator import SimEVSEController
from app.secc.states.iso15118_2_states import CableCheck, ChargeParameterDiscovery
from app.shared.messages.datatypes import DCEVSEStatusCode
from app.shared.messages.enums import EVSEProcessing, IsolationLevel, Protocol
from app.shared.messages.iso15118_2.body import Body, CableCheckReq
from app.shared.messages.iso15118_2.datatypes import DCEVStatus
from app.shared.messages.iso15118_2.header import MessageHeader
from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from app.shared.personality.loader import load_personality
from app.shared.personality.model import SECCPersonality
from tests.conformance.state_machine.harness import (
    ScriptedPeer,
    StubCommSession,
    StubWriter,
)
from tests.conformance.state_machine.secc.test_iso2_isolation_field_tree import (
    _dc_charge_parameter_discovery_req,
)

PERSONALITIES_DIR = Path(__file__).resolve().parents[4] / "personalities"


def _session(personality: SECCPersonality) -> StubCommSession:
    from app.secc.secc_settings import Config
    from app.shared.personality.model import Runtime

    controller = SimEVSEController(personality=personality)
    controller.set_selected_protocol(Protocol.ISO_15118_2)
    session = StubCommSession(protocol=Protocol.ISO_15118_2, session_id=bytes(1).hex())
    session.evse_controller = controller
    session.config = Config.from_personality(personality, Runtime())
    session.ev_session_context = SimpleNamespace(sa_schedule_tuple_id=0)
    session.writer = StubWriter()
    return session


@pytest.mark.asyncio
async def test_baseline_charge_parameter_discovery_res_is_ready(exi_codec):
    personality = load_personality(
        str(PERSONALITIES_DIR / "iso2-secc-baseline.yaml"), "secc"
    )
    session = _session(personality)

    result = await ScriptedPeer(session, ChargeParameterDiscovery).feed(
        _dc_charge_parameter_discovery_req(session)
    )

    status = result.outbound_msg.body.charge_parameter_discovery_res.dc_charge_parameter.dc_evse_status  # noqa: E501
    assert status.evse_isolation_status is IsolationLevel.INVALID
    assert status.evse_status_code is DCEVSEStatusCode.EVSE_READY


@pytest.mark.asyncio
async def test_ongoing_cable_check_reports_monitoring_active_with_empty_tree(
    exi_codec,
):
    session = _session(
        SECCPersonality.model_validate(
            {"capabilities": {"supported_protocols": ["ISO_15118_2"]}}
        )
    )
    req = V2GMessageV2(
        header=MessageHeader(session_id=session.session_id),
        body=Body(
            cable_check_req=CableCheckReq(
                dc_ev_status=DCEVStatus(
                    ev_ready=True, ev_error_code="NO_ERROR", ev_ress_soc=50
                )
            )
        ),
    )
    cc = ScriptedPeer(session, CableCheck)

    res = (await cc.feed(req)).outbound_msg.body.cable_check_res
    assert res.evse_processing == EVSEProcessing.ONGOING
    assert res.dc_evse_status.evse_isolation_status is IsolationLevel.INVALID
    assert (
        res.dc_evse_status.evse_status_code
        is DCEVSEStatusCode.EVSE_ISOLATION_MONITORING_ACTIVE
    )

    res = (await cc.feed(req)).outbound_msg.body.cable_check_res
    assert res.evse_processing == EVSEProcessing.FINISHED
    assert res.dc_evse_status.evse_isolation_status is IsolationLevel.VALID
    assert res.dc_evse_status.evse_status_code is DCEVSEStatusCode.EVSE_READY
