"""The DIN and ISO-2 EVCCs proceed on informational charger status (issue #142,
conformance review SC-037, SC-038).

DIN [V2G-DC-637] and its NOTE make EVSEStatusCode informational: only
EVSE_Shutdown carries an EVCC obligation ([V2G-DC-650]), and
EVSE_IsolationMonitoringActive is an expected value during CableCheck.
EVSEIsolationStatus is optional (DIN Table 66), and a Warning isolation
(ISO-2 Table 97: below the warning level) is still a go. So a Finished
CableCheckRes advances to PreCharge unless the isolation is Fault or the
charger asks for a shutdown (EVSE_Shutdown, or EVSE_EmergencyShutdown since
the charger has cut its output), and the DIN charge loop keeps running on any
code but those. Each tolerated value logs one warning; a Valid isolation logs
one info line.

Each replay feeds the charger's message to the real state at the ADR-0003
``process_message()`` seam.
"""

from __future__ import annotations

import logging
from typing import Optional

import pytest

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.evcc.states import din_spec_states as din
from app.evcc.states import iso15118_2_states as iso2
from app.shared.exi_codec import EXI
from app.shared.messages.datatypes import (
    DCEVSEStatus,
    DCEVSEStatusCode,
    EVSENotification,
    PVEVSEPresentCurrentDin,
    PVEVSEPresentVoltageDin,
)
from app.shared.messages.din_spec import body as din_body
from app.shared.messages.din_spec.header import MessageHeader as MessageHeaderDIN
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import (
    EVSEProcessing,
    IsolationLevel,
    Namespace,
    Protocol,
    UnitSymbol,
)
from app.shared.messages.iso15118_2 import body as iso2_body
from app.shared.messages.iso15118_2.header import MessageHeader as MessageHeaderV2
from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from app.shared.personality.loader import load_personality
from app.shared.states import Terminate
from tests.conformance.out_of_spec_log import (
    OUT_OF_SPEC_LOGGER,
    assert_single_out_of_spec_warning,
    out_of_spec_records,
)
from tests.conformance.state_machine.evcc._iso2_session import baseline_session
from tests.conformance.state_machine.harness import (
    ScriptedPeer,
    StubCommSession,
    StubWriter,
)

READY = DCEVSEStatusCode.EVSE_READY
MONITORING = DCEVSEStatusCode.EVSE_ISOLATION_MONITORING_ACTIVE
UTILITY_INTERRUPT = DCEVSEStatusCode.EVSE_UTILITY_INTERUPT_EVENT
SHUTDOWN = DCEVSEStatusCode.EVSE_SHUTDOWN
EMERGENCY = DCEVSEStatusCode.EVSE_EMERGENCY_SHUTDOWN
EVCC_STATE_LOGGER = "app.evcc.states.evcc_state"

# (status code, isolation, the value the single warning names)
TOLERATED = [
    pytest.param(MONITORING, IsolationLevel.VALID, MONITORING.value, id="monitoring-active"),
    pytest.param(READY, IsolationLevel.WARNING, "Warning", id="warning-isolation"),
    pytest.param(READY, None, "EVSEIsolationStatus", id="absent-isolation"),
    pytest.param(READY, IsolationLevel.NO_IMD, "No_IMD", id="no-imd-isolation"),
]


def _status(code: DCEVSEStatusCode, isolation: Optional[IsolationLevel]) -> DCEVSEStatus:
    return DCEVSEStatus(
        notification_max_delay=0,
        evse_notification=EVSENotification.NONE,
        evse_isolation_status=isolation,
        evse_status_code=code,
    )


def _din_session() -> StubCommSession:
    config = EVCCConfig.from_personality(load_personality("din_dc_extended-evcc", "evcc"))
    session = StubCommSession(protocol=Protocol.DIN_SPEC_70121, session_id=bytes(1).hex())
    session.config = config
    session.ev_controller = SimEVController(config)
    session.ev_controller.charge_loop_delay_time = 0
    session.live_control = None
    session.selected_auth_option = None
    session.selected_services = []
    session.selected_energy_mode = None
    session.selected_schedule = None
    session.ongoing_timer = -1
    session.writer = StubWriter()
    return session


def _decode(result, namespace: Namespace):
    payload = result.outbound_v2gtp.payload
    return EXI().from_exi_document(payload, namespace).body.get_message()


async def _feed_din_cable_check(status: DCEVSEStatus):
    session = _din_session()
    message = V2GMessageDINSPEC(
        header=MessageHeaderDIN(session_id=session.session_id),
        body=din_body.Body(
            cable_check_res=din_body.CableCheckRes(
                response_code="OK",
                dc_evse_status=status,
                evse_processing=EVSEProcessing.FINISHED,
            )
        ),
    )
    return await ScriptedPeer(session, din.CableCheck).feed(message)


async def _feed_iso2_cable_check(status: DCEVSEStatus):
    session = baseline_session()
    session.writer = StubWriter()
    message = V2GMessageV2(
        header=MessageHeaderV2(session_id=session.session_id),
        body=iso2_body.Body(
            cable_check_res=iso2_body.CableCheckRes(
                response_code="OK",
                dc_evse_status=status,
                evse_processing=EVSEProcessing.FINISHED,
            )
        ),
    )
    return await ScriptedPeer(session, iso2.CableCheck).feed(message)


@pytest.mark.asyncio
@pytest.mark.parametrize("code, isolation, needle", TOLERATED)
async def test_din_cable_check_finished_proceeds_on_informational_status(
    exi_codec, caplog, code, isolation, needle
):
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        result = await _feed_din_cable_check(_status(code, isolation))

    assert result.next_state is din.PreCharge
    assert isinstance(_decode(result, Namespace.DIN_MSG_DEF), din_body.PreChargeReq)
    assert_single_out_of_spec_warning(caplog, needle)


@pytest.mark.asyncio
@pytest.mark.parametrize("code, isolation, needle", TOLERATED)
async def test_iso2_cable_check_finished_proceeds_on_informational_status(
    exi_codec, caplog, code, isolation, needle
):
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        result = await _feed_iso2_cable_check(_status(code, isolation))

    assert result.next_state is iso2.PreCharge
    assert isinstance(_decode(result, Namespace.ISO_V2_MSG_DEF), iso2_body.PreChargeReq)
    assert_single_out_of_spec_warning(caplog, needle)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "feed", [_feed_din_cable_check, _feed_iso2_cable_check], ids=["din", "iso2"]
)
async def test_cable_check_ready_and_valid_logs_one_info_line(exi_codec, caplog, feed):
    with caplog.at_level(logging.INFO):
        result = await feed(_status(READY, IsolationLevel.VALID))

    assert result.next_state not in (None, Terminate)
    assert out_of_spec_records(caplog) == []
    valid_lines = [
        rec
        for rec in caplog.records
        if rec.name == EVCC_STATE_LOGGER and rec.levelno == logging.INFO
    ]
    assert len(valid_lines) == 1, [rec.getMessage() for rec in valid_lines]
    assert "Valid" in valid_lines[0].getMessage()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "feed", [_feed_din_cable_check, _feed_iso2_cable_check], ids=["din", "iso2"]
)
@pytest.mark.parametrize(
    "code, isolation",
    [
        pytest.param(READY, IsolationLevel.FAULT, id="fault-isolation"),
        pytest.param(SHUTDOWN, IsolationLevel.VALID, id="shutdown"),
        pytest.param(EMERGENCY, IsolationLevel.VALID, id="emergency-shutdown"),
    ],
)
async def test_cable_check_finished_stops_on_fault_or_shutdown(
    exi_codec, feed, code, isolation
):
    result = await feed(_status(code, isolation))

    assert result.next_state is Terminate


def _current_demand_message(session, code: DCEVSEStatusCode) -> V2GMessageDINSPEC:
    return V2GMessageDINSPEC(
        header=MessageHeaderDIN(session_id=session.session_id),
        body=din_body.Body(
            current_demand_res=din_body.CurrentDemandRes(
                response_code="OK",
                dc_evse_status=_status(code, IsolationLevel.VALID),
                evse_present_voltage=PVEVSEPresentVoltageDin(
                    multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
                ),
                evse_present_current=PVEVSEPresentCurrentDin(
                    multiplier=0, value=50, unit=UnitSymbol.AMPERE
                ),
                evse_current_limit_achieved=False,
                evse_voltage_limit_achieved=False,
                evse_power_limit_achieved=False,
            )
        ),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [UTILITY_INTERRUPT, MONITORING], ids=lambda c: c.value)
async def test_din_charge_loop_continues_on_informational_status(
    exi_codec, caplog, code
):
    session = _din_session()
    peer = ScriptedPeer(session, din.CurrentDemand)

    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        result = await peer.feed(_current_demand_message(session, code))

    assert isinstance(_decode(result, Namespace.DIN_MSG_DEF), din_body.CurrentDemandReq)
    assert_single_out_of_spec_warning(caplog, "EVSEStatusCode", code.value)


@pytest.mark.asyncio
async def test_din_charge_loop_logs_a_held_status_code_once(exi_codec, caplog):
    session = _din_session()
    peer = ScriptedPeer(session, din.CurrentDemand)

    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        for _ in range(3):
            result = await peer.feed(_current_demand_message(session, MONITORING))

    assert isinstance(_decode(result, Namespace.DIN_MSG_DEF), din_body.CurrentDemandReq)
    assert_single_out_of_spec_warning(caplog, MONITORING.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [SHUTDOWN, EMERGENCY], ids=lambda c: c.value)
async def test_din_charge_loop_stops_on_shutdown(exi_codec, code):
    session = _din_session()
    peer = ScriptedPeer(session, din.CurrentDemand)

    result = await peer.feed(_current_demand_message(session, code))

    assert result.next_state is din.PowerDelivery
    stop = _decode(result, Namespace.DIN_MSG_DEF)
    assert isinstance(stop, din_body.PowerDeliveryReq)
    assert stop.ready_to_charge is False
