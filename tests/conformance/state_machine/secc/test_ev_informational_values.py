"""The SECC does not fail CableCheck / PreCharge on informational EV values (#141).

Conformance review SC-004 / SC-039:

- ``DC_EVStatus.EVErrorCode`` is informational: DIN [V2G-DC-640] and ISO-2
  [V2G2-881] say the EVSE shall not change its behaviour on it (the EV signals
  shutdown through the control pilot). NoData or a reserved code is logged and
  the session continues with an OK response.
- A PreChargeReq ``EVTargetCurrent`` above 2 A has no DIN / ISO-2 bound; the
  2 A figure is IEC 61851-23 inrush guidance on the charger's own output. The
  request is logged and the simulated output clamped, never rejected.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from app.secc.controller.simulator import SimEVSEController
from app.secc.failed_responses import (
    init_failed_responses_din_spec_70121,
    init_failed_responses_iso_v2,
)
from app.secc.states import din_spec_states, iso15118_2_states
from app.secc.states.secc_state import PRECHARGE_MAX_CURRENT_A
from app.shared.messages import datatypes as dt
from app.shared.messages.din_spec import body as din_body
from app.shared.messages.din_spec import datatypes as din_dt
from app.shared.messages.din_spec.header import MessageHeader as DinHeader
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import DCEVErrorCode, Protocol, UnitSymbol
from app.shared.messages.iso15118_2 import body as iso2_body
from app.shared.messages.iso15118_2 import datatypes as iso2_dt
from app.shared.messages.iso15118_2.header import MessageHeader as Iso2Header
from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from app.shared.personality.model import Runtime, SECCPersonality
from app.shared.states import Terminate
from tests.conformance.state_machine.harness import (
    ScriptedPeer,
    StubCommSession,
    StubWriter,
)

# Both out-of-spec and informational lines are logged by this module.
RECEIVE_POSTURE_LOGGER = "app.shared.messages.out_of_spec"


def _session(protocol: Protocol) -> StubCommSession:
    from app.secc.secc_settings import Config

    personality = SECCPersonality.model_validate(
        {"capabilities": {"supported_protocols": [protocol.name]}}
    )
    controller = SimEVSEController(personality=personality)
    controller.set_selected_protocol(protocol)
    session = StubCommSession(protocol=protocol, session_id=bytes(1).hex())
    session.evse_controller = controller
    session.config = Config.from_personality(personality, Runtime())
    session.ev_session_context = SimpleNamespace(sa_schedule_tuple_id=0)
    session.writer = StubWriter()
    session.failed_responses_din_spec = init_failed_responses_din_spec_70121()
    session.failed_responses_isov2 = init_failed_responses_iso_v2()
    session.charge_progress_started = False
    return session


def _din_status(code: DCEVErrorCode) -> din_dt.DCEVStatus:
    return din_dt.DCEVStatus(ev_ready=True, ev_error_code=code, ev_ress_soc=42)


def _iso2_status(code: DCEVErrorCode) -> iso2_dt.DCEVStatus:
    return iso2_dt.DCEVStatus(ev_ready=True, ev_error_code=code, ev_ress_soc=42)


def _din_cable_check(session, code):
    return V2GMessageDINSPEC(
        header=DinHeader(session_id=session.session_id),
        body=din_body.Body(
            cable_check_req=din_body.CableCheckReq(dc_ev_status=_din_status(code))
        ),
    )


def _din_pre_charge(session, code, current_a=1):
    return V2GMessageDINSPEC(
        header=DinHeader(session_id=session.session_id),
        body=din_body.Body(
            pre_charge_req=din_body.PreChargeReq(
                dc_ev_status=_din_status(code),
                ev_target_voltage=dt.PVEVTargetVoltageDin(
                    multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
                ),
                ev_target_current=dt.PVEVTargetCurrentDin(
                    multiplier=0, value=current_a, unit=UnitSymbol.AMPERE
                ),
            )
        ),
    )


def _iso2_cable_check(session, code):
    return V2GMessageV2(
        header=Iso2Header(session_id=session.session_id),
        body=iso2_body.Body(
            cable_check_req=iso2_body.CableCheckReq(dc_ev_status=_iso2_status(code))
        ),
    )


def _iso2_pre_charge(session, code, current_a=1):
    return V2GMessageV2(
        header=Iso2Header(session_id=session.session_id),
        body=iso2_body.Body(
            pre_charge_req=iso2_body.PreChargeReq(
                dc_ev_status=_iso2_status(code),
                ev_target_voltage=dt.PVEVTargetVoltage(
                    multiplier=0, value=400, unit=UnitSymbol.VOLTAGE
                ),
                ev_target_current=dt.PVEVTargetCurrent(
                    multiplier=0, value=current_a, unit=UnitSymbol.AMPERE
                ),
            )
        ),
    )


# Per protocol: the SECC states module, and a request builder per state name.
PROTOCOLS = {
    Protocol.DIN_SPEC_70121: (
        din_spec_states,
        {"CableCheck": _din_cable_check, "PreCharge": _din_pre_charge},
    ),
    Protocol.ISO_15118_2: (
        iso15118_2_states,
        {"CableCheck": _iso2_cable_check, "PreCharge": _iso2_pre_charge},
    ),
}


def _warning_lines(caplog):
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == RECEIVE_POSTURE_LOGGER and r.levelno == logging.WARNING
    ]


def _response(result, name: str):
    return getattr(result.outbound_msg.body, name)


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", list(PROTOCOLS), ids=lambda p: p.name)
@pytest.mark.parametrize(
    "state_name, res_field",
    [("CableCheck", "cable_check_res"), ("PreCharge", "pre_charge_res")],
    ids=["CableCheck", "PreCharge"],
)
@pytest.mark.parametrize(
    "code", [DCEVErrorCode.NO_DATA, DCEVErrorCode.RESERVED_A], ids=lambda c: c.value
)
async def test_ev_error_code_is_ignored(
    exi_codec, protocol, state_name, res_field, code, caplog
):
    states, builders = PROTOCOLS[protocol]
    session = _session(protocol)
    caplog.set_level(logging.WARNING)

    result = await ScriptedPeer(session, getattr(states, state_name)).feed(
        builders[state_name](session, code)
    )

    res = _response(result, res_field)
    assert res.response_code.value == "OK"
    assert result.next_state is not Terminate
    lines = _warning_lines(caplog)
    assert len(lines) == 1
    assert "EVErrorCode" in lines[0] and code.value in lines[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", list(PROTOCOLS), ids=lambda p: p.name)
async def test_pre_charge_clamps_high_target_current(exi_codec, protocol, caplog):
    states, builders = PROTOCOLS[protocol]
    session = _session(protocol)
    caplog.set_level(logging.WARNING)

    result = await ScriptedPeer(session, states.PreCharge).feed(
        builders["PreCharge"](session, DCEVErrorCode.NO_ERROR, current_a=10)
    )

    res = _response(result, "pre_charge_res")
    assert res.response_code.value == "OK"
    assert result.next_state is not Terminate
    # The simulator's own clamp to the advertised maximum is covered by
    # tests/secc/controller/test_sim_charging_command.py.
    present = await session.evse_controller.get_evse_present_current(protocol)
    assert present.get_decimal_value() <= PRECHARGE_MAX_CURRENT_A
    lines = _warning_lines(caplog)
    assert len(lines) == 1
    assert "EVTargetCurrent" in lines[0] and "10" in lines[0]
