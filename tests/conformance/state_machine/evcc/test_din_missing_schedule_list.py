"""The DIN EVCC survives a Finished ChargeParameterDiscoveryRes with no
SAScheduleList (issue #137, conformance review SC-040).

DIN Table 39 requires the SAScheduleList once EVSEProcessing is Finished, but
the EVCC only uses it to pick the SAScheduleTupleID for an optional charging
profile. A charger that omits it is non-conformant; the receive posture is to
log the gap once as out-of-spec, default the tuple ID to 1 and carry on to
CableCheck instead of dying on an ``AttributeError`` with nothing sent.

The replay feeds the charger's message to the real state at the ADR-0003
``process_message()`` seam.
"""

from __future__ import annotations

import logging

import pytest

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.evcc.states.din_spec_states import CableCheck, ChargeParameterDiscovery
from app.shared.exi_codec import EXI
from app.shared.messages.datatypes import (
    DCEVSEChargeParameter,
    DCEVSEStatus,
    DCEVSEStatusCode,
    EVSENotification,
    PVEVSEMaxCurrentLimit,
    PVEVSEMaxPowerLimit,
    PVEVSEMaxVoltageLimit,
    PVEVSEMinCurrentLimit,
    PVEVSEMinVoltageLimit,
    PVEVSEPeakCurrentRipple,
)
from app.shared.messages.din_spec.body import (
    Body,
    CableCheckReq,
    ChargeParameterDiscoveryRes,
)
from app.shared.messages.din_spec.header import MessageHeader
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from app.shared.messages.enums import (
    EVSEProcessing,
    IsolationLevel,
    Namespace,
    Protocol,
    UnitSymbol,
)
from app.shared.personality.loader import load_personality
from tests.conformance.out_of_spec_log import (
    OUT_OF_SPEC_LOGGER,
    assert_single_out_of_spec_warning,
)
from tests.conformance.state_machine.harness import ScriptedPeer, StubCommSession


def _run_default_session() -> StubCommSession:
    personality = load_personality("din_dc_extended-evcc", "evcc")
    config = EVCCConfig.from_personality(personality)
    session = StubCommSession(
        protocol=Protocol.DIN_SPEC_70121, session_id=bytes(1).hex()
    )
    session.config = config
    session.ev_controller = SimEVController(config)
    session.live_control = None
    session.selected_auth_option = None
    session.selected_services = []
    session.selected_energy_mode = None
    session.selected_schedule = None
    session.ongoing_timer = -1
    return session


def _decode(result):
    payload = result.outbound_v2gtp.payload
    return EXI().from_exi_document(payload, Namespace.DIN_MSG_DEF).body.get_message()


def _dc_evse_charge_parameter() -> DCEVSEChargeParameter:
    def pv(cls, value, unit):
        return cls(multiplier=0, value=value, unit=unit)

    return DCEVSEChargeParameter(
        dc_evse_status=DCEVSEStatus(
            notification_max_delay=0,
            evse_notification=EVSENotification.NONE,
            evse_isolation_status=IsolationLevel.INVALID,
            evse_status_code=DCEVSEStatusCode.EVSE_READY,
        ),
        evse_maximum_current_limit=pv(PVEVSEMaxCurrentLimit, 200, UnitSymbol.AMPERE),
        evse_maximum_power_limit=PVEVSEMaxPowerLimit(multiplier=1, value=5000, unit=UnitSymbol.WATT),
        evse_maximum_voltage_limit=pv(PVEVSEMaxVoltageLimit, 500, UnitSymbol.VOLTAGE),
        evse_minimum_current_limit=pv(PVEVSEMinCurrentLimit, 0, UnitSymbol.AMPERE),
        evse_minimum_voltage_limit=pv(PVEVSEMinVoltageLimit, 200, UnitSymbol.VOLTAGE),
        evse_peak_current_ripple=pv(PVEVSEPeakCurrentRipple, 1, UnitSymbol.AMPERE),
    )


@pytest.mark.asyncio
async def test_finished_without_schedule_list_advances_to_cable_check(
    exi_codec, caplog
):
    session = _run_default_session()
    peer = ScriptedPeer(session, ChargeParameterDiscovery)
    charger_message = V2GMessageDINSPEC(
        header=MessageHeader(session_id=session.session_id),
        body=Body(
            charge_parameter_discovery_res=ChargeParameterDiscoveryRes(
                response_code="OK",
                evse_processing=EVSEProcessing.FINISHED,
                dc_charge_parameter=_dc_evse_charge_parameter(),
            )
        ),
    )
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        result = await peer.feed(charger_message)

    assert result.next_state is CableCheck
    assert isinstance(_decode(result), CableCheckReq), (
        "A Finished ChargeParameterDiscoveryRes without SAScheduleList must "
        "still advance the DIN EVCC to CableCheck (SC-040)."
    )
    assert session.selected_schedule == 1
    assert_single_out_of_spec_warning(
        caplog, "ChargeParameterDiscoveryRes", "SAScheduleList"
    )
