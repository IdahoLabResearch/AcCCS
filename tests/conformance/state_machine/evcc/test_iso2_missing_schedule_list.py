"""The ISO-2 EVCC survives a Finished ChargeParameterDiscoveryRes with no
SAScheduleList (issue #137, conformance review SC-040).

[V2G2-688] lets the SECC omit the SAScheduleList only while EVSEProcessing is
Ongoing, so a charger that sends Finished without one is non-conformant. The
EVCC only uses the list to pick the SAScheduleTupleID for an optional charging
profile, so the receive posture is to log the gap once as out-of-spec, default
the tuple ID to 1 and carry on: to CableCheck on a DC session, to PowerDelivery
without a ChargingProfile on an AC session.

Each replay feeds the charger's message to the real state at the ADR-0003
``process_message()`` seam.
"""

from __future__ import annotations

import logging

import pytest

from app.evcc.states.iso15118_2_states import (
    CableCheck,
    ChargeParameterDiscovery,
    PowerDelivery,
)
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
from app.shared.messages.enums import (
    EVSEProcessing,
    IsolationLevel,
    Namespace,
    UnitSymbol,
)
from app.shared.messages.iso15118_2.body import (
    Body,
    CableCheckReq,
    ChargeParameterDiscoveryRes,
    PowerDeliveryReq,
)
from app.shared.messages.iso15118_2.datatypes import (
    ACEVSEChargeParameter,
    ACEVSEStatus,
    ChargeProgress,
    PVEVSEMaxCurrent,
    PVEVSENominalVoltage,
)
from app.shared.messages.iso15118_2.header import MessageHeader
from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from tests.conformance.out_of_spec_log import (
    OUT_OF_SPEC_LOGGER,
    assert_single_out_of_spec_warning,
)
from tests.conformance.state_machine.evcc._iso2_session import baseline_session
from tests.conformance.state_machine.harness import ScriptedPeer


def _decode(result):
    payload = result.outbound_v2gtp.payload
    return EXI().from_exi_document(payload, Namespace.ISO_V2_MSG_DEF).body.get_message()


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
        evse_maximum_power_limit=PVEVSEMaxPowerLimit(
            multiplier=1, value=5000, unit=UnitSymbol.WATT
        ),
        evse_maximum_voltage_limit=pv(PVEVSEMaxVoltageLimit, 500, UnitSymbol.VOLTAGE),
        evse_minimum_current_limit=pv(PVEVSEMinCurrentLimit, 0, UnitSymbol.AMPERE),
        evse_minimum_voltage_limit=pv(PVEVSEMinVoltageLimit, 200, UnitSymbol.VOLTAGE),
        evse_peak_current_ripple=pv(PVEVSEPeakCurrentRipple, 1, UnitSymbol.AMPERE),
    )


def _ac_evse_charge_parameter() -> ACEVSEChargeParameter:
    return ACEVSEChargeParameter(
        ac_evse_status=ACEVSEStatus(
            notification_max_delay=0,
            evse_notification=EVSENotification.NONE,
            rcd=False,
        ),
        evse_nominal_voltage=PVEVSENominalVoltage(
            multiplier=0, value=230, unit=UnitSymbol.VOLTAGE
        ),
        evse_max_current=PVEVSEMaxCurrent(
            multiplier=0, value=32, unit=UnitSymbol.AMPERE
        ),
    )


def _finished_without_schedule(session, **charge_parameter) -> V2GMessageV2:
    return V2GMessageV2(
        header=MessageHeader(session_id=session.session_id),
        body=Body(
            charge_parameter_discovery_res=ChargeParameterDiscoveryRes(
                response_code="OK",
                evse_processing=EVSEProcessing.FINISHED,
                **charge_parameter,
            )
        ),
    )


@pytest.mark.asyncio
async def test_dc_session_without_schedule_list_advances_to_cable_check(
    exi_codec, caplog
):
    session = baseline_session()
    peer = ScriptedPeer(session, ChargeParameterDiscovery)
    message = _finished_without_schedule(
        session, dc_charge_parameter=_dc_evse_charge_parameter()
    )
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        result = await peer.feed(message)

    assert result.next_state is CableCheck
    assert isinstance(_decode(result), CableCheckReq), (
        "A Finished ChargeParameterDiscoveryRes without SAScheduleList must "
        "still advance a DC session to CableCheck (SC-040)."
    )
    assert session.selected_schedule == 1
    assert_single_out_of_spec_warning(
        caplog, "ChargeParameterDiscoveryRes", "SAScheduleList"
    )


@pytest.mark.asyncio
async def test_ac_session_without_schedule_list_starts_power_delivery(
    exi_codec, caplog
):
    session = baseline_session()
    session.selected_charging_type_is_ac = True
    peer = ScriptedPeer(session, ChargeParameterDiscovery)
    message = _finished_without_schedule(
        session, ac_charge_parameter=_ac_evse_charge_parameter()
    )
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        result = await peer.feed(message)

    assert result.next_state is PowerDelivery
    power_delivery_req = _decode(result)
    assert isinstance(power_delivery_req, PowerDeliveryReq)
    assert power_delivery_req.charge_progress == ChargeProgress.START
    assert power_delivery_req.sa_schedule_tuple_id == 1
    assert power_delivery_req.charging_profile is None, (
        "With no schedule offered there is nothing to derive a profile from; "
        "the ChargingProfile is optional and must simply be left out."
    )
    assert session.selected_schedule == 1
    assert_single_out_of_spec_warning(
        caplog, "ChargeParameterDiscoveryRes", "SAScheduleList"
    )
