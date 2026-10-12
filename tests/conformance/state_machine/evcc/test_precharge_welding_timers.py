"""The EVCC precharge and welding timers bound a voltage that never converges (#145).

Precharge finishes only on the charger's reported voltage (#139) and welding
detection only once it has fallen below the welding threshold (#145), so a
charger that never gets there must still be cut off by the protocol's timer.
Each test drives the real EVCC state through `process_message()` with the
timer already expired and a reported voltage that has not converged, on DIN,
ISO-2 and ISO-20.
"""

from __future__ import annotations

from time import time

import pytest

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.evcc.states import din_spec_states as din
from app.evcc.states import iso15118_2_states as iso2
from app.evcc.states import iso15118_20_states as iso20
from app.shared.messages.datatypes import (
    DCEVSEStatus,
    DCEVSEStatusCode,
    EVSENotification,
    PVEVSEPresentVoltage,
    PVEVSEPresentVoltageDin,
)
from app.shared.messages.din_spec import body as din_body
from app.shared.messages.din_spec.header import MessageHeader as DinHeader
from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDIN
from app.shared.messages.enums import IsolationLevel, Protocol, UnitSymbol
from app.shared.messages.iso15118_2 import body as iso2_body
from app.shared.messages.iso15118_2.header import MessageHeader as Iso2Header
from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from app.shared.messages.iso15118_20.common_types import (
    MessageHeader as Iso20Header,
)
from app.shared.messages.iso15118_20.common_types import RationalNumber
from app.shared.messages.iso15118_20.dc import DCPreChargeRes, DCWeldingDetectionRes
from app.shared.messages.timeouts import Timeouts as TimeoutsShared
from app.shared.personality import EVCCPersonality
from app.shared.states import Terminate
from tests.conformance.state_machine.harness import (
    ScriptedPeer,
    StubCommSession,
    StubWriter,
)

# A precharge reading far short of the 800 V target, and a welding reading
# still well above the welding threshold.
_UNCONVERGED_V = 34
_STILL_CHARGED_V = 400
# Far enough back that every protocol's precharge and ongoing timer expired.
_EXPIRED = 10 * TimeoutsShared.V2G_EVCC_ONGOING_TIMEOUT


def _session(protocol: Protocol) -> StubCommSession:
    config = EVCCConfig.from_personality(
        EVCCPersonality.model_validate(
            {"residual": {"charge_ramp": {"target_voltage_v": 800.0}}}
        )
    )
    session = StubCommSession(protocol=protocol, session_id=bytes(1).hex())
    session.config = config
    session.ev_controller = SimEVController(config)
    session.live_control = None
    session.writer = StubWriter()
    session.ongoing_timer = time() - _EXPIRED
    if protocol == Protocol.ISO_15118_20_DC:
        # The ISO-20 welding state compares against an int(time()) timer.
        session.ongoing_timer = int(session.ongoing_timer)
    return session


def _dc_evse_status() -> DCEVSEStatus:
    return DCEVSEStatus(
        notification_max_delay=0,
        evse_notification=EVSENotification.NONE,
        evse_isolation_status=IsolationLevel.VALID,
        evse_status_code=DCEVSEStatusCode.EVSE_READY,
    )


def _din(session, **body) -> V2GMessageDIN:
    return V2GMessageDIN(
        header=DinHeader(session_id=session.session_id),
        body=din_body.Body(**body),
    )


def _iso2(session, **body) -> V2GMessageV2:
    return V2GMessageV2(
        header=Iso2Header(session_id=session.session_id),
        body=iso2_body.Body(**body),
    )


def _iso20_header(session) -> Iso20Header:
    return Iso20Header(session_id=session.session_id, timestamp=int(time()))


def _din_v(volts: int) -> PVEVSEPresentVoltageDin:
    return PVEVSEPresentVoltageDin(multiplier=0, value=volts, unit=UnitSymbol.VOLTAGE)


def _iso2_v(volts: int) -> PVEVSEPresentVoltage:
    return PVEVSEPresentVoltage(multiplier=0, value=volts, unit=UnitSymbol.VOLTAGE)


def _din_precharge(session):
    return _din(
        session,
        pre_charge_res=din_body.PreChargeRes(
            response_code=din_body.ResponseCode.OK,
            dc_evse_status=_dc_evse_status(),
            evse_present_voltage=_din_v(_UNCONVERGED_V),
        ),
    )


def _din_welding(session):
    return _din(
        session,
        welding_detection_res=din_body.WeldingDetectionRes(
            response_code=din_body.ResponseCode.OK,
            dc_evse_status=_dc_evse_status(),
            evse_present_voltage=_din_v(_STILL_CHARGED_V),
        ),
    )


def _iso2_precharge(session):
    return _iso2(
        session,
        pre_charge_res=iso2_body.PreChargeRes(
            response_code=iso2_body.ResponseCode.OK,
            dc_evse_status=_dc_evse_status(),
            evse_present_voltage=_iso2_v(_UNCONVERGED_V),
        ),
    )


def _iso2_welding(session):
    return _iso2(
        session,
        welding_detection_res=iso2_body.WeldingDetectionRes(
            response_code=iso2_body.ResponseCode.OK,
            dc_evse_status=_dc_evse_status(),
            evse_present_voltage=_iso2_v(_STILL_CHARGED_V),
        ),
    )


def _iso20_precharge(session):
    return DCPreChargeRes(
        header=_iso20_header(session),
        response_code="OK",
        evse_present_voltage=RationalNumber.get_rational_repr(_UNCONVERGED_V),
    )


def _iso20_welding(session):
    return DCWeldingDetectionRes(
        header=_iso20_header(session),
        response_code="OK",
        evse_present_voltage=RationalNumber.get_rational_repr(_STILL_CHARGED_V),
    )


@pytest.mark.parametrize(
    "protocol, state, response",
    [
        (Protocol.DIN_SPEC_70121, din.PreCharge, _din_precharge),
        (Protocol.DIN_SPEC_70121, din.WeldingDetection, _din_welding),
        (Protocol.ISO_15118_2, iso2.PreCharge, _iso2_precharge),
        (Protocol.ISO_15118_2, iso2.WeldingDetection, _iso2_welding),
        (Protocol.ISO_15118_20_DC, iso20.DCPreCharge, _iso20_precharge),
        (Protocol.ISO_15118_20_DC, iso20.DCWeldingDetection, _iso20_welding),
    ],
    ids=[
        "din-precharge",
        "din-welding",
        "iso2-precharge",
        "iso2-welding",
        "iso20-precharge",
        "iso20-welding",
    ],
)
async def test_expired_timer_ends_an_unconverged_wait(
    exi_codec, protocol, state, response
):
    session = _session(protocol)
    peer = ScriptedPeer(session, start_state=state)

    result = await peer.feed(response(session))

    assert result.next_state is Terminate
    assert "time" in session.stop_reason.reason.lower()  # timed out / timeout
