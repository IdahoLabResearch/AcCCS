"""AC control-pilot timing at the send sites, and State B on every abort
(issue #146; conformance review SC-001 AC part, SC-065 control-pilot part).

AC start: the EV is still in State B when its PowerDeliveryReq(Start) leaves
and goes to C within 250 ms after ([V2G2-846]/[847], [V2G20-1617]/[847]). AC
stop: back to B within 250 ms after sending PowerDeliveryReq(Stop), not after
a response that may take seconds ([V2G2-848], [V2G20-848]). So a state that
builds one of those requests leaves an `after_send` action for the receive
loop instead of writing the pilot itself; the tests assert nothing is written
while the request is being built and the right state is written once the
action runs. DC keeps its changes ahead of CableCheckReq and behind the stop
response, and a renegotiation never leaves State C.

Abort: DIN [V2G-DC-651] ff. want State B "without any delay", so
`stop_state_machine` and the shutdown routine write it before anything else.
"""

from __future__ import annotations

import random
from time import time
from types import SimpleNamespace

import pytest

from app.evcc.controller.simulator import SimEVController
from app.evcc.evcc_config import EVCCConfig
from app.evcc.states import iso15118_2_states as iso2
from app.evcc.states import iso15118_20_states as iso20
from app.shared import comm_session as comm_session_module
from app.shared.comm_session import V2GCommunicationSession
from app.shared.EmulatorEnum import PEVState
from app.shared.messages.datatypes import (
    DCEVSEStatus,
    DCEVSEStatusCode,
    EVSENotification,
)
from app.shared.messages.enums import (
    ControlMode,
    EVSEProcessing,
    IsolationLevel,
    Protocol,
    ServiceV20,
)
from app.shared.messages.iso15118_2.body import (
    Body,
    ChargeParameterDiscoveryRes,
    ChargingStatusRes,
    MeteringReceiptRes,
    PowerDeliveryRes,
)
from app.shared.messages.iso15118_2.datatypes import ACEVSEStatus, ChargeProgress
from app.shared.messages.iso15118_2.header import MessageHeader as MessageHeaderV2
from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from app.shared.messages.iso15118_20.common_messages import (
    ChargeProgress as ChargeProgressV20,
)
from app.shared.messages.iso15118_20.common_messages import (
    DynamicScheduleExchangeResParams,
    ParameterSet,
    ScheduleExchangeRes,
    SelectedEnergyService,
)
from app.shared.messages.iso15118_20.common_messages import (
    PowerDeliveryRes as PowerDeliveryResV20,
)
from app.shared.messages.iso15118_20.common_types import (
    MessageHeader as MessageHeaderV20,
)
from app.shared.messages.iso15118_20.common_types import Processing
from app.shared.personality.model import EVCCPersonality
from app.shared.states import Terminate
from tests.conformance.state_machine.evcc._iso2_session import (
    _sa_schedule_list,
    baseline_session,
)
from tests.conformance.state_machine.harness import (
    ScriptedPeer,
    StubCommSession,
    StubWriter,
)

pytestmark = pytest.mark.usefixtures("exi_codec")


def _record_cp(session) -> list:
    """Wire a recording control-pilot setter into the session's controller."""
    states: list = []
    session.ev_controller.cp_state_setter = states.append
    return states


# ---------------------------------------------------------------------------
# ISO 15118-2
# ---------------------------------------------------------------------------


def _iso2_session(*, ac: bool) -> StubCommSession:
    session = baseline_session()
    session.selected_charging_type_is_ac = ac
    session.selected_schedule = 1
    session.writer = StubWriter()
    return session


def _v2(session, **body) -> V2GMessageV2:
    return V2GMessageV2(
        header=MessageHeaderV2(session_id=session.session_id), body=Body(**body)
    )


def _ac_status(notification=EVSENotification.NONE) -> ACEVSEStatus:
    return ACEVSEStatus(
        notification_max_delay=0, evse_notification=notification, rcd=False
    )


def _dc_status(notification=EVSENotification.NONE) -> DCEVSEStatus:
    return DCEVSEStatus(
        notification_max_delay=0,
        evse_notification=notification,
        evse_isolation_status=IsolationLevel.VALID,
        evse_status_code=DCEVSEStatusCode.EVSE_READY,
    )


def _cpd_finished(session) -> V2GMessageV2:
    return _v2(
        session,
        charge_parameter_discovery_res=ChargeParameterDiscoveryRes(
            response_code="OK",
            evse_processing=EVSEProcessing.FINISHED,
            sa_schedule_list=_sa_schedule_list(),
        ),
    )


def _charging_status_res(session, notification) -> V2GMessageV2:
    return _v2(
        session,
        charging_status_res=ChargingStatusRes(
            response_code="OK",
            evse_id="USFRDE9001",
            sa_schedule_tuple_id=1,
            ac_evse_status=_ac_status(notification),
        ),
    )


async def test_iso2_ac_start_drives_state_c_only_after_the_request_is_sent():
    session = _iso2_session(ac=True)
    states = _record_cp(session)
    peer = ScriptedPeer(session, iso2.ChargeParameterDiscovery)

    result = await peer.feed(_cpd_finished(session))

    assert result.next_state is iso2.PowerDelivery
    assert states == [], "State B must hold while PowerDeliveryReq(Start) leaves"
    await result.after_send()
    assert states == [PEVState.C]


async def test_iso2_ac_power_delivery_that_is_not_a_start_does_not_drive_state_c(
    monkeypatch,
):
    session = _iso2_session(ac=True)
    states = _record_cp(session)

    async def stop_schedule(_tuples):
        return ChargeProgress.STOP, 1, None

    monkeypatch.setattr(
        session.ev_controller, "process_sa_schedules_v2", stop_schedule
    )
    peer = ScriptedPeer(session, iso2.ChargeParameterDiscovery)

    result = await peer.feed(_cpd_finished(session))

    assert result.next_state is iso2.PowerDelivery
    assert result.after_send is None
    assert states == []


async def test_iso2_dc_still_drives_state_c_before_cable_check_req():
    session = _iso2_session(ac=False)
    states = _record_cp(session)
    peer = ScriptedPeer(session, iso2.ChargeParameterDiscovery)

    result = await peer.feed(_cpd_finished(session))

    assert result.next_state is iso2.CableCheck
    assert states == [PEVState.C]
    assert result.after_send is None


@pytest.mark.parametrize(
    "stop_by",
    ["charger_notification", "ev_loop_end"],
)
async def test_iso2_ac_charging_status_stop_drives_state_b_once_sent(stop_by):
    session = _iso2_session(ac=True)
    states = _record_cp(session)
    await session.ev_controller.enable_charging(True, settle=False)
    notification = EVSENotification.NONE
    if stop_by == "charger_notification":
        notification = EVSENotification.STOP_CHARGING
    else:
        await session.ev_controller.stop_charging()
    peer = ScriptedPeer(session, iso2.ChargingStatus)

    result = await peer.feed(_charging_status_res(session, notification))

    assert result.next_state is iso2.PowerDelivery
    assert result.outbound_msg.body.get_message().charge_progress == ChargeProgress.STOP
    assert states == [PEVState.C]
    await result.after_send()
    assert states == [PEVState.C, PEVState.B], (
        "State B follows the stop request, before any PowerDeliveryRes"
    )

    # The response then changes nothing on the pilot.
    result = await peer.feed(
        _v2(session, power_delivery_res=PowerDeliveryRes(
            response_code="OK", ac_evse_status=_ac_status()
        ))
    )
    assert result.next_state is iso2.SessionStop
    assert result.after_send is None
    assert states == [PEVState.C, PEVState.B]


async def test_iso2_ac_metering_receipt_stop_drives_state_b_once_sent():
    session = _iso2_session(ac=True)
    states = _record_cp(session)
    await session.ev_controller.enable_charging(True, settle=False)
    peer = ScriptedPeer(session, iso2.MeteringReceipt)

    result = await peer.feed(
        _v2(session, metering_receipt_res=MeteringReceiptRes(
            response_code="OK",
            ac_evse_status=_ac_status(EVSENotification.STOP_CHARGING),
        ))
    )

    assert result.outbound_msg.body.get_message().charge_progress == ChargeProgress.STOP
    assert states == [PEVState.C]
    await result.after_send()
    assert states == [PEVState.C, PEVState.B]

    # With the pilot in State B the session must end, not resume the loop.
    result = await peer.feed(
        _v2(session, power_delivery_res=PowerDeliveryRes(
            response_code="OK", ac_evse_status=_ac_status()
        ))
    )
    assert result.next_state is iso2.SessionStop
    assert states == [PEVState.C, PEVState.B]


async def test_iso2_dc_metering_receipt_stop_stays_in_state_c_until_the_response():
    session = _iso2_session(ac=False)
    states = _record_cp(session)
    await session.ev_controller.enable_charging(True, settle=False)
    peer = ScriptedPeer(session, iso2.MeteringReceipt)

    result = await peer.feed(
        _v2(session, metering_receipt_res=MeteringReceiptRes(
            response_code="OK",
            dc_evse_status=_dc_status(EVSENotification.STOP_CHARGING),
        ))
    )

    assert result.outbound_msg.body.get_message().charge_progress == ChargeProgress.STOP
    assert result.after_send is None
    assert states == [PEVState.C]


async def test_iso2_dc_renegotiation_leaves_the_pilot_in_state_c():
    session = _iso2_session(ac=False)
    states = _record_cp(session)
    await session.ev_controller.enable_charging(True, settle=False)
    session.selected_energy_mode = None
    peer = ScriptedPeer(session, iso2.MeteringReceipt)

    # The charger asks for a renegotiation -> PowerDeliveryReq(Renegotiate).
    result = await peer.feed(
        _v2(session, metering_receipt_res=MeteringReceiptRes(
            response_code="OK",
            dc_evse_status=_dc_status(EVSENotification.RE_NEGOTIATION),
        ))
    )
    assert result.outbound_msg.body.get_message().charge_progress == ChargeProgress.RENEGOTIATE
    assert result.after_send is None

    # PowerDeliveryRes -> the renewed ChargeParameterDiscoveryReq.
    result = await peer.feed(
        _v2(session, power_delivery_res=PowerDeliveryRes(
            response_code="OK", dc_evse_status=_dc_status()
        ))
    )
    assert result.next_state is iso2.ChargeParameterDiscovery
    assert result.after_send is None

    # ...and its response. Charging is "enabled" again, with nothing to write.
    result = await peer.feed(_cpd_finished(session))
    assert result.after_send is None
    assert states == [PEVState.C], "the pilot never left State C"


# ---------------------------------------------------------------------------
# ISO 15118-20
# ---------------------------------------------------------------------------


def _iso20_session(*, ac: bool) -> StubCommSession:
    config = EVCCConfig.from_personality(EVCCPersonality())
    session = StubCommSession(
        protocol=Protocol.ISO_15118_20_AC if ac else Protocol.ISO_15118_20_DC,
        session_id=bytes(1).hex(),
    )
    session.config = config
    session.ev_controller = SimEVController(config)
    session.live_control = None
    session.writer = StubWriter()
    session.selected_energy_service = SelectedEnergyService(
        service=ServiceV20.AC if ac else ServiceV20.DC,
        is_free=False,
        parameter_set=ParameterSet(id=1, parameters=[]),
    )
    session.selected_charging_type_is_ac = ac
    session.control_mode = ControlMode.DYNAMIC
    session.renegotiation_requested = False
    session.charging_session_stop_v20 = None
    session.ev_processing = Processing.FINISHED
    session.ongoing_timer = -1
    session.schedule_exchange_res = None
    return session


def _schedule_exchange_res(session, go_to_pause=None) -> ScheduleExchangeRes:
    return ScheduleExchangeRes(
        header=MessageHeaderV20(session_id=session.session_id, timestamp=int(time())),
        response_code="OK",
        evse_processing=Processing.FINISHED,
        dynamic_params=DynamicScheduleExchangeResParams(),
        go_to_pause=go_to_pause,
    )


def _ev_schedule_ready(monkeypatch, ready: bool) -> None:
    """Pin the simulated EV's coin flip on whether its power profile is ready."""
    monkeypatch.setattr(random, "getrandbits", lambda _bits: int(ready))


async def test_iso20_ac_start_drives_state_c_only_after_the_request_is_sent(
    monkeypatch,
):
    _ev_schedule_ready(monkeypatch, True)
    session = _iso20_session(ac=True)
    states = _record_cp(session)
    peer = ScriptedPeer(session, iso20.ScheduleExchange)

    result = await peer.feed(_schedule_exchange_res(session))

    assert result.next_state is iso20.PowerDelivery
    assert result.outbound_msg.charge_progress == ChargeProgressV20.START
    assert result.outbound_msg.ev_processing == Processing.FINISHED
    assert states == [], "State B must hold while PowerDeliveryReq(Start) leaves"
    await result.after_send()
    assert states == [PEVState.C]


async def test_iso20_ac_ongoing_power_delivery_req_does_not_drive_state_c(
    monkeypatch,
):
    _ev_schedule_ready(monkeypatch, False)
    session = _iso20_session(ac=True)
    states = _record_cp(session)
    peer = ScriptedPeer(session, iso20.ScheduleExchange)

    result = await peer.feed(_schedule_exchange_res(session))

    assert result.outbound_msg.ev_processing == Processing.ONGOING
    assert result.after_send is None
    assert states == []

    # The follow-up request, once the EV has finished, is the one that starts.
    _ev_schedule_ready(monkeypatch, True)
    result = await peer.feed(
        PowerDeliveryResV20(
            header=MessageHeaderV20(
                session_id=session.session_id, timestamp=int(time())
            ),
            response_code="OK",
        )
    )
    assert result.outbound_msg.ev_processing == Processing.FINISHED
    assert states == []
    await result.after_send()
    assert states == [PEVState.C]


async def test_iso20_ac_pause_stop_does_not_drive_state_c(monkeypatch):
    _ev_schedule_ready(monkeypatch, True)
    session = _iso20_session(ac=True)
    states = _record_cp(session)
    peer = ScriptedPeer(session, iso20.ScheduleExchange)

    result = await peer.feed(_schedule_exchange_res(session, go_to_pause=True))

    assert result.outbound_msg.charge_progress == ChargeProgressV20.STOP
    assert result.after_send is None
    assert states == []


async def test_iso20_dc_still_drives_state_c_before_cable_check_req(monkeypatch):
    _ev_schedule_ready(monkeypatch, True)
    session = _iso20_session(ac=False)
    states = _record_cp(session)
    peer = ScriptedPeer(session, iso20.ScheduleExchange)

    result = await peer.feed(_schedule_exchange_res(session))

    assert result.next_state is iso20.DCCableCheck
    assert states == [PEVState.C]
    assert result.after_send is None


@pytest.mark.parametrize("ac", [True, False], ids=["ac", "dc"])
async def test_iso20_stop_drives_state_b_once_sent_on_ac_only(ac):
    session = _iso20_session(ac=ac)
    states = _record_cp(session)
    await session.ev_controller.enable_charging(True, settle=False)
    state = iso20.PowerDelivery(session)

    state.stop_v20_charging(next_state=iso20.PowerDelivery)

    assert states == [PEVState.C]
    if not ac:
        assert state.after_send is None, "DC stays in C until the response"
        return
    await state.after_send()
    assert states == [PEVState.C, PEVState.B]


# ---------------------------------------------------------------------------
# Abort paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("charging", [False, True], ids=["before_charging", "charging"])
async def test_stop_state_machine_drives_state_b_at_once(charging):
    session = _iso2_session(ac=False)
    states = _record_cp(session)
    if charging:
        await session.ev_controller.enable_charging(True, settle=False)
    state = iso2.CurrentDemand(session)

    state.stop_state_machine("forced abort")

    assert state.next_state is Terminate
    assert states[-1] is PEVState.B


@pytest.mark.parametrize("charging", [False, True], ids=["before_charging", "charging"])
async def test_shutdown_routine_drives_state_b_before_its_delay(
    charging, monkeypatch
):
    events: list = []
    controller = SimEVController(
        EVCCConfig.from_personality(EVCCPersonality()),
        cp_state_setter=events.append,
    )
    if charging:
        await controller.enable_charging(True, settle=False)
        events.clear()

    async def recorded_sleep(seconds):
        events.append(f"sleep {seconds}")

    monkeypatch.setattr(comm_session_module.asyncio, "sleep", recorded_sleep)

    class _Writer:
        def close(self):
            events.append("tcp close")

        async def wait_closed(self):
            pass

    machine = SimpleNamespace(
        comm_session=SimpleNamespace(ev_controller=controller),
        current_state=SimpleNamespace(next_state=Terminate),
        writer=_Writer(),
        peer_name="peer",
    )

    await V2GCommunicationSession.stop(machine, "forced abort")

    assert events == [PEVState.B, "sleep 2", "sleep 3", "tcp close"]
