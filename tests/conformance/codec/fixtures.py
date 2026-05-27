"""Codec-layer fixture registry.

Per ADR-0003:

    Fixtures are `(pydantic_model, expected_bytes)` pairs.
    Bootstrapped from the current (Exificient) codec during ADR-0002 Slices 1–3.
    Rebaselined against EXPy at ADR-0002 Slice 5.

Each fixture is a `CodecFixture` registered in `FIXTURES`. The codec test
discovers entries by iterating this list. Per-protocol fixture growth happens
in EXPy Slices 1–3 (#12 / #13 / #14) — they add entries here. Slice 1 seeds
the full DIN message-type corpus from the current Exificient codec.

Why a Python registry rather than data files: the messages are pydantic
models, the namespace is an enum, and constructing them in Python is the
clearest single-source-of-truth. The golden bytes are stored next to the
registry as `.bin` files, named by the fixture id.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from pydantic import BaseModel

GOLDENS_DIR = Path(__file__).parent / "goldens"


@dataclass(frozen=True)
class CodecFixture:
    id: str
    protocol: str  # "din70121" | "iso15118-2" | "iso15118-20"
    namespace: str
    build: Callable[[], BaseModel]

    @property
    def golden_path(self) -> Path:
        return GOLDENS_DIR / f"{self.id}.bin"


def _din_namespace() -> str:
    from app.shared.messages.enums import Namespace

    return Namespace.DIN_MSG_DEF


# --- DIN 70121 builders ---------------------------------------------------
#
# Each builder constructs a `V2GMessage` wrapping one DIN body message.
# Values are spec-valid but otherwise arbitrary; the goal is shape coverage,
# not behavioural realism.


def _din_header(session_id: str = "0011223344556677"):
    from app.shared.messages.din_spec.header import MessageHeader

    return MessageHeader(session_id=session_id)


def _din_wrap(body):
    from app.shared.messages.din_spec.msgdef import V2GMessage

    return V2GMessage(header=_din_header(), body=body)


def _din_session_setup_req():
    from app.shared.messages.din_spec.body import Body, SessionSetupReq

    return _din_wrap(Body(session_setup_req=SessionSetupReq(evcc_id="00112233445566")))


def _din_session_setup_res():
    from app.shared.messages.din_spec.body import Body, SessionSetupRes
    from app.shared.messages.din_spec.datatypes import ResponseCode

    return _din_wrap(
        Body(
            session_setup_res=SessionSetupRes(
                response_code=ResponseCode.OK_NEW_SESSION_ESTABLISHED,
                evse_id="49A89A6360",
                datetime_now=1700000000,
            )
        )
    )


def _din_service_discovery_req():
    from app.shared.messages.din_spec.body import Body, ServiceDiscoveryReq

    return _din_wrap(Body(service_discovery_req=ServiceDiscoveryReq()))


def _din_service_discovery_req_with_optionals():
    from app.shared.messages.din_spec.body import Body, ServiceDiscoveryReq
    from app.shared.messages.din_spec.datatypes import ServiceCategory

    return _din_wrap(
        Body(
            service_discovery_req=ServiceDiscoveryReq(
                service_scope="any",
                service_category=ServiceCategory.CHARGING,
            )
        )
    )


def _din_service_discovery_res():
    from app.shared.messages.din_spec.body import Body, ServiceDiscoveryRes
    from app.shared.messages.din_spec.datatypes import (
        AuthOptionList,
        ChargeService,
        ResponseCode,
        ServiceCategory,
        ServiceDetails,
        ServiceID,
        ServiceName,
    )
    from app.shared.messages.enums import AuthEnum, EnergyTransferModeEnum

    return _din_wrap(
        Body(
            service_discovery_res=ServiceDiscoveryRes(
                response_code=ResponseCode.OK,
                auth_option_list=AuthOptionList(auth_options=[AuthEnum.EIM_V2]),
                charge_service=ChargeService(
                    service_tag=ServiceDetails(
                        service_id=ServiceID.CHARGING,
                        service_name=ServiceName.CHARGING,
                        service_category=ServiceCategory.CHARGING,
                    ),
                    free_service=True,
                    energy_transfer_type=EnergyTransferModeEnum.DC_EXTENDED,
                ),
            )
        )
    )


def _din_service_payment_selection_req():
    from app.shared.messages.datatypes import SelectedService, SelectedServiceList
    from app.shared.messages.din_spec.body import Body, ServicePaymentSelectionReq
    from app.shared.messages.enums import AuthEnum

    return _din_wrap(
        Body(
            service_payment_selection_req=ServicePaymentSelectionReq(
                selected_payment_option=AuthEnum.EIM_V2,
                selected_service_list=SelectedServiceList(
                    selected_service=[SelectedService(service_id=1)]
                ),
            )
        )
    )


def _din_service_payment_selection_res():
    from app.shared.messages.din_spec.body import Body, ServicePaymentSelectionRes
    from app.shared.messages.din_spec.datatypes import ResponseCode

    return _din_wrap(
        Body(
            service_payment_selection_res=ServicePaymentSelectionRes(
                response_code=ResponseCode.OK
            )
        )
    )


def _din_contract_authentication_req():
    from app.shared.messages.din_spec.body import Body, ContractAuthenticationReq

    return _din_wrap(Body(contract_authentication_req=ContractAuthenticationReq()))


def _din_contract_authentication_res():
    from app.shared.messages.din_spec.body import Body, ContractAuthenticationRes
    from app.shared.messages.din_spec.datatypes import ResponseCode
    from app.shared.messages.enums import EVSEProcessing

    return _din_wrap(
        Body(
            contract_authentication_res=ContractAuthenticationRes(
                response_code=ResponseCode.OK,
                evse_processing=EVSEProcessing.FINISHED,
            )
        )
    )


def _dc_ev_status():
    from app.shared.messages.din_spec.datatypes import DCEVStatus
    from app.shared.messages.enums import DCEVErrorCode

    return DCEVStatus(
        ev_ready=True,
        ev_error_code=DCEVErrorCode.NO_ERROR,
        ev_ress_soc=42,
    )


def _dc_evse_status():
    from app.shared.messages.datatypes import DCEVSEStatus, DCEVSEStatusCode
    from app.shared.messages.din_spec.datatypes import EVSENotification
    from app.shared.messages.enums import IsolationLevel

    return DCEVSEStatus(
        notification_max_delay=0,
        evse_notification=EVSENotification.NONE,
        evse_isolation_status=IsolationLevel.VALID,
        evse_status_code=DCEVSEStatusCode.EVSE_READY,
    )


def _pv(cls, value: int, multiplier: int = 0):
    """Build a PhysicalValue subclass. If `Unit` is required, default to the
    subclass's only-allowed UnitSymbol."""
    kwargs = {"value": value, "multiplier": multiplier}
    field = cls.model_fields.get("unit")
    if field is not None and field.is_required():
        import typing as _t

        ann = field.annotation
        # Literal[UnitSymbol.X] → first arg
        args = _t.get_args(ann)
        if args:
            kwargs["unit"] = args[0]
    return cls(**kwargs)


def _din_charge_parameter_discovery_req():
    from app.shared.messages.datatypes import (
        PVEVMaxCurrentLimitDin,
        PVEVMaxPowerLimitDin,
        PVEVMaxVoltageLimitDin,
    )
    from app.shared.messages.din_spec.body import Body, ChargeParameterDiscoveryReq
    from app.shared.messages.din_spec.datatypes import DCEVChargeParameter
    from app.shared.messages.enums import EnergyTransferModeEnum

    return _din_wrap(
        Body(
            charge_parameter_discovery_req=ChargeParameterDiscoveryReq(
                requested_energy_mode=EnergyTransferModeEnum.DC_EXTENDED,
                dc_ev_charge_parameter=DCEVChargeParameter(
                    dc_ev_status=_dc_ev_status(),
                    ev_maximum_current_limit=_pv(PVEVMaxCurrentLimitDin, 32),
                    ev_maximum_power_limit=_pv(PVEVMaxPowerLimitDin, 10, 3),
                    ev_maximum_voltage_limit=_pv(PVEVMaxVoltageLimitDin, 400),
                ),
            )
        )
    )


def _din_charge_parameter_discovery_res():
    from app.shared.messages.datatypes import (
        PVEVSEMaxCurrentLimit,
        PVEVSEMaxPowerLimit,
        PVEVSEMaxVoltageLimit,
        PVEVSEMinCurrentLimit,
        PVEVSEMinVoltageLimit,
        PVEVSEPeakCurrentRipple,
        DCEVSEChargeParameter,
    )
    from app.shared.messages.din_spec.body import Body, ChargeParameterDiscoveryRes
    from app.shared.messages.din_spec.datatypes import (
        PMaxScheduleEntry,
        PMaxScheduleEntryDetails,
        RelativeTimeInterval,
        ResponseCode,
        SAScheduleList,
        SAScheduleTupleEntry,
    )
    from app.shared.messages.enums import EVSEProcessing

    schedule = SAScheduleList(
        values=[
            SAScheduleTupleEntry(
                sa_schedule_tuple_id=1,
                p_max_schedule=PMaxScheduleEntry(
                    p_max_schedule_id=1,
                    entry_details=[
                        PMaxScheduleEntryDetails(
                            p_max=22000,
                            time_interval=RelativeTimeInterval(start=0, duration=3600),
                        )
                    ],
                ),
            )
        ]
    )
    dc_params = DCEVSEChargeParameter(
        dc_evse_status=_dc_evse_status(),
        evse_maximum_current_limit=_pv(PVEVSEMaxCurrentLimit, 200),
        evse_maximum_power_limit=_pv(PVEVSEMaxPowerLimit, 80, 3),
        evse_maximum_voltage_limit=_pv(PVEVSEMaxVoltageLimit, 500),
        evse_minimum_current_limit=_pv(PVEVSEMinCurrentLimit, 0),
        evse_minimum_voltage_limit=_pv(PVEVSEMinVoltageLimit, 200),
        evse_peak_current_ripple=_pv(PVEVSEPeakCurrentRipple, 1),
    )

    return _din_wrap(
        Body(
            charge_parameter_discovery_res=ChargeParameterDiscoveryRes(
                response_code=ResponseCode.OK,
                evse_processing=EVSEProcessing.FINISHED,
                sa_schedule_list=schedule,
                dc_charge_parameter=dc_params,
            )
        )
    )


def _din_cable_check_req():
    from app.shared.messages.din_spec.body import Body, CableCheckReq

    return _din_wrap(Body(cable_check_req=CableCheckReq(dc_ev_status=_dc_ev_status())))


def _din_cable_check_res():
    from app.shared.messages.din_spec.body import Body, CableCheckRes
    from app.shared.messages.din_spec.datatypes import ResponseCode
    from app.shared.messages.enums import EVSEProcessing

    return _din_wrap(
        Body(
            cable_check_res=CableCheckRes(
                response_code=ResponseCode.OK,
                dc_evse_status=_dc_evse_status(),
                evse_processing=EVSEProcessing.FINISHED,
            )
        )
    )


def _din_precharge_req():
    from app.shared.messages.datatypes import PVEVTargetCurrentDin, PVEVTargetVoltageDin
    from app.shared.messages.din_spec.body import Body, PreChargeReq

    return _din_wrap(
        Body(
            pre_charge_req=PreChargeReq(
                dc_ev_status=_dc_ev_status(),
                ev_target_voltage=_pv(PVEVTargetVoltageDin, 400),
                ev_target_current=_pv(PVEVTargetCurrentDin, 1),
            )
        )
    )


def _din_precharge_res():
    from app.shared.messages.datatypes import PVEVSEPresentVoltageDin
    from app.shared.messages.din_spec.body import Body, PreChargeRes
    from app.shared.messages.din_spec.datatypes import ResponseCode

    return _din_wrap(
        Body(
            pre_charge_res=PreChargeRes(
                response_code=ResponseCode.OK,
                dc_evse_status=_dc_evse_status(),
                evse_present_voltage=_pv(PVEVSEPresentVoltageDin, 399),
            )
        )
    )


def _din_power_delivery_req():
    from app.shared.messages.din_spec.body import Body, PowerDeliveryReq

    return _din_wrap(
        Body(power_delivery_req=PowerDeliveryReq(ready_to_charge=True))
    )


def _din_power_delivery_res():
    from app.shared.messages.din_spec.body import Body, PowerDeliveryRes
    from app.shared.messages.din_spec.datatypes import ResponseCode

    return _din_wrap(
        Body(
            power_delivery_res=PowerDeliveryRes(
                response_code=ResponseCode.OK,
                dc_evse_status=_dc_evse_status(),
            )
        )
    )


def _din_current_demand_req():
    from app.shared.messages.datatypes import (
        PVEVMaxCurrentLimitDin,
        PVEVMaxPowerLimitDin,
        PVEVMaxVoltageLimitDin,
        PVEVTargetCurrentDin,
        PVEVTargetVoltageDin,
    )
    from app.shared.messages.din_spec.body import Body, CurrentDemandReq

    return _din_wrap(
        Body(
            current_demand_req=CurrentDemandReq(
                dc_ev_status=_dc_ev_status(),
                ev_target_current=_pv(PVEVTargetCurrentDin, 10),
                ev_max_voltage_limit=_pv(PVEVMaxVoltageLimitDin, 500),
                ev_max_current_limit=_pv(PVEVMaxCurrentLimitDin, 200),
                ev_max_power_limit=_pv(PVEVMaxPowerLimitDin, 50, 3),
                bulk_charging_complete=False,
                charging_complete=False,
                ev_target_voltage=_pv(PVEVTargetVoltageDin, 400),
            )
        )
    )


def _din_current_demand_res():
    from app.shared.messages.datatypes import (
        PVEVSEMaxCurrentLimitDin,
        PVEVSEMaxPowerLimitDin,
        PVEVSEMaxVoltageLimitDin,
        PVEVSEPresentCurrentDin,
        PVEVSEPresentVoltageDin,
    )
    from app.shared.messages.din_spec.body import Body, CurrentDemandRes
    from app.shared.messages.din_spec.datatypes import ResponseCode

    return _din_wrap(
        Body(
            current_demand_res=CurrentDemandRes(
                response_code=ResponseCode.OK,
                dc_evse_status=_dc_evse_status(),
                evse_present_voltage=_pv(PVEVSEPresentVoltageDin, 400),
                evse_present_current=_pv(PVEVSEPresentCurrentDin, 10),
                evse_current_limit_achieved=False,
                evse_voltage_limit_achieved=False,
                evse_power_limit_achieved=False,
                evse_max_voltage_limit=_pv(PVEVSEMaxVoltageLimitDin, 500),
                evse_max_current_limit=_pv(PVEVSEMaxCurrentLimitDin, 200),
                evse_max_power_limit=_pv(PVEVSEMaxPowerLimitDin, 80, 3),
            )
        )
    )


def _din_welding_detection_req():
    from app.shared.messages.din_spec.body import Body, WeldingDetectionReq

    return _din_wrap(
        Body(welding_detection_req=WeldingDetectionReq(dc_ev_status=_dc_ev_status()))
    )


def _din_welding_detection_res():
    from app.shared.messages.datatypes import PVEVSEPresentVoltageDin
    from app.shared.messages.din_spec.body import Body, WeldingDetectionRes
    from app.shared.messages.din_spec.datatypes import ResponseCode

    return _din_wrap(
        Body(
            welding_detection_res=WeldingDetectionRes(
                response_code=ResponseCode.OK,
                dc_evse_status=_dc_evse_status(),
                evse_present_voltage=_pv(PVEVSEPresentVoltageDin, 2),
            )
        )
    )


def _din_session_stop_req():
    from app.shared.messages.din_spec.body import Body, SessionStopReq

    return _din_wrap(Body(session_stop_req=SessionStopReq()))


def _din_session_stop_res():
    from app.shared.messages.din_spec.body import Body, SessionStopRes
    from app.shared.messages.din_spec.datatypes import ResponseCode

    return _din_wrap(Body(session_stop_res=SessionStopRes(response_code=ResponseCode.OK)))


def _din_fixture(id_: str, build: Callable[[], BaseModel]) -> CodecFixture:
    return CodecFixture(id=id_, protocol="din70121", namespace=_din_namespace(), build=build)


FIXTURES: list[CodecFixture] = [
    _din_fixture("din-session-setup-req", _din_session_setup_req),
    _din_fixture("din-session-setup-res", _din_session_setup_res),
    _din_fixture("din-service-discovery-req", _din_service_discovery_req),
    _din_fixture(
        "din-service-discovery-req-with-optionals",
        _din_service_discovery_req_with_optionals,
    ),
    _din_fixture("din-service-discovery-res", _din_service_discovery_res),
    _din_fixture(
        "din-service-payment-selection-req", _din_service_payment_selection_req
    ),
    _din_fixture(
        "din-service-payment-selection-res", _din_service_payment_selection_res
    ),
    _din_fixture(
        "din-contract-authentication-req", _din_contract_authentication_req
    ),
    _din_fixture(
        "din-contract-authentication-res", _din_contract_authentication_res
    ),
    _din_fixture(
        "din-charge-parameter-discovery-req", _din_charge_parameter_discovery_req
    ),
    _din_fixture(
        "din-charge-parameter-discovery-res", _din_charge_parameter_discovery_res
    ),
    _din_fixture("din-cable-check-req", _din_cable_check_req),
    _din_fixture("din-cable-check-res", _din_cable_check_res),
    _din_fixture("din-precharge-req", _din_precharge_req),
    _din_fixture("din-precharge-res", _din_precharge_res),
    _din_fixture("din-power-delivery-req", _din_power_delivery_req),
    _din_fixture("din-power-delivery-res", _din_power_delivery_res),
    _din_fixture("din-current-demand-req", _din_current_demand_req),
    _din_fixture("din-current-demand-res", _din_current_demand_res),
    _din_fixture("din-welding-detection-req", _din_welding_detection_req),
    _din_fixture("din-welding-detection-res", _din_welding_detection_res),
    _din_fixture("din-session-stop-req", _din_session_stop_req),
    _din_fixture("din-session-stop-res", _din_session_stop_res),
]
