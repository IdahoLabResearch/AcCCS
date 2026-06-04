"""Codec-layer fixture registry.

Per ADR-0003:

    Fixtures are `(pydantic_model, expected_bytes)` pairs.
    Bootstrapped from the legacy (Exificient) codec during ADR-0002 Slices 1–3.
    Rebaselined against EXPy at ADR-0002 Slice 5 — the golden bytes are now
    EXPy output.

Each fixture is a `CodecFixture` registered in `FIXTURES`. The codec test
discovers entries by iterating this list. Per-protocol fixture growth happened
in EXPy Slices 1–3 (#12 / #13 / #14), which seeded the DIN/ISO message-type
corpus (bootstrapped from the then-current Exificient codec, since rebaselined
against EXPy).

Why a Python registry rather than data files: the messages are pydantic
models, the namespace is an enum, and constructing them in Python is the
clearest single-source-of-truth. The golden bytes are stored next to the
registry as `.bin` files, named by the fixture id.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal, Optional, Type

from pydantic import BaseModel

GOLDENS_DIR = Path(__file__).parent / "goldens"

RootKind = Literal["document", "fragment", "xmldsig"]


@dataclass(frozen=True)
class CodecFixture:
    id: str
    protocol: str  # "din70121" | "iso15118-2" | "iso15118-20"
    namespace: str
    build: Callable[[], BaseModel]
    root_kind: RootKind = "document"
    # Override the default ``str(model)`` root name. Required for
    # :class:`CertificateChain`-typed fragments (``ContractSignatureCertChain``
    # vs ``SAProvisioningCertificateChain``) and similar context-dependent
    # XSD element names.
    root_name: Optional[str] = None
    # When set, golden bytes are produced by EXPy via the translation module
    # rather than the legacy Exificient codec. Used for fragment payloads
    # where the legacy Exificient codec produced output that even Exificient
    # could not decode (e.g. ``eMAID`` — see ADR-0002 Slice 5 rebaselining).
    expy_authoritative: bool = False
    model_cls: Optional[Type[BaseModel]] = None

    @property
    def golden_path(self) -> Path:
        return GOLDENS_DIR / f"{self.id}.bin"

    @property
    def decode_model_cls(self) -> Type[BaseModel]:
        if self.model_cls is not None:
            return self.model_cls
        return type(self.build())


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


# --- ISO 15118-2 builders -------------------------------------------------
#
# Same approach as the DIN block: each builder constructs a ``V2GMessage``
# wrapping one ISO-2 body message with spec-valid (but otherwise arbitrary)
# values. Field/shape coverage matters; exhaustive realism does not.


def _iso2_namespace() -> str:
    from app.shared.messages.enums import Namespace

    return Namespace.ISO_V2_MSG_DEF


def _iso2_header(session_id: str = "0011223344556677"):
    from app.shared.messages.iso15118_2.header import MessageHeader

    return MessageHeader(session_id=session_id)


def _iso2_wrap(body):
    from app.shared.messages.iso15118_2.msgdef import V2GMessage

    return V2GMessage(header=_iso2_header(), body=body)


def _iso2_ac_evse_status():
    from app.shared.messages.datatypes import EVSENotification
    from app.shared.messages.iso15118_2.datatypes import ACEVSEStatus

    return ACEVSEStatus(
        notification_max_delay=0,
        evse_notification=EVSENotification.NONE,
        rcd=False,
    )


def _iso2_dc_ev_status():
    from app.shared.messages.iso15118_2.datatypes import DCEVStatus
    from app.shared.messages.enums import DCEVErrorCode

    return DCEVStatus(
        ev_ready=True,
        ev_error_code=DCEVErrorCode.NO_ERROR,
        ev_ress_soc=42,
    )


def _iso2_dc_evse_status():
    from app.shared.messages.datatypes import DCEVSEStatus, DCEVSEStatusCode
    from app.shared.messages.datatypes import EVSENotification
    from app.shared.messages.enums import IsolationLevel

    return DCEVSEStatus(
        notification_max_delay=0,
        evse_notification=EVSENotification.NONE,
        evse_isolation_status=IsolationLevel.VALID,
        evse_status_code=DCEVSEStatusCode.EVSE_READY,
    )


def _iso2_session_setup_req():
    from app.shared.messages.iso15118_2.body import Body, SessionSetupReq

    return _iso2_wrap(Body(session_setup_req=SessionSetupReq(evcc_id="001122334455")))


def _iso2_session_setup_res():
    from app.shared.messages.iso15118_2.body import Body, SessionSetupRes
    from app.shared.messages.iso15118_2.datatypes import ResponseCode

    return _iso2_wrap(
        Body(
            session_setup_res=SessionSetupRes(
                response_code=ResponseCode.OK_NEW_SESSION_ESTABLISHED,
                evse_id="DE*ICE*E1234",
                evse_timestamp=1700000000,
            )
        )
    )


def _iso2_service_discovery_req():
    from app.shared.messages.iso15118_2.body import Body, ServiceDiscoveryReq
    from app.shared.messages.iso15118_2.datatypes import ServiceCategory

    return _iso2_wrap(
        Body(
            service_discovery_req=ServiceDiscoveryReq(
                service_scope="any",
                service_category=ServiceCategory.CHARGING,
            )
        )
    )


def _iso2_service_discovery_res():
    from app.shared.messages.iso15118_2.body import Body, ServiceDiscoveryRes
    from app.shared.messages.iso15118_2.datatypes import (
        AuthOptionList,
        ChargeService,
        EnergyTransferModeList,
        ResponseCode,
        ServiceCategory,
        ServiceID,
        ServiceName,
    )
    from app.shared.messages.enums import AuthEnum, EnergyTransferModeEnum

    return _iso2_wrap(
        Body(
            service_discovery_res=ServiceDiscoveryRes(
                response_code=ResponseCode.OK,
                auth_option_list=AuthOptionList(auth_options=[AuthEnum.EIM_V2]),
                charge_service=ChargeService(
                    service_id=ServiceID.CHARGING,
                    service_name=ServiceName.CHARGING,
                    service_category=ServiceCategory.CHARGING,
                    free_service=True,
                    supported_energy_transfer_mode=EnergyTransferModeList(
                        energy_modes=[EnergyTransferModeEnum.DC_EXTENDED]
                    ),
                ),
            )
        )
    )


def _iso2_service_detail_req():
    from app.shared.messages.iso15118_2.body import Body, ServiceDetailReq

    return _iso2_wrap(Body(service_detail_req=ServiceDetailReq(service_id=1)))


def _iso2_service_detail_res():
    from app.shared.messages.iso15118_2.body import Body, ServiceDetailRes
    from app.shared.messages.iso15118_2.datatypes import ResponseCode

    return _iso2_wrap(
        Body(
            service_detail_res=ServiceDetailRes(
                response_code=ResponseCode.OK,
                service_id=1,
            )
        )
    )


def _iso2_payment_service_selection_req():
    from app.shared.messages.datatypes import SelectedService, SelectedServiceList
    from app.shared.messages.iso15118_2.body import Body, PaymentServiceSelectionReq
    from app.shared.messages.enums import AuthEnum

    return _iso2_wrap(
        Body(
            payment_service_selection_req=PaymentServiceSelectionReq(
                selected_auth_option=AuthEnum.EIM_V2,
                selected_service_list=SelectedServiceList(
                    selected_service=[SelectedService(service_id=1)]
                ),
            )
        )
    )


def _iso2_payment_service_selection_res():
    from app.shared.messages.iso15118_2.body import Body, PaymentServiceSelectionRes
    from app.shared.messages.iso15118_2.datatypes import ResponseCode

    return _iso2_wrap(
        Body(payment_service_selection_res=PaymentServiceSelectionRes(response_code=ResponseCode.OK))
    )


def _iso2_root_cert_id_list():
    from app.shared.messages.iso15118_2.datatypes import RootCertificateIDList
    from app.shared.messages.xmldsig import X509IssuerSerial

    return RootCertificateIDList(
        x509_issuer_serials=[
            X509IssuerSerial(x509_issuer_name="CN=Test", x509_serial_number=42)
        ]
    )


def _iso2_certificate_chain(*, with_id: bool = True, with_sub: bool = True):
    """Build a representative :class:`CertificateChain`.

    *with_id* controls whether the ``Id`` attribute is emitted. The XSD
    permits ``Id`` on ``ContractSignatureCertChain`` (it's referenced by the
    XML-Signature) but not on ``SAProvisioningCertificateChain``.

    *with_sub* controls whether ``SubCertificates`` is emitted. libcbv2g
    rejects ``CertificateInstallationRes`` / ``CertificateUpdateRes``
    documents when both inner chains carry ``SubCertificates`` (likely a
    shared-state bug in the generated codec — see EXPy issue tracker);
    callers should omit it on one chain to stay within the encoder's
    tolerance for now.
    """
    from app.shared.messages.iso15118_2.datatypes import (
        CertificateChain,
        SubCertificates,
    )

    kwargs = dict(certificate=b"\x30" + b"\x01" * 30)
    if with_id:
        kwargs["id"] = "id1"
    if with_sub:
        kwargs["sub_certificates"] = SubCertificates(
            certificates=[b"\x30" + b"\x02" * 20]
        )
    return CertificateChain(**kwargs)


def _iso2_certificate_installation_req():
    from app.shared.messages.iso15118_2.body import Body, CertificateInstallationReq

    return _iso2_wrap(
        Body(
            certificate_installation_req=CertificateInstallationReq(
                id="id1",
                oem_provisioning_cert=b"\x30" + b"\x01" * 50,
                list_of_root_cert_ids=_iso2_root_cert_id_list(),
            )
        )
    )


def _iso2_certificate_installation_res():
    from app.shared.messages.iso15118_2.body import Body, CertificateInstallationRes
    from app.shared.messages.iso15118_2.datatypes import (
        DHPublicKey,
        EMAID,
        EncryptedPrivateKey,
        ResponseCode,
    )

    return _iso2_wrap(
        Body(
            certificate_installation_res=CertificateInstallationRes(
                response_code=ResponseCode.OK,
                cps_cert_chain=_iso2_certificate_chain(with_id=False, with_sub=False),
                contract_cert_chain=_iso2_certificate_chain(),
                encrypted_private_key=EncryptedPrivateKey(id="id2", value=b"\x02" * 48),
                dh_public_key=DHPublicKey(id="id3", value=b"\x03" * 65),
                emaid=EMAID(id="id4", value="DE8AA1A2B3C4D5"),
            )
        )
    )


def _iso2_certificate_update_req():
    from app.shared.messages.iso15118_2.body import Body, CertificateUpdateReq
    from app.shared.messages.iso15118_2.datatypes import EMAID

    # NB: ``CertificateUpdateReq.eMAID`` is a bare string in libcbv2g
    # (``eMAID: str`` in ``CertificateUpdateReqType``) — distinct from
    # ``CertificateInstallationRes.eMAID`` which is an :class:`EMAIDType`
    # wrapper with an ``Id`` attribute. AcCCS's Pydantic model represents
    # both as :class:`EMAID`; here we drop the ``Id`` so the encoded form
    # matches the simple-string shape libcbv2g expects.
    return _iso2_wrap(
        Body(
            certificate_update_req=CertificateUpdateReq(
                id="id1",
                contract_cert_chain=_iso2_certificate_chain(),
                emaid=EMAID(id="id4", value="DE8AA1A2B3C4D5"),
                list_of_root_cert_ids=_iso2_root_cert_id_list(),
            )
        )
    )


def _iso2_certificate_update_res():
    from app.shared.messages.iso15118_2.body import Body, CertificateUpdateRes
    from app.shared.messages.iso15118_2.datatypes import (
        DHPublicKey,
        EMAID,
        EncryptedPrivateKey,
        ResponseCode,
    )

    return _iso2_wrap(
        Body(
            certificate_update_res=CertificateUpdateRes(
                response_code=ResponseCode.OK,
                cps_cert_chain=_iso2_certificate_chain(with_id=False, with_sub=False),
                contract_cert_chain=_iso2_certificate_chain(),
                encrypted_private_key=EncryptedPrivateKey(id="id2", value=b"\x02" * 48),
                dh_public_key=DHPublicKey(id="id3", value=b"\x03" * 65),
                emaid=EMAID(id="id4", value="DE8AA1A2B3C4D5"),
            )
        )
    )


def _iso2_payment_details_req():
    from app.shared.messages.iso15118_2.body import Body, PaymentDetailsReq

    return _iso2_wrap(
        Body(
            payment_details_req=PaymentDetailsReq(
                emaid="DE8AA1A2B3C4D5",
                cert_chain=_iso2_certificate_chain(),
            )
        )
    )


def _iso2_payment_details_res():
    from app.shared.messages.iso15118_2.body import Body, PaymentDetailsRes
    from app.shared.messages.iso15118_2.datatypes import ResponseCode

    return _iso2_wrap(
        Body(
            payment_details_res=PaymentDetailsRes(
                response_code=ResponseCode.OK,
                gen_challenge=b"0123456789012345",
                evse_timestamp=1700000000,
            )
        )
    )


def _iso2_authorization_req():
    from app.shared.messages.iso15118_2.body import Body, AuthorizationReq

    return _iso2_wrap(
        Body(
            authorization_req=AuthorizationReq(
                id="id1", gen_challenge=b"0123456789012345"
            )
        )
    )


def _iso2_authorization_res():
    from app.shared.messages.iso15118_2.body import Body, AuthorizationRes
    from app.shared.messages.iso15118_2.datatypes import ResponseCode
    from app.shared.messages.enums import EVSEProcessing

    return _iso2_wrap(
        Body(
            authorization_res=AuthorizationRes(
                response_code=ResponseCode.OK,
                evse_processing=EVSEProcessing.FINISHED,
            )
        )
    )


def _iso2_pv(cls, value: int, multiplier: int = 0):
    kwargs = {"value": value, "multiplier": multiplier}
    field_ = cls.model_fields.get("unit")
    if field_ is not None and field_.is_required():
        import typing as _t

        ann = field_.annotation
        args = _t.get_args(ann)
        if args:
            kwargs["unit"] = args[0]
    return cls(**kwargs)


def _iso2_cable_check_req():
    from app.shared.messages.iso15118_2.body import Body, CableCheckReq

    return _iso2_wrap(
        Body(cable_check_req=CableCheckReq(dc_ev_status=_iso2_dc_ev_status()))
    )


def _iso2_cable_check_res():
    from app.shared.messages.iso15118_2.body import Body, CableCheckRes
    from app.shared.messages.iso15118_2.datatypes import ResponseCode
    from app.shared.messages.enums import EVSEProcessing

    return _iso2_wrap(
        Body(
            cable_check_res=CableCheckRes(
                response_code=ResponseCode.OK,
                dc_evse_status=_iso2_dc_evse_status(),
                evse_processing=EVSEProcessing.FINISHED,
            )
        )
    )


def _iso2_pre_charge_req():
    from app.shared.messages.datatypes import PVEVTargetCurrent, PVEVTargetVoltage
    from app.shared.messages.iso15118_2.body import Body, PreChargeReq

    return _iso2_wrap(
        Body(
            pre_charge_req=PreChargeReq(
                dc_ev_status=_iso2_dc_ev_status(),
                ev_target_voltage=_iso2_pv(PVEVTargetVoltage, 400),
                ev_target_current=_iso2_pv(PVEVTargetCurrent, 1),
            )
        )
    )


def _iso2_pre_charge_res():
    from app.shared.messages.datatypes import PVEVSEPresentVoltage
    from app.shared.messages.iso15118_2.body import Body, PreChargeRes
    from app.shared.messages.iso15118_2.datatypes import ResponseCode

    return _iso2_wrap(
        Body(
            pre_charge_res=PreChargeRes(
                response_code=ResponseCode.OK,
                dc_evse_status=_iso2_dc_evse_status(),
                evse_present_voltage=_iso2_pv(PVEVSEPresentVoltage, 399),
            )
        )
    )


def _iso2_charge_parameter_discovery_req():
    from app.shared.messages.datatypes import (
        PVEVMaxCurrentLimit,
        PVEVMaxPowerLimit,
        PVEVMaxVoltageLimit,
    )
    from app.shared.messages.iso15118_2.body import Body, ChargeParameterDiscoveryReq
    from app.shared.messages.iso15118_2.datatypes import DCEVChargeParameter
    from app.shared.messages.enums import EnergyTransferModeEnum

    return _iso2_wrap(
        Body(
            charge_parameter_discovery_req=ChargeParameterDiscoveryReq(
                requested_energy_mode=EnergyTransferModeEnum.DC_EXTENDED,
                dc_ev_charge_parameter=DCEVChargeParameter(
                    dc_ev_status=_iso2_dc_ev_status(),
                    ev_maximum_current_limit=_iso2_pv(PVEVMaxCurrentLimit, 32),
                    ev_maximum_power_limit=_iso2_pv(PVEVMaxPowerLimit, 10, 3),
                    ev_maximum_voltage_limit=_iso2_pv(PVEVMaxVoltageLimit, 400),
                ),
            )
        )
    )


def _iso2_charge_parameter_discovery_res():
    from app.shared.messages.datatypes import (
        DCEVSEChargeParameter,
        PVEVSEMaxCurrentLimit,
        PVEVSEMaxPowerLimit,
        PVEVSEMaxVoltageLimit,
        PVEVSEMinCurrentLimit,
        PVEVSEMinVoltageLimit,
        PVEVSEPeakCurrentRipple,
    )
    from app.shared.messages.iso15118_2.body import Body, ChargeParameterDiscoveryRes
    from app.shared.messages.iso15118_2.datatypes import (
        PMaxSchedule,
        PMaxScheduleEntry,
        ResponseCode,
        RelativeTimeInterval,
        SAScheduleList,
        SAScheduleTuple,
    )
    from app.shared.messages.datatypes import PVPMax
    from app.shared.messages.enums import EVSEProcessing

    schedule = SAScheduleList(
        schedule_tuples=[
            SAScheduleTuple(
                sa_schedule_tuple_id=1,
                p_max_schedule=PMaxSchedule(
                    schedule_entries=[
                        PMaxScheduleEntry(
                            p_max=_iso2_pv(PVPMax, 22000),
                            time_interval=RelativeTimeInterval(start=0, duration=3600),
                        )
                    ],
                ),
            )
        ]
    )
    dc_params = DCEVSEChargeParameter(
        dc_evse_status=_iso2_dc_evse_status(),
        evse_maximum_current_limit=_iso2_pv(PVEVSEMaxCurrentLimit, 200),
        evse_maximum_power_limit=_iso2_pv(PVEVSEMaxPowerLimit, 80, 3),
        evse_maximum_voltage_limit=_iso2_pv(PVEVSEMaxVoltageLimit, 500),
        evse_minimum_current_limit=_iso2_pv(PVEVSEMinCurrentLimit, 0),
        evse_minimum_voltage_limit=_iso2_pv(PVEVSEMinVoltageLimit, 200),
        evse_peak_current_ripple=_iso2_pv(PVEVSEPeakCurrentRipple, 1),
    )

    return _iso2_wrap(
        Body(
            charge_parameter_discovery_res=ChargeParameterDiscoveryRes(
                response_code=ResponseCode.OK,
                evse_processing=EVSEProcessing.FINISHED,
                sa_schedule_list=schedule,
                dc_charge_parameter=dc_params,
            )
        )
    )


def _iso2_power_delivery_req():
    from app.shared.messages.iso15118_2.body import Body, PowerDeliveryReq
    from app.shared.messages.iso15118_2.datatypes import ChargeProgress

    return _iso2_wrap(
        Body(
            power_delivery_req=PowerDeliveryReq(
                charge_progress=ChargeProgress.START,
                sa_schedule_tuple_id=1,
            )
        )
    )


def _iso2_power_delivery_res():
    from app.shared.messages.iso15118_2.body import Body, PowerDeliveryRes
    from app.shared.messages.iso15118_2.datatypes import ResponseCode

    return _iso2_wrap(
        Body(
            power_delivery_res=PowerDeliveryRes(
                response_code=ResponseCode.OK,
                dc_evse_status=_iso2_dc_evse_status(),
            )
        )
    )


def _iso2_charging_status_req():
    from app.shared.messages.iso15118_2.body import Body, ChargingStatusReq

    return _iso2_wrap(Body(charging_status_req=ChargingStatusReq()))


def _iso2_charging_status_res():
    from app.shared.messages.iso15118_2.body import Body, ChargingStatusRes
    from app.shared.messages.iso15118_2.datatypes import ResponseCode

    return _iso2_wrap(
        Body(
            charging_status_res=ChargingStatusRes(
                response_code=ResponseCode.OK,
                evse_id="DE*ICE*E1234",
                sa_schedule_tuple_id=1,
                ac_evse_status=_iso2_ac_evse_status(),
            )
        )
    )


def _iso2_current_demand_req():
    from app.shared.messages.datatypes import (
        PVEVMaxCurrentLimit,
        PVEVMaxPowerLimit,
        PVEVMaxVoltageLimit,
        PVEVTargetCurrent,
        PVEVTargetVoltage,
    )
    from app.shared.messages.iso15118_2.body import Body, CurrentDemandReq

    return _iso2_wrap(
        Body(
            current_demand_req=CurrentDemandReq(
                dc_ev_status=_iso2_dc_ev_status(),
                ev_target_current=_iso2_pv(PVEVTargetCurrent, 10),
                ev_max_voltage_limit=_iso2_pv(PVEVMaxVoltageLimit, 500),
                ev_max_current_limit=_iso2_pv(PVEVMaxCurrentLimit, 200),
                ev_max_power_limit=_iso2_pv(PVEVMaxPowerLimit, 50, 3),
                bulk_charging_complete=False,
                charging_complete=False,
                ev_target_voltage=_iso2_pv(PVEVTargetVoltage, 400),
            )
        )
    )


def _iso2_current_demand_res():
    from app.shared.messages.datatypes import (
        PVEVSEMaxCurrentLimit,
        PVEVSEMaxPowerLimit,
        PVEVSEMaxVoltageLimit,
        PVEVSEPresentCurrent,
        PVEVSEPresentVoltage,
    )
    from app.shared.messages.iso15118_2.body import Body, CurrentDemandRes
    from app.shared.messages.iso15118_2.datatypes import ResponseCode

    return _iso2_wrap(
        Body(
            current_demand_res=CurrentDemandRes(
                response_code=ResponseCode.OK,
                dc_evse_status=_iso2_dc_evse_status(),
                evse_present_voltage=_iso2_pv(PVEVSEPresentVoltage, 400),
                evse_present_current=_iso2_pv(PVEVSEPresentCurrent, 10),
                evse_current_limit_achieved=False,
                evse_voltage_limit_achieved=False,
                evse_power_limit_achieved=False,
                evse_max_voltage_limit=_iso2_pv(PVEVSEMaxVoltageLimit, 500),
                evse_max_current_limit=_iso2_pv(PVEVSEMaxCurrentLimit, 200),
                evse_max_power_limit=_iso2_pv(PVEVSEMaxPowerLimit, 80, 3),
                evse_id="DE*ICE*E1234",
                sa_schedule_tuple_id=1,
            )
        )
    )


def _iso2_meter_info():
    from app.shared.messages.iso15118_2.datatypes import MeterInfo

    return MeterInfo(meter_id="m1", meter_reading=42, t_meter=1700000000)


def _iso2_metering_receipt_req():
    from app.shared.messages.iso15118_2.body import Body, MeteringReceiptReq

    return _iso2_wrap(
        Body(
            metering_receipt_req=MeteringReceiptReq(
                id="id1",
                session_id="0011223344556677",
                sa_schedule_tuple_id=1,
                meter_info=_iso2_meter_info(),
            )
        )
    )


def _iso2_metering_receipt_res():
    from app.shared.messages.iso15118_2.body import Body, MeteringReceiptRes
    from app.shared.messages.iso15118_2.datatypes import ResponseCode

    return _iso2_wrap(
        Body(
            metering_receipt_res=MeteringReceiptRes(
                response_code=ResponseCode.OK,
                ac_evse_status=_iso2_ac_evse_status(),
            )
        )
    )


def _iso2_welding_detection_req():
    from app.shared.messages.iso15118_2.body import Body, WeldingDetectionReq

    return _iso2_wrap(
        Body(welding_detection_req=WeldingDetectionReq(dc_ev_status=_iso2_dc_ev_status()))
    )


def _iso2_welding_detection_res():
    from app.shared.messages.datatypes import PVEVSEPresentVoltage
    from app.shared.messages.iso15118_2.body import Body, WeldingDetectionRes
    from app.shared.messages.iso15118_2.datatypes import ResponseCode

    return _iso2_wrap(
        Body(
            welding_detection_res=WeldingDetectionRes(
                response_code=ResponseCode.OK,
                dc_evse_status=_iso2_dc_evse_status(),
                evse_present_voltage=_iso2_pv(PVEVSEPresentVoltage, 2),
            )
        )
    )


def _iso2_session_stop_req():
    from app.shared.messages.iso15118_2.body import Body, SessionStopReq
    from app.shared.messages.iso15118_2.datatypes import ChargingSession

    return _iso2_wrap(
        Body(session_stop_req=SessionStopReq(charging_session=ChargingSession.TERMINATE))
    )


def _iso2_session_stop_res():
    from app.shared.messages.iso15118_2.body import Body, SessionStopRes
    from app.shared.messages.iso15118_2.datatypes import ResponseCode

    return _iso2_wrap(Body(session_stop_res=SessionStopRes(response_code=ResponseCode.OK)))


def _iso2_doc(id_: str, build: Callable[[], BaseModel]) -> CodecFixture:
    return CodecFixture(
        id=id_,
        protocol="iso15118-2",
        namespace=_iso2_namespace(),
        build=build,
    )


# --- ISO 15118-2 Fragment / XmldsigFragment builders ---------------------


def _iso2_frag_authorization_req():
    from app.shared.messages.iso15118_2.body import AuthorizationReq

    return AuthorizationReq(id="id1", gen_challenge=b"0123456789012345")


def _iso2_frag_certificate_installation_req():
    from app.shared.messages.iso15118_2.body import CertificateInstallationReq

    return CertificateInstallationReq(
        id="id1",
        oem_provisioning_cert=b"\x30" + b"\x01" * 50,
        list_of_root_cert_ids=_iso2_root_cert_id_list(),
    )


def _iso2_frag_metering_receipt_req():
    from app.shared.messages.iso15118_2.body import MeteringReceiptReq

    return MeteringReceiptReq(
        id="id1",
        session_id="0011223344556677",
        sa_schedule_tuple_id=1,
        meter_info=_iso2_meter_info(),
    )


def _iso2_frag_contract_signature_cert_chain():
    return _iso2_certificate_chain()


def _iso2_frag_encrypted_private_key():
    from app.shared.messages.iso15118_2.datatypes import EncryptedPrivateKey

    return EncryptedPrivateKey(id="id2", value=b"\x02" * 48)


def _iso2_frag_dh_public_key():
    from app.shared.messages.iso15118_2.datatypes import DHPublicKey

    return DHPublicKey(id="id3", value=b"\x03" * 65)


def _iso2_frag_emaid():
    from app.shared.messages.iso15118_2.datatypes import EMAID

    return EMAID(id="id4", value="DE8AA1A2B3C4D5")


def _iso2_xmldsig_signed_info():
    from app.shared.messages.xmldsig import (
        CanonicalizationMethod,
        DigestMethod,
        Reference,
        SignatureMethod,
        SignedInfo,
        Transform,
        Transforms,
    )

    return SignedInfo(
        canonicalization_method=CanonicalizationMethod(
            algorithm="http://www.w3.org/TR/canonical-exi/"
        ),
        signature_method=SignatureMethod(
            algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
        ),
        reference=[
            Reference(
                uri="#id1",
                transforms=Transforms(
                    transform=[
                        Transform(algorithm="http://www.w3.org/TR/canonical-exi/")
                    ]
                ),
                digest_method=DigestMethod(
                    algorithm="http://www.w3.org/2001/04/xmlenc#sha256"
                ),
                digest_value=b"\x00" * 32,
            )
        ],
    )


FIXTURES.extend(
    [
        _iso2_doc("iso2-session-setup-req", _iso2_session_setup_req),
        _iso2_doc("iso2-session-setup-res", _iso2_session_setup_res),
        _iso2_doc("iso2-service-discovery-req", _iso2_service_discovery_req),
        _iso2_doc("iso2-service-discovery-res", _iso2_service_discovery_res),
        _iso2_doc("iso2-service-detail-req", _iso2_service_detail_req),
        _iso2_doc("iso2-service-detail-res", _iso2_service_detail_res),
        _iso2_doc(
            "iso2-payment-service-selection-req", _iso2_payment_service_selection_req
        ),
        _iso2_doc(
            "iso2-payment-service-selection-res", _iso2_payment_service_selection_res
        ),
        _iso2_doc(
            "iso2-certificate-installation-req", _iso2_certificate_installation_req
        ),
        _iso2_doc(
            "iso2-certificate-installation-res", _iso2_certificate_installation_res
        ),
        # ``CertificateUpdateReq.eMAID`` is a structural Pydantic↔libcbv2g
        # mismatch: AcCCS's :class:`EMAID` model requires an ``Id``
        # attribute, but libcbv2g flattens the field to a bare string for
        # this request type. Re-modelling EMAID would change production
        # code, which is out of scope for Slice 2 (ADR-0002). Including
        # only the response here, which is consistent with the simulator
        # call sites — CertificateUpdateReq is unused in the current
        # AcCCS flows.
        _iso2_doc("iso2-certificate-update-res", _iso2_certificate_update_res),
        _iso2_doc("iso2-payment-details-req", _iso2_payment_details_req),
        _iso2_doc("iso2-payment-details-res", _iso2_payment_details_res),
        _iso2_doc("iso2-authorization-req", _iso2_authorization_req),
        _iso2_doc("iso2-authorization-res", _iso2_authorization_res),
        _iso2_doc("iso2-cable-check-req", _iso2_cable_check_req),
        _iso2_doc("iso2-cable-check-res", _iso2_cable_check_res),
        _iso2_doc("iso2-pre-charge-req", _iso2_pre_charge_req),
        _iso2_doc("iso2-pre-charge-res", _iso2_pre_charge_res),
        _iso2_doc(
            "iso2-charge-parameter-discovery-req",
            _iso2_charge_parameter_discovery_req,
        ),
        _iso2_doc(
            "iso2-charge-parameter-discovery-res",
            _iso2_charge_parameter_discovery_res,
        ),
        _iso2_doc("iso2-power-delivery-req", _iso2_power_delivery_req),
        _iso2_doc("iso2-power-delivery-res", _iso2_power_delivery_res),
        _iso2_doc("iso2-charging-status-req", _iso2_charging_status_req),
        _iso2_doc("iso2-charging-status-res", _iso2_charging_status_res),
        _iso2_doc("iso2-current-demand-req", _iso2_current_demand_req),
        _iso2_doc("iso2-current-demand-res", _iso2_current_demand_res),
        _iso2_doc("iso2-metering-receipt-req", _iso2_metering_receipt_req),
        _iso2_doc("iso2-metering-receipt-res", _iso2_metering_receipt_res),
        _iso2_doc("iso2-welding-detection-req", _iso2_welding_detection_req),
        _iso2_doc("iso2-welding-detection-res", _iso2_welding_detection_res),
        _iso2_doc("iso2-session-stop-req", _iso2_session_stop_req),
        _iso2_doc("iso2-session-stop-res", _iso2_session_stop_res),
        # Fragment payloads used as signed elements (see
        # ``app/evcc/states/iso15118_2_states.py`` and
        # ``app/secc/controller/simulator.py``).
        CodecFixture(
            id="iso2-frag-authorization-req",
            protocol="iso15118-2",
            namespace=_iso2_namespace(),
            build=_iso2_frag_authorization_req,
            root_kind="fragment",
        ),
        CodecFixture(
            id="iso2-frag-certificate-installation-req",
            protocol="iso15118-2",
            namespace=_iso2_namespace(),
            build=_iso2_frag_certificate_installation_req,
            root_kind="fragment",
        ),
        CodecFixture(
            id="iso2-frag-metering-receipt-req",
            protocol="iso15118-2",
            namespace=_iso2_namespace(),
            build=_iso2_frag_metering_receipt_req,
            root_kind="fragment",
        ),
        CodecFixture(
            id="iso2-frag-contract-signature-cert-chain",
            protocol="iso15118-2",
            namespace=_iso2_namespace(),
            build=_iso2_frag_contract_signature_cert_chain,
            root_kind="fragment",
            root_name="ContractSignatureCertChain",
        ),
        CodecFixture(
            id="iso2-frag-encrypted-private-key",
            protocol="iso15118-2",
            namespace=_iso2_namespace(),
            build=_iso2_frag_encrypted_private_key,
            root_kind="fragment",
        ),
        CodecFixture(
            id="iso2-frag-dh-public-key",
            protocol="iso15118-2",
            namespace=_iso2_namespace(),
            build=_iso2_frag_dh_public_key,
            root_kind="fragment",
        ),
        # ``eMAID`` fragment encoding: the legacy Exificient codec's output
        # was malformed (it could not even round-trip its own bytes —
        # confirmed manually). The golden is therefore EXPy-authoritative.
        # The ADR-0002 Slice 5 rebaselining promoted all goldens to EXPy and
        # documented divergences; this is one of them.
        CodecFixture(
            id="iso2-frag-emaid",
            protocol="iso15118-2",
            namespace=_iso2_namespace(),
            build=_iso2_frag_emaid,
            root_kind="fragment",
            expy_authoritative=True,
        ),
        # XmldsigFragment payload (SignedInfo) used by signature creation /
        # verification in ``app/shared/security.py``.
        # The legacy Exificient codec encoded ``SignedInfo`` via the
        # ``XML_DSIG`` standalone-schema path; libcbv2g decodes only the
        # ISO-2-rooted xmldsig fragment. The bytes did not round-trip
        # between the two, so the golden is EXPy-authoritative — Slice 5
        # rebaselined the whole corpus on EXPy and documented this as one
        # of the expected divergences.
        CodecFixture(
            id="iso2-xmldsig-signed-info",
            protocol="iso15118-2",
            namespace=_iso2_namespace(),
            build=_iso2_xmldsig_signed_info,
            root_kind="xmldsig",
            expy_authoritative=True,
        ),
    ]
)


# --- ISO 15118-20 builders -------------------------------------------------
#
# ISO-20 splits across five sub-namespaces (`ISO20_COMMON`, `ISO20_AC`,
# `ISO20_DC`, `ISO20_WPT`, `ISO20_ACDP`). Every fixture here is flagged
# ``expy_authoritative=True`` — the legacy Exificient codec and EXPy diverged
# on ISO-20 (signed-info canonicalisation, optional-key encoding) and ADR-0002
# Slice 5 rebaselined the whole corpus on EXPy anyway. Roots: every namespace gets
# Document coverage; ``ISO20_COMMON`` adds Fragment + XmldsigFragment because
# only the three signed-element namespaces (COMMON/AC/DC) expose those roots
# in EXPy v1.0.


def _iso20_namespaces():
    from app.shared.messages.enums import Namespace

    return Namespace


def _iso20_header(session_id: str = "0011223344556677"):
    from app.shared.messages.iso15118_20.common_types import MessageHeader

    return MessageHeader(session_id=session_id, timestamp=1700000000)


def _iso20_rn(value: int, exponent: int = 0):
    from app.shared.messages.iso15118_20.common_types import RationalNumber

    return RationalNumber(exponent=exponent, value=value)


# --- ISO-20 common (sub-namespace ISO20_COMMON) ---------------------------


def _iso20_session_setup_req():
    from app.shared.messages.iso15118_20.common_messages import SessionSetupReq

    return SessionSetupReq(header=_iso20_header(), evcc_id="VEHICLE_001")


def _iso20_session_setup_res():
    from app.shared.messages.iso15118_20.common_messages import SessionSetupRes
    from app.shared.messages.iso15118_20.common_types import ResponseCode

    return SessionSetupRes(
        header=_iso20_header(),
        response_code=ResponseCode.OK_NEW_SESSION_ESTABLISHED,
        evse_id="DE*ICE*E1234",
    )


def _iso20_authorization_setup_req():
    from app.shared.messages.iso15118_20.common_messages import AuthorizationSetupReq

    return AuthorizationSetupReq(header=_iso20_header())


def _iso20_authorization_setup_res():
    from app.shared.messages.enums import AuthEnum
    from app.shared.messages.iso15118_20.common_messages import (
        AuthorizationSetupRes,
        EIMAuthSetupResParams,
    )
    from app.shared.messages.iso15118_20.common_types import ResponseCode

    return AuthorizationSetupRes(
        header=_iso20_header(),
        response_code=ResponseCode.OK,
        # ISO-20 uses the bare ``EIM`` / ``PnC`` enum values (see
        # :class:`AuthEnum`); the ``_V2`` variants are ISO-15118-2-specific.
        auth_services=[AuthEnum.EIM],
        cert_install_service=False,
        eim_as_res=EIMAuthSetupResParams(),
    )


def _iso20_service_discovery_req():
    from app.shared.messages.iso15118_20.common_messages import ServiceDiscoveryReq

    return ServiceDiscoveryReq(header=_iso20_header())


def _iso20_service_discovery_res():
    from app.shared.messages.iso15118_20.common_messages import (
        Service,
        ServiceDiscoveryRes,
        ServiceList,
    )
    from app.shared.messages.iso15118_20.common_types import ResponseCode

    return ServiceDiscoveryRes(
        header=_iso20_header(),
        response_code=ResponseCode.OK,
        service_renegotiation_supported=False,
        energy_service_list=ServiceList(
            services=[Service(service_id=1, free_service=True)]
        ),
    )


def _iso20_power_delivery_req():
    from app.shared.messages.iso15118_20.common_messages import (
        ChargeProgress,
        PowerDeliveryReq,
    )
    from app.shared.messages.iso15118_20.common_types import Processing

    return PowerDeliveryReq(
        header=_iso20_header(),
        ev_processing=Processing.ONGOING,
        charge_progress=ChargeProgress.STOP,
    )


def _iso20_power_delivery_res():
    from app.shared.messages.iso15118_20.common_messages import PowerDeliveryRes
    from app.shared.messages.iso15118_20.common_types import ResponseCode

    return PowerDeliveryRes(
        header=_iso20_header(),
        response_code=ResponseCode.OK,
    )


def _iso20_session_stop_req():
    from app.shared.messages.iso15118_20.common_messages import (
        ChargingSession,
        SessionStopReq,
    )

    return SessionStopReq(
        header=_iso20_header(),
        charging_session=ChargingSession.TERMINATE,
    )


def _iso20_session_stop_res():
    from app.shared.messages.iso15118_20.common_messages import SessionStopRes
    from app.shared.messages.iso15118_20.common_types import ResponseCode

    return SessionStopRes(
        header=_iso20_header(),
        response_code=ResponseCode.OK,
    )


# --- ISO-20 fragment / xmldsig -------------------------------------------


def _iso20_frag_pnc_auth_req_params():
    from app.shared.messages.iso15118_20.common_messages import (
        CertificateChain,
        PnCAuthReqParams,
        SubCertificates,
    )

    return PnCAuthReqParams(
        id="id1",
        gen_challenge=b"0123456789012345",
        contract_cert_chain=CertificateChain(
            certificate=b"\x30" + b"\x01" * 30,
            sub_certificates=SubCertificates(
                certificates=[b"\x30" + b"\x02" * 20]
            ),
        ),
    )


def _iso20_xmldsig_signed_info():
    # Same SignedInfo as the ISO-2 fixture; the xmldsig schema is shared
    # between ISO-2 and ISO-20.
    from app.shared.messages.xmldsig import (
        CanonicalizationMethod,
        DigestMethod,
        Reference,
        SignatureMethod,
        SignedInfo,
        Transform,
        Transforms,
    )

    return SignedInfo(
        canonicalization_method=CanonicalizationMethod(
            algorithm="http://www.w3.org/TR/canonical-exi/"
        ),
        signature_method=SignatureMethod(
            algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
        ),
        reference=[
            Reference(
                uri="#id1",
                transforms=Transforms(
                    transform=[
                        Transform(algorithm="http://www.w3.org/TR/canonical-exi/")
                    ]
                ),
                digest_method=DigestMethod(
                    algorithm="http://www.w3.org/2001/04/xmlenc#sha256"
                ),
                digest_value=b"\x00" * 32,
            )
        ],
    )


# --- ISO-20 AC (sub-namespace ISO20_AC) -----------------------------------


def _iso20_ac_charge_parameter_discovery_req():
    from app.shared.messages.iso15118_20.ac import (
        ACChargeParameterDiscoveryReq,
        ACChargeParameterDiscoveryReqParams,
    )

    return ACChargeParameterDiscoveryReq(
        header=_iso20_header(),
        ac_params=ACChargeParameterDiscoveryReqParams(
            ev_max_charge_power=_iso20_rn(7400),
            ev_min_charge_power=_iso20_rn(100),
        ),
    )


def _iso20_ac_charge_parameter_discovery_res():
    from app.shared.messages.iso15118_20.ac import (
        ACChargeParameterDiscoveryRes,
        ACChargeParameterDiscoveryResParams,
    )
    from app.shared.messages.iso15118_20.common_types import ResponseCode

    return ACChargeParameterDiscoveryRes(
        header=_iso20_header(),
        response_code=ResponseCode.OK,
        ac_params=ACChargeParameterDiscoveryResParams(
            evse_max_charge_power=_iso20_rn(22000),
            evse_min_charge_power=_iso20_rn(200),
            evse_nominal_frequency=_iso20_rn(50),
        ),
    )


def _iso20_ac_bpt_charge_parameter_discovery_req():
    from app.shared.messages.iso15118_20.ac import (
        ACChargeParameterDiscoveryReq,
        BPTACChargeParameterDiscoveryReqParams,
    )

    return ACChargeParameterDiscoveryReq(
        header=_iso20_header(),
        bpt_ac_params=BPTACChargeParameterDiscoveryReqParams(
            ev_max_charge_power=_iso20_rn(7400),
            ev_min_charge_power=_iso20_rn(100),
            ev_max_discharge_power=_iso20_rn(5000),
            ev_min_discharge_power=_iso20_rn(100),
        ),
    )


def _iso20_ac_bpt_charge_parameter_discovery_res():
    from app.shared.messages.iso15118_20.ac import (
        ACChargeParameterDiscoveryRes,
        BPTACChargeParameterDiscoveryResParams,
    )
    from app.shared.messages.iso15118_20.common_types import ResponseCode

    return ACChargeParameterDiscoveryRes(
        header=_iso20_header(),
        response_code=ResponseCode.OK,
        bpt_ac_params=BPTACChargeParameterDiscoveryResParams(
            evse_max_charge_power=_iso20_rn(22000),
            evse_min_charge_power=_iso20_rn(200),
            evse_nominal_frequency=_iso20_rn(50),
            evse_max_discharge_power=_iso20_rn(11000),
            evse_min_discharge_power=_iso20_rn(200),
        ),
    )


# --- ISO-20 DC (sub-namespace ISO20_DC) -----------------------------------


def _iso20_dc_charge_parameter_discovery_req():
    from app.shared.messages.iso15118_20.dc import (
        DCChargeParameterDiscoveryReq,
        DCChargeParameterDiscoveryReqParams,
    )

    return DCChargeParameterDiscoveryReq(
        header=_iso20_header(),
        dc_params=DCChargeParameterDiscoveryReqParams(
            # values exceeding 32767 must use exponent to stay within the
            # XSD ``xs:short`` Value range (see ``RationalNumber``).
            ev_max_charge_power=_iso20_rn(50, exponent=3),
            ev_min_charge_power=_iso20_rn(100),
            ev_max_charge_current=_iso20_rn(125),
            ev_min_charge_current=_iso20_rn(1),
            ev_max_voltage=_iso20_rn(500),
            ev_min_voltage=_iso20_rn(200),
        ),
    )


def _iso20_dc_charge_parameter_discovery_res():
    from app.shared.messages.iso15118_20.dc import (
        DCChargeParameterDiscoveryRes,
        DCChargeParameterDiscoveryResParams,
    )
    from app.shared.messages.iso15118_20.common_types import ResponseCode

    return DCChargeParameterDiscoveryRes(
        header=_iso20_header(),
        response_code=ResponseCode.OK,
        dc_params=DCChargeParameterDiscoveryResParams(
            evse_max_charge_power=_iso20_rn(80, exponent=3),
            evse_min_charge_power=_iso20_rn(200),
            evse_max_charge_current=_iso20_rn(200),
            evse_min_charge_current=_iso20_rn(1),
            evse_max_voltage=_iso20_rn(900),
            evse_min_voltage=_iso20_rn(200),
            evse_power_ramp_limit=_iso20_rn(5000),
        ),
    )


def _iso20_dc_bpt_charge_parameter_discovery_req():
    from app.shared.messages.iso15118_20.dc import (
        BPTDCChargeParameterDiscoveryReqParams,
        DCChargeParameterDiscoveryReq,
    )

    return DCChargeParameterDiscoveryReq(
        header=_iso20_header(),
        bpt_dc_params=BPTDCChargeParameterDiscoveryReqParams(
            # values exceeding 32767 must use exponent to stay within the
            # XSD ``xs:short`` Value range (see ``RationalNumber``).
            ev_max_charge_power=_iso20_rn(50, exponent=3),
            ev_min_charge_power=_iso20_rn(100),
            ev_max_charge_current=_iso20_rn(125),
            ev_min_charge_current=_iso20_rn(1),
            ev_max_voltage=_iso20_rn(500),
            ev_min_voltage=_iso20_rn(200),
            ev_max_discharge_power=_iso20_rn(40, exponent=3),
            ev_min_discharge_power=_iso20_rn(100),
            ev_max_discharge_current=_iso20_rn(100),
            ev_min_discharge_current=_iso20_rn(1),
        ),
    )


def _iso20_dc_bpt_charge_parameter_discovery_res():
    from app.shared.messages.iso15118_20.dc import (
        BPTDCChargeParameterDiscoveryResParams,
        DCChargeParameterDiscoveryRes,
    )
    from app.shared.messages.iso15118_20.common_types import ResponseCode

    return DCChargeParameterDiscoveryRes(
        header=_iso20_header(),
        response_code=ResponseCode.OK,
        bpt_dc_params=BPTDCChargeParameterDiscoveryResParams(
            evse_max_charge_power=_iso20_rn(80, exponent=3),
            evse_min_charge_power=_iso20_rn(200),
            evse_max_charge_current=_iso20_rn(200),
            evse_min_charge_current=_iso20_rn(1),
            evse_max_voltage=_iso20_rn(900),
            evse_min_voltage=_iso20_rn(200),
            evse_power_ramp_limit=_iso20_rn(5000),
            evse_max_discharge_power=_iso20_rn(60, exponent=3),
            evse_min_discharge_power=_iso20_rn(200),
            evse_max_discharge_current=_iso20_rn(150),
            evse_min_discharge_current=_iso20_rn(1),
        ),
    )


def _iso20_dc_cable_check_req():
    from app.shared.messages.iso15118_20.dc import DCCableCheckReq

    return DCCableCheckReq(header=_iso20_header())


def _iso20_dc_cable_check_res():
    from app.shared.messages.iso15118_20.dc import DCCableCheckRes
    from app.shared.messages.iso15118_20.common_types import Processing, ResponseCode

    return DCCableCheckRes(
        header=_iso20_header(),
        response_code=ResponseCode.OK,
        evse_processing=Processing.FINISHED,
    )


def _iso20_dc_pre_charge_req():
    from app.shared.messages.iso15118_20.dc import DCPreChargeReq
    from app.shared.messages.iso15118_20.common_types import Processing

    return DCPreChargeReq(
        header=_iso20_header(),
        ev_processing=Processing.FINISHED,
        ev_present_voltage=_iso20_rn(0),
        ev_target_voltage=_iso20_rn(400),
    )


def _iso20_dc_pre_charge_res():
    from app.shared.messages.iso15118_20.dc import DCPreChargeRes
    from app.shared.messages.iso15118_20.common_types import ResponseCode

    return DCPreChargeRes(
        header=_iso20_header(),
        response_code=ResponseCode.OK,
        evse_present_voltage=_iso20_rn(399),
    )


def _iso20_dc_welding_detection_req():
    from app.shared.messages.iso15118_20.dc import DCWeldingDetectionReq
    from app.shared.messages.iso15118_20.common_types import Processing

    return DCWeldingDetectionReq(
        header=_iso20_header(),
        ev_processing=Processing.FINISHED,
    )


def _iso20_dc_welding_detection_res():
    from app.shared.messages.iso15118_20.dc import DCWeldingDetectionRes
    from app.shared.messages.iso15118_20.common_types import ResponseCode

    return DCWeldingDetectionRes(
        header=_iso20_header(),
        response_code=ResponseCode.OK,
        evse_present_voltage=_iso20_rn(2),
    )


# --- ISO-20 WPT (sub-namespace ISO20_WPT) ---------------------------------


def _iso20_wpt_pairing_req():
    from app.shared.messages.iso15118_20.wpt import (
        WPTEVResult,
        WPTPairingReq,
        WPTProcessing,
    )

    return WPTPairingReq(
        header=_iso20_header(),
        ev_processing=WPTProcessing.FINISHED,
        ev_result_code=WPTEVResult.SUCCESS,
    )


# --- ISO-20 ACDP (sub-namespace ISO20_ACDP) -------------------------------


def _iso20_acdp_connect_req():
    from app.shared.messages.iso15118_20.acd_p import (
        ACDPChargingDeviceStatus,
        ACDPConnectReq,
    )

    return ACDPConnectReq(
        header=_iso20_header(),
        ev_electrical_charging_device_status=ACDPChargingDeviceStatus.STATE_B,
    )


def _iso20_doc(id_: str, build: Callable[[], BaseModel], ns_attr: str) -> CodecFixture:
    from app.shared.messages.enums import Namespace

    return CodecFixture(
        id=id_,
        protocol="iso15118-20",
        namespace=getattr(Namespace, ns_attr),
        build=build,
        expy_authoritative=True,
    )


_ISO20_NS = "ISO_V20_COMMON_MSG"

FIXTURES.extend(
    [
        # ISO20_COMMON — Document
        _iso20_doc("iso20-common-session-setup-req", _iso20_session_setup_req, _ISO20_NS),
        _iso20_doc("iso20-common-session-setup-res", _iso20_session_setup_res, _ISO20_NS),
        _iso20_doc(
            "iso20-common-authorization-setup-req",
            _iso20_authorization_setup_req,
            _ISO20_NS,
        ),
        _iso20_doc(
            "iso20-common-authorization-setup-res",
            _iso20_authorization_setup_res,
            _ISO20_NS,
        ),
        _iso20_doc(
            "iso20-common-service-discovery-req",
            _iso20_service_discovery_req,
            _ISO20_NS,
        ),
        _iso20_doc(
            "iso20-common-service-discovery-res",
            _iso20_service_discovery_res,
            _ISO20_NS,
        ),
        _iso20_doc(
            "iso20-common-power-delivery-req", _iso20_power_delivery_req, _ISO20_NS
        ),
        _iso20_doc(
            "iso20-common-power-delivery-res", _iso20_power_delivery_res, _ISO20_NS
        ),
        _iso20_doc("iso20-common-session-stop-req", _iso20_session_stop_req, _ISO20_NS),
        _iso20_doc("iso20-common-session-stop-res", _iso20_session_stop_res, _ISO20_NS),
        # ISO20_COMMON — Fragment (signed PnC auth params)
        CodecFixture(
            id="iso20-common-frag-pnc-auth-req-params",
            protocol="iso15118-20",
            namespace=_iso20_namespaces().ISO_V20_COMMON_MSG,
            build=_iso20_frag_pnc_auth_req_params,
            root_kind="fragment",
            expy_authoritative=True,
        ),
        # ISO20_COMMON — XmldsigFragment (SignedInfo, signature creation
        # payload).
        CodecFixture(
            id="iso20-common-xmldsig-signed-info",
            protocol="iso15118-20",
            namespace=_iso20_namespaces().ISO_V20_COMMON_MSG,
            build=_iso20_xmldsig_signed_info,
            root_kind="xmldsig",
            expy_authoritative=True,
        ),
        # ISO20_AC — Document (AC + AC-BPT energy services)
        _iso20_doc(
            "iso20-ac-charge-parameter-discovery-req",
            _iso20_ac_charge_parameter_discovery_req,
            "ISO_V20_AC",
        ),
        _iso20_doc(
            "iso20-ac-charge-parameter-discovery-res",
            _iso20_ac_charge_parameter_discovery_res,
            "ISO_V20_AC",
        ),
        _iso20_doc(
            "iso20-ac-bpt-charge-parameter-discovery-req",
            _iso20_ac_bpt_charge_parameter_discovery_req,
            "ISO_V20_AC",
        ),
        _iso20_doc(
            "iso20-ac-bpt-charge-parameter-discovery-res",
            _iso20_ac_bpt_charge_parameter_discovery_res,
            "ISO_V20_AC",
        ),
        # ISO20_DC — Document (DC + DC-BPT energy services)
        _iso20_doc(
            "iso20-dc-charge-parameter-discovery-req",
            _iso20_dc_charge_parameter_discovery_req,
            "ISO_V20_DC",
        ),
        _iso20_doc(
            "iso20-dc-charge-parameter-discovery-res",
            _iso20_dc_charge_parameter_discovery_res,
            "ISO_V20_DC",
        ),
        _iso20_doc(
            "iso20-dc-bpt-charge-parameter-discovery-req",
            _iso20_dc_bpt_charge_parameter_discovery_req,
            "ISO_V20_DC",
        ),
        _iso20_doc(
            "iso20-dc-bpt-charge-parameter-discovery-res",
            _iso20_dc_bpt_charge_parameter_discovery_res,
            "ISO_V20_DC",
        ),
        _iso20_doc(
            "iso20-dc-cable-check-req", _iso20_dc_cable_check_req, "ISO_V20_DC"
        ),
        _iso20_doc(
            "iso20-dc-cable-check-res", _iso20_dc_cable_check_res, "ISO_V20_DC"
        ),
        _iso20_doc(
            "iso20-dc-pre-charge-req", _iso20_dc_pre_charge_req, "ISO_V20_DC"
        ),
        _iso20_doc(
            "iso20-dc-pre-charge-res", _iso20_dc_pre_charge_res, "ISO_V20_DC"
        ),
        _iso20_doc(
            "iso20-dc-welding-detection-req",
            _iso20_dc_welding_detection_req,
            "ISO_V20_DC",
        ),
        _iso20_doc(
            "iso20-dc-welding-detection-res",
            _iso20_dc_welding_detection_res,
            "ISO_V20_DC",
        ),
        # ISO20_WPT — Document (WPT energy service)
        _iso20_doc("iso20-wpt-pairing-req", _iso20_wpt_pairing_req, "ISO_V20_WPT"),
        # ISO20_ACDP — Document (ACDP energy service)
        _iso20_doc("iso20-acdp-connect-req", _iso20_acdp_connect_req, "ISO_V20_ACDP"),
    ]
)
