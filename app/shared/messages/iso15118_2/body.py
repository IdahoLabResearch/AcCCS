"""
This modules contains classes which implement all the elements of the
ISO 15118-2 XSD file V2G_CI_MsgBody.xsd (see folder 'schemas').
These are the V2GMessages exchanged between the EVCC and the SECC.

All classes are ultimately subclassed from pydantic's BaseModel to ease
validation when instantiating a class and to reduce boilerplate code.
Pydantic's Field class is used to be able to create a json schema of each model
(or class) that matches the definitions in the XSD schema, including the XSD
element names by using the 'alias' attribute.
"""

import logging
from abc import ABC
from typing import Optional, Tuple, Type, Any, Self

from pydantic import Field, model_validator, field_validator

from app.shared.exceptions import V2GMessageValidationError
from app.shared.messages import BaseModel
from app.shared.messages.datatypes import (
    DCEVSEChargeParameter,
    DCEVSEStatus,
    PVEVMaxCurrentLimit,
    PVEVMaxPowerLimit,
    PVEVMaxVoltageLimit,
    PVEVSEMaxCurrent,
    PVEVSEMaxCurrentLimit,
    PVEVSEMaxPowerLimit,
    PVEVSEMaxVoltageLimit,
    PVEVSEPresentCurrent,
    PVEVSEPresentVoltage,
    PVEVTargetCurrent,
    PVEVTargetVoltage,
    PVRemainingTimeToBulkSOC,
    PVRemainingTimeToFullSOC,
    SelectedServiceList,
)
from app.shared.messages.enums import (
    AuthEnum,
    EnergyTransferModeEnum,
    EVSEProcessing,
)
from app.shared.messages.iso15118_2.datatypes import (
    EMAID,
    ACEVChargeParameter,
    ACEVSEChargeParameter,
    ACEVSEStatus,
    AuthOptionList,
    CertificateChain,
    ChargeProgress,
    ChargeService,
    ChargingProfile,
    ChargingSession,
    DCEVChargeParameter,
    DCEVPowerDeliveryParameter,
    DCEVStatus,
    DHPublicKey,
    EncryptedPrivateKey,
    MeterInfo,
    ResponseCode,
    RootCertificateIDList,
    SAScheduleList,
    ServiceCategory,
    ServiceList,
    ServiceParameterList,
    eMAID,
)
from app.shared.validators import one_field_must_be_set

logger = logging.getLogger(__name__)


class BodyBase(BaseModel, ABC):
    """
    A base class for all body elements of a V2GMessage Body. This base type is
    substituted by the concrete messages from SessionSetupReq to SessionStopRes
    when creating a V2GMessage instance.

    See section 8.3.4 Message Body Definition in ISO 15118-2
    """

    def __str__(self):
        return type(self).__name__


class Response(BodyBase, ABC):
    """
    The base class for all response messages, as they all share a response code
    """

    response_code: ResponseCode = Field(..., alias="ResponseCode")


class AuthorizationReq(BodyBase):
    """See section 8.4.3.7.1 in ISO 15118-2"""

    # 'Id' is actually an XML attribute, but JSON (our serialisation method)
    # doesn't have attributes. The EXI codec has to en-/decode accordingly.
    id: Optional[str] = Field(None, alias="Id")
    gen_challenge: Optional[bytes] = Field(
        None, min_length=16, max_length=16, alias="GenChallenge"
    )

    @model_validator(mode='before')
    def both_fields_set_or_unset(cls, values: Any) -> Any:
        """
        If the AuthorizationReq is digitally signed, then both the
        gen_challenge field and the id attribute must be set.
        If the AuthorizationReq is not digitally signed, then the message is
        must be empty. This validator checks that both are either set or unset.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        _id, gen_challenge = values.get("id"), values.get("gen_challenge")
        if (_id and not gen_challenge) or (not _id and gen_challenge):
            raise ValueError(
                "Fields 'id' and 'gen_challenge' must either both "
                "be set (digital signature in header) or unset "
                "(no digital signature in header)"
            )
        return values


class AuthorizationRes(Response):
    """See section 8.4.3.7.2 in ISO 15118-2"""

    evse_processing: EVSEProcessing = Field(..., alias="EVSEProcessing")


class CableCheckReq(BodyBase):
    """See section 8.4.5.2.2 in ISO 15118-2"""

    dc_ev_status: DCEVStatus = Field(..., alias="DC_EVStatus")


class CableCheckRes(Response):
    """See section 8.4.5.2.3 in ISO 15118-2"""

    dc_evse_status: DCEVSEStatus = Field(..., alias="DC_EVSEStatus")
    evse_processing: EVSEProcessing = Field(..., alias="EVSEProcessing")


class CertificateInstallationReq(BodyBase):
    """See section 8.4.3.11.2 in ISO 15118-2"""

    id: str = Field(..., alias="Id")
    oem_provisioning_cert: bytes = Field(
        ..., max_length=800, alias="OEMProvisioningCert"
    )
    list_of_root_cert_ids: RootCertificateIDList = Field(
        ..., alias="ListOfRootCertificateIDs"
    )


class CertificateInstallationRes(Response):
    """See section 8.4.3.11.3 in ISO 15118-2"""

    cps_cert_chain: CertificateChain = Field(
        ..., alias="SAProvisioningCertificateChain"
    )
    contract_cert_chain: CertificateChain = Field(
        ..., alias="ContractSignatureCertChain"
    )
    encrypted_private_key: EncryptedPrivateKey = Field(
        ..., alias="ContractSignatureEncryptedPrivateKey"
    )
    dh_public_key: DHPublicKey = Field(..., alias="DHpublickey")
    emaid: EMAID = Field(..., alias="eMAID")


class CertificateUpdateReq(BodyBase):
    """See section 8.4.3.10.2 in ISO 15118-2"""

    id: str = Field(..., alias="Id")
    contract_cert_chain: CertificateChain = Field(
        ..., alias="ContractSignatureCertChain"
    )
    emaid: EMAID = Field(..., alias="eMAID")
    list_of_root_cert_ids: RootCertificateIDList = Field(
        ..., alias="ListOfRootCertificateIDs"
    )


class CertificateUpdateRes(Response):
    """See section 8.4.3.10.3 in ISO 15118-2"""

    cps_cert_chain: CertificateChain = Field(
        ..., alias="SAProvisioningCertificateChain"
    )
    contract_cert_chain: CertificateChain = Field(
        ..., alias="ContractSignatureCertChain"
    )
    encrypted_private_key: EncryptedPrivateKey = Field(
        ..., alias="ContractSignatureEncryptedPrivateKey"
    )
    dh_public_key: DHPublicKey = Field(..., alias="DHpublickey")
    emaid: EMAID = Field(..., alias="eMAID")
    # XSD type short (16 bit integer) with value range [-32768..32767].
    # But only -1 is allowed as negative value.
    retry_counter: Optional[int] = Field(None, ge=-1, le=32767, alias="RetryCounter")


class ChargeParameterDiscoveryReq(BodyBase):
    """See section 8.4.3.8.2 in ISO 15118-2"""

    # XSD type unsignedShort (16 bit integer) with value range [0..65535]
    max_entries_sa_schedule_tuple: Optional[int] = Field(
        None, ge=0, le=65535, alias="MaxEntriesSAScheduleTuple"
    )
    requested_energy_mode: EnergyTransferModeEnum = Field(
        ..., alias="RequestedEnergyTransferMode"
    )
    ac_ev_charge_parameter: Optional[ACEVChargeParameter] = Field(
        None, alias="AC_EVChargeParameter"
    )
    dc_ev_charge_parameter: Optional[DCEVChargeParameter] = Field(
        None, alias="DC_EVChargeParameter"
    )

    @model_validator(mode='before')
    def either_ac_or_dc_charge_params(cls, values):
        """
        Either ac_ev_charge_parameter or dc_ev_charge_parameter must be set,
        depending on whether the chosen energy transfer mode is AC or DC.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if one_field_must_be_set(
            [
                "ac_ev_charge_parameter",
                "AC_EVChargeParameter",
                "dc_ev_charge_parameter",
                "DC_EVChargeParameter",
            ],
            values,
            True,
        ):
            return values

    @model_validator(mode='after')
    def requested_energy_mode_must_match_charge_parameter(self) -> Self:
        """
        Check that the requested_energy_mode matches the charge parameter. If
        the requested energy mode is AC-related, then ac_ev_charge_parameter
        must be set, otherwise dc_ev_charge_parameter must be set.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if ("AC_" in self.requested_energy_mode and self.dc_ev_charge_parameter) or (
            "DC_" in self.requested_energy_mode and self.ac_ev_charge_parameter
        ):
            raise V2GMessageValidationError(
                "[V2G2-477] Wrong charge parameters for requested energy "
                f"transfer mode {self.requested_energy_mode}",
                ResponseCode.FAILED_WRONG_CHARGE_PARAMETER,
                Type[self],
            )

        return self


class ChargeParameterDiscoveryRes(Response):
    """See section 8.4.3.8.3 in ISO 15118-2"""

    evse_processing: EVSEProcessing = Field(..., alias="EVSEProcessing")
    sa_schedule_list: Optional[SAScheduleList] = Field(None, alias="SAScheduleList")
    ac_charge_parameter: Optional[ACEVSEChargeParameter] = Field(
        None, alias="AC_EVSEChargeParameter"
    )
    dc_charge_parameter: Optional[DCEVSEChargeParameter] = Field(
        None, alias="DC_EVSEChargeParameter"
    )

    # TODO Reactivate the validator once you figured out how to deal with the
    #       failed_responses dict
    # @root_validator(pre=True)
    # def either_ac_or_dc_charge_params(cls, values):
    #     """
    #     Either ac_charge_parameter or dc_charge_parameter must be set,
    #     depending on whether the chosen energy transfer mode is AC or DC.
    #
    #     Pydantic validators are "class methods",
    #     see https://pydantic-docs.helpmanual.io/usage/validators/
    #     """
    #     # pylint: disable=no-self-argument
    #     # pylint: disable=no-self-use
    #     if one_field_must_be_set(['ac_charge_parameter',
    #                               'AC_EVSEChargeParameter',
    #                               'dc_charge_parameter',
    #                               'DC_EVSEChargeParameter'],
    #                              values,
    #                              True):
    #         return values

    # TODO Reactivate the validator once you figured out how to deal with the
    #       failed_responses dict
    # @root_validator()
    # def schedule_must_be_set_if_processing_finished(cls, values):
    #     """
    #     Once the field evse_processing is set to EVSEProcessing.FINISHED, the
    #     fields sa_schedule_list and ac_charge_parameter must be set.
    #     """
    #     # pylint: disable=no-self-argument
    #     # pylint: disable=no-self-use
    #     evse_processing, schedules, ac_charge_params, dc_charge_params = \
    #         values.get('evse_processing'), \
    #         values.get('sa_schedule_list'), \
    #         values.get('ac_charge_parameter'), \
    #         values.get('ac_charge_parameter')
    #     if evse_processing == EVSEProcessing.FINISHED and (
    #             not schedules or not (ac_charge_params or dc_charge_params)):
    #         raise ValueError("SECC set EVSEProcessing to 'FINISHED' but either"
    #                          "SAScheduleList or charge parameters are not set")
    #     return values


class ChargingStatusReq(BodyBase):
    """See section 8.4.4.2.2 in ISO 15118-2"""


class ChargingStatusRes(Response):
    """See section 8.4.4.2.3 in ISO 15118-2"""

    evse_id: str = Field(..., min_length=7, max_length=37, alias="EVSEID")
    # XSD type unsignedByte with value range [1..255]
    sa_schedule_tuple_id: int = Field(..., ge=1, le=255, alias="SAScheduleTupleID")
    evse_max_current: Optional[PVEVSEMaxCurrent] = Field(None, alias="EVSEMaxCurrent")
    meter_info: Optional[MeterInfo] = Field(None, alias="MeterInfo")
    receipt_required: Optional[bool] = Field(None, alias="ReceiptRequired")
    ac_evse_status: ACEVSEStatus = Field(..., alias="AC_EVSEStatus")


class CurrentDemandReq(BodyBase):
    """See section 8.4.5.4.2 in ISO 15118-2"""

    dc_ev_status: DCEVStatus = Field(..., alias="DC_EVStatus")
    ev_target_current: PVEVTargetCurrent = Field(..., alias="EVTargetCurrent")
    ev_max_voltage_limit: Optional[PVEVMaxVoltageLimit] = Field(
        None, alias="EVMaximumVoltageLimit"
    )
    ev_max_current_limit: Optional[PVEVMaxCurrentLimit] = Field(
        None, alias="EVMaximumCurrentLimit"
    )
    ev_max_power_limit: Optional[PVEVMaxPowerLimit] = Field(None, alias="EVMaximumPowerLimit")
    bulk_charging_complete: Optional[bool] = Field(None, alias="BulkChargingComplete")
    charging_complete: bool = Field(..., alias="ChargingComplete")
    remaining_time_to_full_soc: Optional[PVRemainingTimeToFullSOC] = Field(
        None, alias="RemainingTimeToFullSoC"
    )
    remaining_time_to_bulk_soc: Optional[PVRemainingTimeToBulkSOC] = Field(
        None, alias="RemainingTimeToBulkSoC"
    )
    ev_target_voltage: PVEVTargetVoltage = Field(..., alias="EVTargetVoltage")


class CurrentDemandRes(Response):
    """See section 8.4.5.4.3 in ISO 15118-2"""

    dc_evse_status: DCEVSEStatus = Field(..., alias="DC_EVSEStatus")
    evse_present_voltage: PVEVSEPresentVoltage = Field(..., alias="EVSEPresentVoltage")
    evse_present_current: PVEVSEPresentCurrent = Field(..., alias="EVSEPresentCurrent")
    evse_current_limit_achieved: bool = Field(..., alias="EVSECurrentLimitAchieved")
    evse_voltage_limit_achieved: bool = Field(..., alias="EVSEVoltageLimitAchieved")
    evse_power_limit_achieved: bool = Field(..., alias="EVSEPowerLimitAchieved")
    evse_max_voltage_limit: Optional[PVEVSEMaxVoltageLimit] = Field(
        None, alias="EVSEMaximumVoltageLimit"
    )
    evse_max_current_limit: Optional[PVEVSEMaxCurrentLimit] = Field(
        None, alias="EVSEMaximumCurrentLimit"
    )
    evse_max_power_limit: Optional[PVEVSEMaxPowerLimit] = Field(
        None, alias="EVSEMaximumPowerLimit"
    )
    # Note: Table 56 denotes the EVSEID type falsely as hexBinary
    evse_id: str = Field(..., min_length=7, max_length=37, alias="EVSEID")
    # XSD type unsignedByte with value range [1..255]
    sa_schedule_tuple_id: int = Field(..., ge=1, le=255, alias="SAScheduleTupleID")
    meter_info: Optional[MeterInfo] = Field(None, alias="MeterInfo")
    receipt_required: Optional[bool] = Field(None, alias="ReceiptRequired")


class MeteringReceiptReq(BodyBase):
    """See section 8.4.3.13.2 in ISO 15118-2"""

    # 'Id' is actually an XML attribute, but JSON (our serialisation method)
    # doesn't have attributes. The EXI codec has to en-/decode accordingly.
    id: Optional[str] = Field(None, alias="Id")
    # XSD type hexBinary with max 8 bytes encoded as 16 hexadecimal characters
    session_id: str = Field(..., max_length=16, alias="SessionID")
    # XSD type unsignedByte with value range [1..255]
    sa_schedule_tuple_id: Optional[int] = Field(None, ge=1, le=255, alias="SAScheduleTupleID")
    meter_info: MeterInfo = Field(..., alias="MeterInfo")

    @field_validator("session_id")
    @classmethod
    def check_sessionid_is_hexbinary(cls, value):
        """
        Checks whether the session_id field is a hexadecimal representation of
        8 bytes.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        try:
            # convert value to int, assuming base 16
            int(value, 16)
            return value
        except ValueError as exc:
            raise ValueError(
                f"Invalid value '{value}' for SessionID (must be "
                f"hexadecimal representation of max 8 bytes)"
            ) from exc


class MeteringReceiptRes(Response):
    """See section 8.4.3.13.3 in ISO 15118-2"""

    ac_evse_status: Optional[ACEVSEStatus] = Field(None, alias="AC_EVSEStatus")
    dc_evse_status: Optional[DCEVSEStatus] = Field(None, alias="DC_EVSEStatus")

    # TODO Reactivate the validator once you figured out how to deal with the
    #       failed_responses dict
    # @root_validator(pre=True)
    # def either_ac_or_dc_status(cls, values):
    #     """
    #     Either ac_evse_status or ac_evse_status must be set,
    #     depending on whether the chosen energy transfer mode is AC or DC.
    #
    #     Pydantic validators are "class methods",
    #     see https://pydantic-docs.helpmanual.io/usage/validators/
    #     """
    #     # pylint: disable=no-self-argument
    #     # pylint: disable=no-self-use
    #     if one_field_must_be_set(['ac_evse_status',
    #                               'AC_EVSEStatus',
    #                               'dc_evse_status',
    #                               'DC_EVSEStatus'],
    #                              values,
    #                              True):
    #         return values


class PaymentDetailsReq(BodyBase):
    """See section 8.4.3.6.2 in ISO 15118-2"""

    emaid: eMAID = Field(..., alias="eMAID")
    cert_chain: CertificateChain = Field(..., alias="ContractSignatureCertChain")


class PaymentDetailsRes(Response):
    """See section 8.4.3.6.3 in ISO 15118-2"""

    gen_challenge: bytes = Field(
        ..., min_length=16, max_length=16, alias="GenChallenge"
    )
    evse_timestamp: int = Field(..., alias="EVSETimeStamp")


class PaymentServiceSelectionReq(BodyBase):
    """
    See section 8.4.3.5.2 in ISO 15118-2

    The datatype in ISO 15118-2 is called "SelectedPaymentOption", but it's
    rather about the selected authorization method than about payment, thus the
    field name selected_auth_option.
    """

    selected_auth_option: AuthEnum = Field(..., alias="SelectedPaymentOption")
    selected_service_list: SelectedServiceList = Field(..., alias="SelectedServiceList")


class PaymentServiceSelectionRes(Response):
    """See section 8.4.3.5.3 in ISO 15118-2"""


class PowerDeliveryReq(BodyBase):
    """See section 8.4.3.9.2 in ISO 15118-2"""

    charge_progress: ChargeProgress = Field(..., alias="ChargeProgress")
    # XSD type unsignedByte with value range [1..255]
    sa_schedule_tuple_id: int = Field(..., ge=1, le=255, alias="SAScheduleTupleID")
    charging_profile: Optional[ChargingProfile] = Field(None, alias="ChargingProfile")
    dc_ev_power_delivery_parameter: Optional[DCEVPowerDeliveryParameter] = Field(
        None, alias="DC_EVPowerDeliveryParameter"
    )


class PowerDeliveryRes(Response):
    """See section 8.4.3.9.3 in ISO 15118-2"""

    ac_evse_status: Optional[ACEVSEStatus] = Field(None, alias="AC_EVSEStatus")
    dc_evse_status: Optional[DCEVSEStatus] = Field(None, alias="DC_EVSEStatus")

    # TODO Reactivate the validator once you figured out how to deal with the
    #       failed_responses dict
    # @root_validator(pre=True)
    # def either_ac_or_dc_status(cls, values):
    #     """
    #     Either ac_evse_status or dc_evse_status must be set,
    #     depending on whether the chosen energy transfer mode is AC or DC.
    #
    #     Pydantic validators are "class methods",
    #     see https://pydantic-docs.helpmanual.io/usage/validators/
    #     """
    #     # pylint: disable=no-self-argument
    #     # pylint: disable=no-self-use
    #     if one_field_must_be_set(['ac_evse_status',
    #                               'AC_EVSEStatus',
    #                               'dc_evse_status',
    #                               'DC_EVSEStatus'],
    #                              values,
    #                              True):
    #         return values


class PreChargeReq(BodyBase):
    """See section 8.4.5.3.2 in ISO 15118-2"""

    dc_ev_status: DCEVStatus = Field(..., alias="DC_EVStatus")
    ev_target_voltage: PVEVTargetVoltage = Field(..., alias="EVTargetVoltage")
    ev_target_current: PVEVTargetCurrent = Field(..., alias="EVTargetCurrent")


class PreChargeRes(Response):
    """See section 8.4.5.3.3 in ISO 15118-2"""

    dc_evse_status: DCEVSEStatus = Field(..., alias="DC_EVSEStatus")
    evse_present_voltage: PVEVSEPresentVoltage = Field(..., alias="EVSEPresentVoltage")


class ServiceDetailReq(BodyBase):
    """See section 8.4.3.4.1 in ISO 15118-2"""

    # XSD type unsignedShort (16 bit integer) with value range [0..65535]
    service_id: int = Field(..., ge=0, le=65535, alias="ServiceID")


class ServiceDetailRes(Response):
    """See section 8.4.3.4.2 in ISO 15118-2"""

    # XSD type unsignedShort (16 bit integer) with value range [0..65535]
    service_id: int = Field(..., ge=0, le=65535, alias="ServiceID")
    service_parameter_list: Optional[ServiceParameterList] = Field(
        None, alias="ServiceParameterList"
    )


class ServiceDiscoveryReq(BodyBase):
    """See section 8.4.3.3.2 in ISO 15118-2"""

    service_scope: Optional[str] = Field(None, max_length=64, alias="ServiceScope")
    service_category: Optional[ServiceCategory] = Field(None, alias="ServiceCategory")


class ServiceDiscoveryRes(Response):
    """See section 8.4.3.3.3 in ISO 15118-2"""

    auth_option_list: AuthOptionList = Field(..., alias="PaymentOptionList")
    charge_service: ChargeService = Field(..., alias="ChargeService")
    service_list: Optional[ServiceList] = Field(None, alias="ServiceList")


class SessionSetupReq(BodyBase):
    """See section 8.4.3.2.1 in ISO 15118-2"""

    # XSD type hexBinary with max 8 bytes encoded as 12 hexadecimal characters
    evcc_id: str = Field(..., max_length=12, alias="EVCCID")

    @field_validator("evcc_id")
    @classmethod
    def check_sessionid_is_hexbinary(cls, value):
        """
        Checks whether the evcc_id field is a hexadecimal representation of
        8 bytes.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        try:
            # convert value to int, assuming base 16
            int(value, 16)
            return value
        except ValueError as exc:
            raise ValueError(
                f"Invalid value '{value}' for EVCCID (must be "
                f"hexadecimal representation of max 6 bytes)"
            ) from exc


class SessionSetupRes(Response):
    """See section 8.4.3.2.2 in ISO 15118-2"""

    evse_id: str = Field(..., min_length=7, max_length=37, alias="EVSEID")
    evse_timestamp: Optional[int] = Field(None, alias="EVSETimeStamp")


class SessionStopReq(BodyBase):
    """See section 8.4.3.12.2 in ISO 15118-2"""

    charging_session: ChargingSession = Field(..., alias="ChargingSession")


class SessionStopRes(Response):
    """See section 8.4.3.12.3 in ISO 15118-2"""


class WeldingDetectionReq(BodyBase):
    """See section 8.4.5.5.2 in ISO 15118-2"""

    dc_ev_status: DCEVStatus = Field(..., alias="DC_EVStatus")


class WeldingDetectionRes(Response):
    """See section 8.4.5.5.3 in ISO 15118-2"""

    dc_evse_status: DCEVSEStatus = Field(..., alias="DC_EVSEStatus")
    evse_present_voltage: PVEVSEPresentVoltage = Field(..., alias="EVSEPresentVoltage")


class Body(BaseModel):
    """
    The body element of a V2GMessage.

    See section 8.3.4 Message Body Definition in ISO 15118-2
    """

    session_setup_req: Optional[SessionSetupReq] = Field(None, alias="SessionSetupReq")
    session_setup_res: Optional[SessionSetupRes] = Field(None, alias="SessionSetupRes")
    service_discovery_req: Optional[ServiceDiscoveryReq] = Field(
        None, alias="ServiceDiscoveryReq"
    )
    service_discovery_res: Optional[ServiceDiscoveryRes] = Field(
        None, alias="ServiceDiscoveryRes"
    )
    service_detail_req: Optional[ServiceDetailReq] = Field(None, alias="ServiceDetailReq")
    service_detail_res: Optional[ServiceDetailRes] = Field(None, alias="ServiceDetailRes")
    payment_service_selection_req: Optional[PaymentServiceSelectionReq] = Field(
        None, alias="PaymentServiceSelectionReq"
    )
    payment_service_selection_res: Optional[PaymentServiceSelectionRes] = Field(
        None, alias="PaymentServiceSelectionRes"
    )
    certificate_installation_req: Optional[CertificateInstallationReq] = Field(
        None, alias="CertificateInstallationReq"
    )
    certificate_installation_res: Optional[CertificateInstallationRes] = Field(
        None, alias="CertificateInstallationRes"
    )
    certificate_update_req: Optional[CertificateUpdateReq] = Field(
        None, alias="CertificateUpdateReq"
    )
    certificate_update_res: Optional[CertificateUpdateRes] = Field(
        None, alias="CertificateUpdateRes"
    )
    payment_details_req: Optional[PaymentDetailsReq] = Field(None, alias="PaymentDetailsReq")
    payment_details_res: Optional[PaymentDetailsRes] = Field(None, alias="PaymentDetailsRes")
    authorization_req: Optional[AuthorizationReq] = Field(None, alias="AuthorizationReq")
    authorization_res: Optional[AuthorizationRes] = Field(None, alias="AuthorizationRes")
    cable_check_req: Optional[CableCheckReq] = Field(None, alias="CableCheckReq")
    cable_check_res: Optional[CableCheckRes] = Field(None, alias="CableCheckRes")
    pre_charge_req: Optional[PreChargeReq] = Field(None, alias="PreChargeReq")
    pre_charge_res: Optional[PreChargeRes] = Field(None, alias="PreChargeRes")
    charge_parameter_discovery_req: Optional[ChargeParameterDiscoveryReq] = Field(
        None, alias="ChargeParameterDiscoveryReq"
    )
    charge_parameter_discovery_res: Optional[ChargeParameterDiscoveryRes] = Field(
        None, alias="ChargeParameterDiscoveryRes"
    )
    power_delivery_req: Optional[PowerDeliveryReq] = Field(None, alias="PowerDeliveryReq")
    power_delivery_res: Optional[PowerDeliveryRes] = Field(None, alias="PowerDeliveryRes")
    charging_status_req: Optional[ChargingStatusReq] = Field(None, alias="ChargingStatusReq")
    charging_status_res: Optional[ChargingStatusRes] = Field(None, alias="ChargingStatusRes")
    current_demand_req: Optional[CurrentDemandReq] = Field(None, alias="CurrentDemandReq")
    current_demand_res: Optional[CurrentDemandRes] = Field(None, alias="CurrentDemandRes")
    metering_receipt_req: Optional[MeteringReceiptReq] = Field(None, alias="MeteringReceiptReq")
    metering_receipt_res: Optional[MeteringReceiptRes] = Field(None, alias="MeteringReceiptRes")
    welding_detection_req: Optional[WeldingDetectionReq] = Field(
        None, alias="WeldingDetectionReq"
    )
    welding_detection_res: Optional[WeldingDetectionRes] = Field(
        None, alias="WeldingDetectionRes"
    )
    session_stop_req: Optional[SessionStopReq] = Field(None, alias="SessionStopReq")
    session_stop_res: Optional[SessionStopRes] = Field(None, alias="SessionStopRes")

    def get_message_name(self) -> str:
        """Returns the name of the one V2GMessage that is set for Body."""
        for k in self.__dict__.keys():
            if getattr(self, k):
                return str(getattr(self, k))

        return ""

    def get_message(self) -> Optional[BodyBase]:
        """Returns the name of the one V2GMessage that is set for Body."""
        for k in self.__dict__.keys():
            if getattr(self, k):
                return getattr(self, k)

        return None

    def get_message_and_name(self) -> Tuple[Optional[BodyBase], str]:
        """Returns the name of the one V2GMessage that is set for Body."""
        for k in self.__dict__.keys():
            if getattr(self, k):
                return getattr(self, k), str(getattr(self, k))

        return None, ""


def get_msg_type(msg_name: str) -> Optional[Type[BodyBase]]:
    """
    Returns the message type corresponding to the message name provided, or
    None if not match is found.

    Args:
        msg_name: The name of the message (e.g. SessionSetupReq)

    Returns: The message type corresponding to the given message name
    """
    msg_dict: dict[str, Type[BodyBase]] = {
        "SessionSetupReq": SessionSetupReq,
        "SessionSetupRes": SessionSetupRes,
        "ServiceDiscoveryReq": ServiceDiscoveryReq,
        "ServiceDiscoveryRes": ServiceDiscoveryRes,
        "ServiceDetailReq": ServiceDetailReq,
        "ServiceDetailRes": ServiceDetailRes,
        "PaymentServiceSelectionReq": PaymentServiceSelectionReq,
        "PaymentServiceSelectionRes": PaymentServiceSelectionRes,
        "CertificateInstallationReq": CertificateInstallationReq,
        "CertificateInstallationRes": CertificateInstallationRes,
        "PaymentDetailsReq": PaymentDetailsReq,
        "PaymentDetailsRes": PaymentDetailsRes,
        "AuthorizationReq": AuthorizationReq,
        "AuthorizationRes": AuthorizationRes,
        "CableCheckReq": CableCheckReq,
        "CableCheckRes": CableCheckRes,
        "PreChargeReq": PreChargeReq,
        "PreChargeRes": PreChargeRes,
        "ChargeParameterDiscoveryReq": ChargeParameterDiscoveryReq,
        "ChargeParameterDiscoveryRes": ChargeParameterDiscoveryRes,
        "PowerDeliveryReq": PowerDeliveryReq,
        "PowerDeliveryRes": PowerDeliveryRes,
        "ChargingStatusReq": ChargingStatusReq,
        "ChargingStatusRes": ChargingStatusRes,
        "CurrentDemandReq": CurrentDemandReq,
        "CurrentDemandRes": CurrentDemandRes,
        "MeteringReceiptReq": MeteringReceiptReq,
        "MeteringReceiptRes": MeteringReceiptRes,
        "WeldingDetectionReq": WeldingDetectionReq,
        "WeldingDetectionRes": WeldingDetectionRes,
        "SessionStopReq": SessionStopReq,
        "SessionStopRes": SessionStopRes,
    }

    return msg_dict.get(msg_name, None)
