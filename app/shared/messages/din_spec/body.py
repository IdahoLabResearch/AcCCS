import logging
from abc import ABC
from typing import Optional, Tuple, Type, Any

from pydantic import Field, model_validator, field_validator
from typing_extensions import Self

from app.shared.exceptions import V2GMessageValidationError
from app.shared.messages import BaseModel
from app.shared.messages.datatypes import (
    DCEVSEChargeParameter,
    DCEVSEStatus,
    PVEVMaxCurrentLimitDin,
    PVEVMaxPowerLimitDin,
    PVEVMaxVoltageLimitDin,
    PVEVSEMaxCurrentLimitDin,
    PVEVSEMaxPowerLimitDin,
    PVEVSEMaxVoltageLimitDin,
    PVEVSEPresentCurrentDin,
    PVEVSEPresentVoltageDin,
    PVEVTargetCurrentDin,
    PVEVTargetVoltageDin,
    PVRemainingTimeToBulkSOCDin,
    PVRemainingTimeToFullSOCDin,
    SelectedServiceList,
)
from app.shared.messages.din_spec.datatypes import (
    ACEVChargeParameter,
    ACEVSEChargeParameter,
    ACEVSEStatus,
    AuthOptionList,
    ChargeService,
    ChargingProfile,
    DCEVChargeParameter,
    DCEVPowerDeliveryParameter,
    DCEVStatus,
    ResponseCode,
    SAScheduleList,
    ServiceCategory,
    ServiceList,
)
from app.shared.messages.enums import (
    AuthEnum,
    EnergyTransferModeEnum,
    EVSEProcessing,
)
from app.shared.validators import one_field_must_be_set

logger = logging.getLogger(__name__)


class BodyBase(BaseModel, ABC):
    """
    A base class for all body elements of a V2GMessage Body. This base type is
    substituted by the concrete messages from SessionSetupReq to SessionStopRes
    when creating a V2GMessage instance.

    See section 9.3.4 Message Body Definition in DIN SPEC 70121
    """

    def __str__(self):
        return type(self).__name__


class Response(BodyBase, ABC):
    """
    The base class for all response messages, as they all share a response code
    """

    response_code: ResponseCode = Field(..., alias="ResponseCode")


class SessionSetupReq(BodyBase):
    """See section 9.4.1.2.2 in DIN SPEC 70121"""

    """Refer Table 29 under section 9.4.1.2.2"""
    # XSD type hexBinary with max 8 bytes
    # (Spec is quite unclear here, but data from field show that 8bytes are used)
    evcc_id: str = Field(..., max_length=16, alias="EVCCID")

    @field_validator("evcc_id")
    @classmethod
    def check_sessionid_is_hexbinary(cls, value: str) -> str:
        """
        Checks whether the evcc_id field is a hexadecimal representation of
        6 bytes.

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
    """
    See section 9.4.1.2.3 in DIN SPEC 70121
    The SECC and the EVCC shall use the format for EVSEID as defined
    in DIN SPEC 91286.

    See section 9.4.1.2.3 Table 30 in DIN SPEC 70121
    "If an SECC cannot provide such ID data, the value of the EVSEID
    is set to zero (00hex)."
    => min_length = 2

    For EVSE ID format see section 5.3.2:
    "Each <EVSEID> has a variable length with at least five characters (one
    digit <Country Code>, three digits <Spot Operator ID>, one digit <Power Outlet ID>)
    and at most forty-one characters (three digits <Country Code>,
     six digits <Spot Operator ID>, thirty-two digits <Power Outlet ID>).
    While the <Spot Operator ID> must be assigned by a central issuing authority,
     each operator with an assigned <Spot Operator ID> can choose the <Power Outlet ID>
      within the above mentioned rules freely."

    This must be represented in hexbinary.
    Example: The DIN SPEC 91286 EVSE ID “49*89*6360” is represented
     as “0x49 0xA8 0x9A 0x63 0x60”.
    """

    evse_id: str = Field(..., min_length=2, max_length=32, alias="EVSEID")
    datetime_now: Optional[int] = Field(None, alias="DateTimeNow")


class ServiceDiscoveryReq(BodyBase):
    """
    See section 9.4.1.3.2 in DIN SPEC 70121
    In the scope of DIN SPEC 70121, the optional element ServiceScope shall NOT be used.
    In the scope of DIN SPEC 70121, if the optional element ServiceCategory is used,
    it shall always contain the value "EVCharging"
    """

    service_scope: Optional[str] = Field(None, max_length=32, alias="ServiceScope")
    service_category: Optional[ServiceCategory] = Field(None, alias="ServiceCategory")


class ServiceDiscoveryRes(Response):
    """See section 9.4.1.3.3 in DIN SPEC 70121
    In the scope of DIN SPEC 70121, the element “ServiceList” shall not be used.
    In the scope of DIN SPEC 70121, only the PaymentOption “ExternalPayment”
    shall be used.
    """

    auth_option_list: AuthOptionList = Field(..., alias="PaymentOptions")
    charge_service: ChargeService = Field(..., alias="ChargeService")
    service_list: Optional[ServiceList] = Field(None, alias="ServiceList")


class ServicePaymentSelectionReq(BodyBase):
    """
    See section 9.4.1.4.2 in DIN SPEC 70121
    [V2G-DC-252] Only the PaymentOption “ExternalPayment” shall be used,
    since detailed payment options are not defined.
    """

    selected_payment_option: AuthEnum = Field(..., alias="SelectedPaymentOption")
    selected_service_list: SelectedServiceList = Field(..., alias="SelectedServiceList")


class ServicePaymentSelectionRes(Response):
    """See section 9.4.1.4.3 in DIN SPEC 70121"""


class ContractAuthenticationReq(BodyBase):
    """See section 9.4.1.5.1 in DIN SPEC 70121"""

    # In the scope of DIN SPEC 70121, the element “GenChallenge” shall not be used.
    # In the scope of DIN SPEC 70121, the element “Id” shall not be used.
    gen_challenge: Optional[str] = Field(None, alias="GenChallenge")
    id: Optional[str] = Field(None, alias="Id")


class ContractAuthenticationRes(Response):
    """
    See section 9.4.1.5.2 in DIN SPEC 70121
    Parameter indicating that the EVSE has finished the processing
    that was initiated after the ContractAuthenticationReq or that
    the EVSE is still processing at the time the response message was sent.
    """

    evse_processing: Optional[EVSEProcessing] = Field(None, alias="EVSEProcessing")


class ChargeParameterDiscoveryReq(BodyBase):
    """
    See section 9.4.1.6.2 in DIN SPEC 70121
    In the scope of DIN SPEC 70121, the EVCC shall not transmit other values
    than “DC_extended” and “DC_core” in EVRequestedEnergyTransferType.
    """

    requested_energy_mode: EnergyTransferModeEnum = Field(
        ..., alias="EVRequestedEnergyTransferType"
    )
    """
    In the scope of DIN SPEC 70121, the element “AC_EVChargeParameter”
    shall not be used.
    """
    ac_ev_charge_parameter: Optional[ACEVChargeParameter] = Field(
        None, alias="AC_EVChargeParameter"
    )
    """
    In the scope of DIN SPEC 70121, the EVSE shall provide its
    maximum output power limit in the element “EVSEMaximumPowerLimit”
    of “DC_EVSEChargeParameter”.
    """
    dc_ev_charge_parameter: Optional[DCEVChargeParameter] = Field(
        None, alias="DC_EVChargeParameter"
    )

    @model_validator(mode='before')
    def only_dc_charge_params(cls, data: Any) -> Any:
        """
        Only dc_ev_charge_parameter must be set,

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if one_field_must_be_set(
            [
                "dc_ev_charge_parameter",
                "DC_EVChargeParameter",
            ],
            data,
            True,
        ):
            return data

    @model_validator(mode='after')
    def validate_requested_energy_mode(self) -> Self:
        """
        requested_energy_mode must be either DC_extended or DC_core
        Only dc_ev_charge_parameter must be set and must match requested_energy_mode

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use

        requested_energy_mode = self.requested_energy_mode
        ac_params = self.ac_ev_charge_parameter
        dc_params = self.dc_ev_charge_parameter
        if requested_energy_mode not in ("DC_extended", "DC_core"):
            raise V2GMessageValidationError(
                f"[V2G2-476] Wrong energy transfer mode transfer mode "
                f"{requested_energy_mode}",
                ResponseCode.FAILED_WRONG_ENERGY_TRANSFER_MODE,
                self,
            )
        if ("AC_" in requested_energy_mode and dc_params) or (
            "DC_" in requested_energy_mode and ac_params
        ):
            raise V2GMessageValidationError(
                "[V2G2-477] Wrong charge parameters for requested energy "
                f"transfer mode {requested_energy_mode}",
                ResponseCode.FAILED_WRONG_CHARGE_PARAMETER,
                self,
            )
        return self


class ChargeParameterDiscoveryRes(Response):
    """See section 9.4.1.6.3 in DIN SPEC 70121"""

    evse_processing: EVSEProcessing = Field(..., alias="EVSEProcessing")
    sa_schedule_list: Optional[SAScheduleList] = Field(None, alias="SAScheduleList")
    """
    In the scope of DIN SPEC 70121, the element “AC_EVSEChargeParameter”
    shall not be used.
    """
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


class PowerDeliveryReq(BodyBase):
    """See section 9.4.1.7.2 in DIN SPEC 70121"""

    ready_to_charge: bool = Field(..., alias="ReadyToChargeState")
    charging_profile: Optional[ChargingProfile] = Field(None, alias="ChargingProfile")
    dc_ev_power_delivery_parameter: Optional[DCEVPowerDeliveryParameter] = Field(
        None, alias="DC_EVPowerDeliveryParameter"
    )


class PowerDeliveryRes(Response):
    """See section 9.4.1.7.3 in DIN SPEC 70121"""

    """ In the scope of DIN SPEC 70121, AC_EVSEStatus shall not be used. """
    ac_evse_status: Optional[ACEVSEStatus] = Field(None, alias="AC_EVSEStatus")
    dc_evse_status: DCEVSEStatus = Field(..., alias="DC_EVSEStatus")

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


class CableCheckReq(BodyBase):
    """See section 9.4.2.2.2 in DIN SPEC 70121"""

    dc_ev_status: DCEVStatus = Field(..., alias="DC_EVStatus")


class CableCheckRes(Response):
    """See section 9.4.2.2.3 in DIN SPEC 70121"""

    dc_evse_status: DCEVSEStatus = Field(..., alias="DC_EVSEStatus")
    evse_processing: EVSEProcessing = Field(..., alias="EVSEProcessing")


class PreChargeReq(BodyBase):
    """
    See section 9.4.2.3.2 in DIN SPEC 70121
    With the Pre Charging Request the EV asks the EVSE to apply certain values
     for output voltage and output current. Since the contactors of the EV are
    open during Pre Charging, the actual current flow from the EVSE to the EV
    will be very small, i. e. in most cases smaller than the requested output
    current. The EV may use several Pre Charging Request/Response message pairs
    in order to precisely adjust the EVSE output voltage to the EV RESS voltage
    measured inside the EV.
    """

    dc_ev_status: DCEVStatus = Field(..., alias="DC_EVStatus")
    ev_target_voltage: PVEVTargetVoltageDin = Field(..., alias="EVTargetVoltage")
    ev_target_current: PVEVTargetCurrentDin = Field(..., alias="EVTargetCurrent")


class PreChargeRes(Response):
    """See section 9.4.2.3.3 in DIN SPEC 70121"""

    dc_evse_status: DCEVSEStatus = Field(..., alias="DC_EVSEStatus")
    evse_present_voltage: PVEVSEPresentVoltageDin = Field(
        ..., alias="EVSEPresentVoltage"
    )


class CurrentDemandReq(BodyBase):
    """See section 9.4.2.4.2 in DIN SPEC 70121"""

    dc_ev_status: DCEVStatus = Field(..., alias="DC_EVStatus")
    ev_target_current: PVEVTargetCurrentDin = Field(..., alias="EVTargetCurrent")
    ev_max_voltage_limit: Optional[PVEVMaxVoltageLimitDin] = Field(
        None, alias="EVMaximumVoltageLimit"
    )
    ev_max_current_limit: Optional[PVEVMaxCurrentLimitDin] = Field(
        None, alias="EVMaximumCurrentLimit"
    )
    ev_max_power_limit: Optional[PVEVMaxPowerLimitDin] = Field(None, alias="EVMaximumPowerLimit")
    bulk_charging_complete: Optional[bool] = Field(None, alias="BulkChargingComplete")
    charging_complete: bool = Field(..., alias="ChargingComplete")
    remaining_time_to_full_soc: Optional[PVRemainingTimeToFullSOCDin] = Field(
        None, alias="RemainingTimeToFullSoC"
    )
    remaining_time_to_bulk_soc: Optional[PVRemainingTimeToBulkSOCDin] = Field(
        None, alias="RemainingTimeToBulkSoC"
    )
    ev_target_voltage: PVEVTargetVoltageDin = Field(..., alias="EVTargetVoltage")


class CurrentDemandRes(Response):
    """See section 9.4.2.4.3 in DIN SPEC 70121"""

    dc_evse_status: DCEVSEStatus = Field(..., alias="DC_EVSEStatus")
    evse_present_voltage: PVEVSEPresentVoltageDin = Field(
        ..., alias="EVSEPresentVoltage"
    )
    evse_present_current: PVEVSEPresentCurrentDin = Field(
        ..., alias="EVSEPresentCurrent"
    )
    evse_current_limit_achieved: bool = Field(..., alias="EVSECurrentLimitAchieved")
    evse_voltage_limit_achieved: bool = Field(..., alias="EVSEVoltageLimitAchieved")
    evse_power_limit_achieved: bool = Field(..., alias="EVSEPowerLimitAchieved")
    evse_max_voltage_limit: Optional[PVEVSEMaxVoltageLimitDin] = Field(
        None, alias="EVSEMaximumVoltageLimit"
    )
    evse_max_current_limit: Optional[PVEVSEMaxCurrentLimitDin] = Field(
        None, alias="EVSEMaximumCurrentLimit"
    )
    evse_max_power_limit: Optional[PVEVSEMaxPowerLimitDin] = Field(
        None, alias="EVSEMaximumPowerLimit"
    )


class WeldingDetectionReq(BodyBase):
    """See section 9.4.2.5.2 in DIN SPEC 70121"""

    dc_ev_status: DCEVStatus = Field(..., alias="DC_EVStatus")


class WeldingDetectionRes(Response):
    """See section 9.4.2.5.3 in DIN SPEC 70121"""

    dc_evse_status: DCEVSEStatus = Field(..., alias="DC_EVSEStatus")
    evse_present_voltage: PVEVSEPresentVoltageDin = Field(
        ..., alias="EVSEPresentVoltage"
    )


class SessionStopReq(BodyBase):
    """See section 9.4.1.8.2 in DIN SPEC 70121"""


class SessionStopRes(Response):
    """See section 9.4.1.8.3 in DIN SPEC 70121"""


class Body(BaseModel):
    """
    The body element of a V2GMessage.

    See section 9.3.4 Message Body Definition in DIN SPEC 70121
    """

    session_setup_req: Optional[SessionSetupReq] = Field(None, alias="SessionSetupReq")
    session_setup_res: Optional[SessionSetupRes] = Field(None, alias="SessionSetupRes")
    service_discovery_req: Optional[ServiceDiscoveryReq] = Field(
        None, alias="ServiceDiscoveryReq"
    )
    service_discovery_res: Optional[ServiceDiscoveryRes] = Field(
        None, alias="ServiceDiscoveryRes"
    )
    service_payment_selection_req: Optional[ServicePaymentSelectionReq] = Field(
        None, alias="ServicePaymentSelectionReq"
    )
    service_payment_selection_res: Optional[ServicePaymentSelectionRes] = Field(
        None, alias="ServicePaymentSelectionRes"
    )
    contract_authentication_req: Optional[ContractAuthenticationReq] = Field(
        None, alias="ContractAuthenticationReq"
    )
    contract_authentication_res: Optional[ContractAuthenticationRes] = Field(
        None, alias="ContractAuthenticationRes"
    )
    charge_parameter_discovery_req: Optional[ChargeParameterDiscoveryReq] = Field(
        None, alias="ChargeParameterDiscoveryReq"
    )
    charge_parameter_discovery_res: Optional[ChargeParameterDiscoveryRes] = Field(
        None, alias="ChargeParameterDiscoveryRes"
    )
    power_delivery_req: Optional[PowerDeliveryReq] = Field(None, alias="PowerDeliveryReq")
    power_delivery_res: Optional[PowerDeliveryRes] = Field(None, alias="PowerDeliveryRes")
    cable_check_req: Optional[CableCheckReq] = Field(None, alias="CableCheckReq")
    cable_check_res: Optional[CableCheckRes] = Field(None, alias="CableCheckRes")
    pre_charge_req: Optional[PreChargeReq] = Field(None, alias="PreChargeReq")
    pre_charge_res: Optional[PreChargeRes] = Field(None, alias="PreChargeRes")
    current_demand_req: Optional[CurrentDemandReq] = Field(None, alias="CurrentDemandReq")
    current_demand_res: Optional[CurrentDemandRes] = Field(None, alias="CurrentDemandRes")
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
        "ServicePaymentSelectionReq": ServicePaymentSelectionReq,
        "ServicePaymentSelectionRes": ServicePaymentSelectionRes,
        "ContractAuthenticationReq": ContractAuthenticationReq,
        "ContractAuthenticationRes": ContractAuthenticationRes,
        "ChargeParameterDiscoveryReq": ChargeParameterDiscoveryReq,
        "ChargeParameterDiscoveryRes": ChargeParameterDiscoveryRes,
        "CableCheckReq": CableCheckReq,
        "CableCheckRes": CableCheckRes,
        "PreChargeReq": PreChargeReq,
        "PreChargeRes": PreChargeRes,
        "PowerDeliveryReq": PowerDeliveryReq,
        "PowerDeliveryRes": PowerDeliveryRes,
        "CurrentDemandReq": CurrentDemandReq,
        "CurrentDemandRes": CurrentDemandRes,
        "WeldingDetectionReq": WeldingDetectionReq,
        "WeldingDetectionRes": WeldingDetectionRes,
        "SessionStopReq": SessionStopReq,
        "SessionStopRes": SessionStopRes,
    }

    return msg_dict.get(msg_name, None)
