"""
    Copyright 2025, Ford Motor Company
    Copyright 2022, Switch

This module contains the code to retrieve (hardware-related) data from the EVSE
(Electric Vehicle Supply Equipment).
"""

import base64
import logging
import time
import os
from typing import Dict, List, Optional, Union

from app.secc.controller.common import UnknownEnergyService
from app.secc.controller.evse_data import (
    CurrentType,
    EVSEACCLLimits,
    EVSEACCPDLimits,
    EVSEDataContext,
    EVSEDCCLLimits,
    EVSEDCCPDLimits,
    EVSERatedLimits,
    EVSESessionLimits,
)
from app.secc.controller.interface import (
    AuthorizationResponse,
    EVDataContext,
    EVSEControllerInterface,
    ServiceStatus,
)
from app.shared.exceptions import EncryptionError, PrivateKeyReadError
from app.shared.exi_codec import EXI
from app.shared.messages.datatypes import (
    DCEVSEChargeParameter,
    DCEVSEStatus,
    DCEVSEStatusCode,
)
from app.shared.messages.datatypes import EVSENotification as EVSENotificationV2
from app.shared.messages.datatypes import (
    PhysicalValue,
    PVEVSEMaxCurrentLimit,
    PVEVSEMaxPowerLimit,
    PVEVSEMaxVoltageLimit,
    PVEVSEMinCurrentLimit,
    PVEVSEMinVoltageLimit,
    PVEVSEPeakCurrentRipple,
    PVEVSEMaxCurrentLimitDin,
    PVEVSEMaxPowerLimitDin,
    PVEVSEMaxVoltageLimitDin,
    PVEVSEMinCurrentLimitDin,
    PVEVSEMinVoltageLimitDin,
    PVEVSEPeakCurrentRippleDin,
)
from app.shared.messages.din_spec.datatypes import (
    ResponseCode as ResponseCodeDINSPEC,
)
from app.shared.messages.enums import (
    AuthorizationStatus,
    AuthorizationTokenType,
    ControlMode,
    CpState,
    EnergyTransferModeEnum,
    IsolationLevel,
    Namespace,
    PriceAlgorithm,
    Protocol,
    ServiceV20,
    SessionStopAction,
    UnitSymbol,
)
from app.shared.messages.iso15118_2.body import (
    Body,
    CertificateInstallationReq,
    CertificateInstallationRes,
)
from app.shared.messages.iso15118_2.datatypes import (
    EMAID,
    ACEVSEChargeParameter,
    ACEVSEStatus,
    CertificateChain,
    DHPublicKey,
    EncryptedPrivateKey,
)
from app.shared.messages.iso15118_2.datatypes import MeterInfo as MeterInfoV2
from app.shared.messages.iso15118_2.datatypes import (
    PMaxSchedule,
    PMaxScheduleEntry,
    PVEVSEMaxCurrent,
    PVEVSENominalVoltage,
    PVPMax,
    RelativeTimeInterval,
)
from app.shared.messages.iso15118_2.datatypes import ResponseCode as ResponseCodeV2
from app.shared.messages.iso15118_2.datatypes import (
    SalesTariff,
    SalesTariffEntry,
    SAScheduleTuple,
    SubCertificates,
)
from app.shared.messages.iso15118_2.header import MessageHeader as MessageHeaderV2
from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from app.shared.messages.iso15118_20.ac import (
    ACChargeParameterDiscoveryResParams,
    BPTACChargeParameterDiscoveryResParams,
)
from app.shared.messages.iso15118_20.common_messages import (
    AbsolutePriceSchedule,
    AdditionalService,
    AdditionalServiceList,
    ChargingSchedule,
    DischargingSchedule,
    DynamicScheduleExchangeResParams,
    OverstayRule,
    OverstayRuleList,
    Parameter,
    ParameterSet,
    PowerSchedule,
    PowerScheduleEntry,
    PowerScheduleEntryList,
    PriceLevelSchedule,
    PriceLevelScheduleEntry,
    PriceLevelScheduleEntryList,
    PriceRule,
    PriceRuleStack,
    PriceRuleStackList,
    ProviderID,
    ScheduledScheduleExchangeResParams,
    ScheduleExchangeReq,
    ScheduleTuple,
    SelectedEnergyService,
    Service,
    ServiceList,
    ServiceParameterList,
    TaxRule,
    TaxRuleList,
)
from app.shared.messages.iso15118_20.common_types import (
    EVSEStatus,
)
from app.shared.messages.iso15118_20.common_types import MeterInfo as MeterInfoV20
from app.shared.messages.iso15118_20.common_types import (
    RationalNumber,
)
from app.shared.messages.iso15118_20.common_types import (
    ResponseCode as ResponseCodeV20,
)
from app.shared.messages.iso15118_20.dc import (
    BPTDCChargeParameterDiscoveryResParams,
    DCChargeParameterDiscoveryResParams,
)
from app.shared.security import (
    CertPath,
    KeyEncoding,
    KeyPasswordPath,
    KeyPath,
    create_signature,
    encrypt_priv_key,
    get_cert_cn,
    load_cert,
    load_priv_key,
)
from app.shared.personality.message_field_tree import UNSET, resolve_tree_leaf
from app.shared.personality.model import (
    EVSEACLimits,
    EVSEDCLimits,
    EVSEDCLimitsV20,
    EVSEScheduleExchangeV20,
)
from app.shared.states import State

logger = logging.getLogger(__name__)


def get_evse_context():
    ac_limits = EVSEACCPDLimits(
        max_current=10,
        max_charge_power=10,
        min_charge_power=10,
        max_charge_power_l2=10,
        max_charge_power_l3=10,
        min_charge_power_l2=10,
        min_charge_power_l3=10,
        max_discharge_power=10,
        min_discharge_power=10,
        max_discharge_power_l2=10,
        max_discharge_power_l3=10,
        min_discharge_power_l2=10,
        min_discharge_power_l3=10,
    )
    dc_limits = EVSEDCCPDLimits(
        max_charge_power=10,
        min_charge_power=10,
        max_charge_current=10,
        min_charge_current=10,
        max_voltage=10,
        min_voltage=10,
        # 15118-20 DC BPT
        max_discharge_power=10,
        min_discharge_power=10,
        max_discharge_current=10,
        min_discharge_current=10,
    )
    ac_cl_limits = EVSEACCLLimits(
        max_charge_power=10,
        max_charge_power_l2=10,
        max_charge_power_l3=10,
        max_charge_reactive_power=10,
        max_charge_reactive_power_l2=10,
        max_charge_reactive_power_l3=10,
        # BPT attributes
        max_discharge_power=10,
        max_discharge_power_l2=10,
        max_discharge_power_l3=10,
        max_discharge_reactive_power=10,
        max_discharge_reactive_power_l2=10,
        max_discharge_reactive_power_l3=10,
    )
    dc_cl_limits = EVSEDCCLLimits(
        # Optional in 15118-20 DC CL (Scheduled)
        max_charge_power=10,
        min_charge_power=10,
        max_charge_current=10,
        max_voltage=10,
        # Optional and present in 15118-20 DC BPT CL (Scheduled)
        max_discharge_power=10,
        min_discharge_power=10,
        max_discharge_current=10,
        min_voltage=10,
    )
    rated_limits: EVSERatedLimits = EVSERatedLimits(
        ac_limits=ac_limits,
        dc_limits=dc_limits,
    )

    session_limits: EVSESessionLimits = EVSESessionLimits(
        ac_limits=ac_cl_limits,
        dc_limits=dc_cl_limits,
    )
    evse_data_context = EVSEDataContext(
        rated_limits=rated_limits, session_limits=session_limits
    )
    evse_data_context.nominal_voltage = 10
    evse_data_context.nominal_frequency = 10
    evse_data_context.max_power_asymmetry = 10
    evse_data_context.power_ramp_limit = 10
    evse_data_context.present_active_power = 10
    evse_data_context.present_active_power_l2 = 10
    evse_data_context.present_active_power_l3 = 10
    evse_data_context.current_regulation_tolerance = 10
    evse_data_context.energy_to_be_delivered = 10
    evse_data_context.present_current = 1
    evse_data_context.present_voltage = 1
    return evse_data_context


class SimEVSEController(EVSEControllerInterface):
    """
    A simulated version of an EVSE controller
    """

    def __init__(self, personality, live_control=None):
        """Construct a sim controller.

        `personality` is a **required** `SECCPersonality` (ADR-0001 /
        ADR-0006 issue #83). Every wire value the SECC emits is sourced from
        it — `get_evse_id()` reads the EVSEID from `personality.identity`, the
        DIN messages source their leaves from `personality.message_field_tree`,
        and the ISO-2/-20 envelopes read `personality.power`. The
        personality-less construction path (and the in-code `if self.personality
        else <constant>` fallbacks it used to guard) is retired: a personality
        is mandatory to run, so callers that once built the controller bare —
        including the conformance state-machine harness — now pass a
        role-appropriate personality (`SECCPersonality()` for the stock
        defaults).

        `live_control` is the shared `LiveControl` object (ADR-0004); when
        present, the operator console can override the EVSE's reported present
        current/voltage in the ISO 15118-2 charge loop. `None` (the default)
        leaves present-value reads behaving exactly as before.
        """
        if personality is None:
            raise ValueError(
                "SimEVSEController requires a personality (ADR-0006 #83); the "
                "personality-less construction path is retired. Pass a "
                "SECCPersonality (SECCPersonality() for the stock defaults)."
            )
        super().__init__()
        self.personality = personality
        self.live_control = live_control
        self.ev_data_context = EVDataContext()
        self.evse_data_context = get_evse_context()

    def reset_ev_data_context(self):
        self.ev_data_context = EVDataContext()

    # ============================================================================
    # |             COMMON FUNCTIONS (FOR ALL ENERGY TRANSFER MODES)             |
    # ============================================================================
    async def set_status(self, status: ServiceStatus) -> None:
        logger.debug(f"New Status: {status}")

    async def is_valid_evse_id(self, evse_id: str) -> bool:
        # A DIN 70121 EVSE ID is a string of hexadecimal
        # format (each byte represented by two hexadecimal digits).
        try:
            bytes.fromhex(evse_id)
            return True
        except ValueError:
            return False

    async def get_evse_id(self, protocol: Protocol) -> str:
        #  To transform a string-based DIN SPEC 91286 EVSE ID to hexBinary
        #  representation and vice versa, the following conversion rules shall
        #  be used for each character and hex digit: '0' <--> 0x0, '1' <--> 0x1,
        #  '2' <--> 0x2, '3' <--> 0x3, '4' <--> 0x4, '5' <--> 0x5, '6' <--> 0x6,
        #  '7' <--> 0x7, '8' <--> 0x8, '9' <--> 0x9, '*' <--> 0xA,
        #  Unused <--> 0xB .. 0xF.
        # Example: The DIN SPEC 91286 EVSE ID “49*89*6360” is represented
        # as “0x49 0xA8 0x9A 0x63 0x60”.
        
        configured = self.personality.identity.evse_id
        if protocol != Protocol.DIN_SPEC_70121:
            evse_id = configured or "ZZ00000"
        else:
            evse_id = configured or "49A89A6360"
            if not await self.is_valid_evse_id(evse_id):
                logger.warning(
                    f"Invalid EVSE ID {evse_id} provided for protocol "
                    f"{protocol}. Using default EVSE ID."
                )
                evse_id = "49A89A6360"
        return evse_id

    async def get_supported_energy_transfer_modes(
        self, protocol: Protocol
    ) -> List[EnergyTransferModeEnum]:
        """Overrides EVSEControllerInterface.get_supported_energy_transfer_modes()."""
        if protocol == Protocol.DIN_SPEC_70121:
            # Single-source the DIN energy transfer mode from the message field
            # tree (ADR-0006): the advertised value in ServiceDiscoveryRes ->
            # ChargeService -> EnergyTransferType is the *same* value the
            # ChargeParameterDiscovery WrongEnergyTransferType reject-gate
            # compares against, so advertised == accepted by construction. Both
            # the ServiceDiscoveryRes builder and the reject-gate call this
            # method, so routing the read through here is all it takes.
            tree_leaf = resolve_tree_leaf(
                self.personality.message_field_tree,
                "DIN_SPEC_70121",
                "ServiceDiscoveryRes",
                ("charge_service", "energy_transfer_type"),
            )
            if tree_leaf is not UNSET:
                # EnergyTransferType encodes as a restricted EXI enumeration, so
                # the codec accepts only real EnergyTransferModeEnum wire values;
                # every codec-serializable value therefore coerces here. ADR-0006's
                # value-raw seam is vacuous for this field — a value that fails
                # coercion (e.g. the enum name 'DC_EXTENDED' vs the wire value
                # 'DC_extended') could never reach the wire — so a mistyped leaf is
                # rejected at personality load (#76). This coercion is thus total
                # for a loaded personality; the raise is defense-in-depth against a
                # hand-built, unvalidated personality. Whatever this returns is both
                # advertised and accepted (advertised == accepted, ADR-0006).
                try:
                    return [EnergyTransferModeEnum(tree_leaf)]
                except (ValueError, TypeError) as exc:
                    raise ValueError(
                        f"DIN EnergyTransferType {tree_leaf!r} is not a valid "
                        f"energy transfer mode; it cannot be advertised on the wire"
                    ) from exc

            # Fallback for a personality whose tree omits this leaf (e.g. the
            # symmetric din_reference, or any pre-tree personality): the
            # capabilities-sourced mode. DIN SPEC permits only DC_CORE /
            # DC_EXTENDED, so a personality that picked a non-DC mode by hand
            # clamps to DC_EXTENDED.
            configured = self.personality.capabilities.resolved_energy_transfer_mode()
            if configured in (
                EnergyTransferModeEnum.DC_CORE,
                EnergyTransferModeEnum.DC_EXTENDED,
            ):
                return [configured]
            return [EnergyTransferModeEnum.DC_EXTENDED]

        if protocol == Protocol.ISO_15118_2:
            # Single-source the ISO-2 SupportedEnergyTransferMode list from the
            # message field tree (ADR-0006 / #96), mirroring the DIN branch: the
            # advertised list in ServiceDiscoveryRes -> ChargeService ->
            # SupportedEnergyTransferMode -> EnergyTransferMode is the *same* list
            # the ChargeParameterDiscovery WrongEnergyTransferMode reject-gate
            # compares against, so advertised == accepted by construction. Both
            # the ServiceDiscoveryRes builder and the reject-gate call this
            # method, so routing the read through here is all it takes.
            tree_leaf = resolve_tree_leaf(
                self.personality.message_field_tree,
                "ISO_15118_2",
                "ServiceDiscoveryRes",
                ("charge_service", "supported_energy_transfer_mode", "energy_modes"),
            )
            if tree_leaf is not UNSET:
                # EnergyTransferMode encodes as a restricted EXI enumeration, so
                # every codec-serializable member coerces here; a value that
                # cannot coerce could never reach the wire, so the raise is
                # defense-in-depth against a hand-built personality. The tree may
                # spell a single mode as a scalar or the usual list.
                modes = tree_leaf if isinstance(tree_leaf, (list, tuple)) else [tree_leaf]
                try:
                    return [EnergyTransferModeEnum(m) for m in modes]
                except (ValueError, TypeError) as exc:
                    raise ValueError(
                        f"ISO-2 SupportedEnergyTransferMode {tree_leaf!r} contains "
                        f"a value that is not a valid energy transfer mode; it "
                        f"cannot be advertised on the wire"
                    ) from exc

        # It's not valid to have mixed energy transfer modes associated with
        # a single EVSE. Providing this here only for simulation purposes. The
        # pre-tree fallback for an ISO-2 / ISO-20 personality that carries no
        # ServiceDiscoveryRes energy-mode leaf.
        # ac_single_phase = EnergyTransferModeEnum.AC_SINGLE_PHASE_CORE
        ac_three_phase = EnergyTransferModeEnum.AC_THREE_PHASE_CORE
        dc_extended = EnergyTransferModeEnum.DC_EXTENDED
        return [dc_extended, ac_three_phase]

    async def get_schedule_exchange_params(
        self,
        selected_energy_service: SelectedEnergyService,
        control_mode: ControlMode,
        schedule_exchange_req: ScheduleExchangeReq,
    ) -> Union[ScheduledScheduleExchangeResParams, DynamicScheduleExchangeResParams]:
        if control_mode == ControlMode.SCHEDULED:
            return await self.get_scheduled_se_params(
                selected_energy_service, schedule_exchange_req
            )
        else:
            return await self.get_dynamic_se_params(
                selected_energy_service, schedule_exchange_req
            )

    async def get_scheduled_se_params(
        self,
        selected_energy_service: SelectedEnergyService,
        schedule_exchange_req: ScheduleExchangeReq,
    ) -> ScheduledScheduleExchangeResParams:
        """Overrides EVSEControllerInterface.get_scheduled_se_params().

        Retired structured read (ADR-0006 / #98): the schedule envelope
        (durations + power + available energy + tolerance) no longer comes from
        `personality.power.evse_schedule_exchange_v20`. The builder emits a
        model-default skeleton; the `ScheduleExchangeRes` tree leaves supply any
        configured wire values via construction-time substitution at the state's
        build site (mirroring the ISO-2 SECC retirement, #96). The pricing / tax
        / overstay meta-structures stay hardcoded — they are protocol-interop
        stubs, not personality. (The `iso20-dc-secc-baseline`'s source capture
        uses Dynamic control mode with an empty ScheduleExchangeRes control-mode
        payload, so its scheduled/dynamic params stay builder-computed.)
        """
        evse_se = EVSEScheduleExchangeV20()
        schedule_duration = evse_se.schedule_duration_s
        charge_power_w = evse_se.charge_power_w
        discharge_power_w = evse_se.discharge_power_w
        available_energy_wh = evse_se.available_energy_wh
        power_tolerance_w = evse_se.power_tolerance_w
        charging_power_schedule_entry = PowerScheduleEntry(
            duration=schedule_duration,
            power=RationalNumber.get_rational_repr(charge_power_w),
        )

        charging_power_schedule = PowerSchedule(
            time_anchor=0,
            available_energy=RationalNumber.get_rational_repr(available_energy_wh),
            power_tolerance=RationalNumber.get_rational_repr(power_tolerance_w),
            schedule_entry_list=PowerScheduleEntryList(
                entries=[charging_power_schedule_entry]
            ),
        )

        tax_rule = TaxRule(
            tax_rule_id=1,
            tax_rule_name="What a great tax rule",
            tax_rate=RationalNumber(exponent=0, value=10),
            tax_included_in_price=False,
            applies_to_energy_fee=True,
            applies_to_parking_fee=True,
            applies_to_overstay_fee=True,
            applies_to_min_max_cost=True,
        )

        tax_rules = TaxRuleList(tax_rule=[tax_rule])

        price_rule = PriceRule(
            energy_fee=RationalNumber(exponent=0, value=20),
            parking_fee=RationalNumber(exponent=0, value=0),
            parking_fee_period=0,
            carbon_dioxide_emission=0,
            renewable_energy_percentage=0,
            power_range_start=RationalNumber(exponent=0, value=0),
        )

        price_rule_stack = PriceRuleStack(duration=3600, price_rules=[price_rule])

        price_rule_stacks = PriceRuleStackList(price_rule_stacks=[price_rule_stack])

        overstay_rule = OverstayRule(
            description="What a great description",
            start_time=0,
            fee=RationalNumber(exponent=0, value=50),
            fee_period=3600,
        )

        overstay_rules = OverstayRuleList(
            time_threshold=3600,
            power_threshold=RationalNumber(exponent=3, value=30),
            rules=[overstay_rule],
        )

        additional_service = AdditionalService(
            service_name="What a great service name",
            service_fee=RationalNumber(exponent=0, value=0),
        )

        additional_services = AdditionalServiceList(
            additional_services=[additional_service]
        )

        charging_absolute_price_schedule = AbsolutePriceSchedule(
            time_anchor=0,
            schedule_id=1,
            currency="EUR",
            language="ENG",
            price_algorithm=PriceAlgorithm.POWER,
            min_cost=RationalNumber(exponent=0, value=1),
            max_cost=RationalNumber(exponent=0, value=10),
            tax_rules=tax_rules,
            price_rule_stacks=price_rule_stacks,
            overstay_rules=overstay_rules,
            additional_services=additional_services,
        )

        discharging_power_schedule_entry = PowerScheduleEntry(
            duration=schedule_duration,
            power=RationalNumber.get_rational_repr(discharge_power_w),
        )

        discharging_power_schedule = PowerSchedule(
            time_anchor=0,
            schedule_entry_list=PowerScheduleEntryList(
                entries=[discharging_power_schedule_entry]
            ),
        )

        discharging_absolute_price_schedule = charging_absolute_price_schedule

        charging_schedule = ChargingSchedule(
            power_schedule=charging_power_schedule,
            absolute_price_schedule=charging_absolute_price_schedule,
        )
        
        discharging_schedule = DischargingSchedule(
            power_schedule=discharging_power_schedule,
            absolute_price_schedule=discharging_absolute_price_schedule,
        )

        schedule_tuple = ScheduleTuple(
            schedule_tuple_id=1,
            charging_schedule=charging_schedule,
            discharging_schedule=discharging_schedule,
        )

        scheduled_params = ScheduledScheduleExchangeResParams(
            schedule_tuples=[schedule_tuple]
        )

        return scheduled_params

    async def get_service_parameter_list(
        self, service_id: int
    ) -> Optional[ServiceParameterList]:
        """Overrides EVSEControllerInterface.get_service_parameter_list()."""
        parameter_sets_list: List[ParameterSet] = []

        try:
            connector_parameter = Parameter(name="Connector", int_value=2)

            nominal_voltage = 400

            nominal_voltage_parameter = Parameter(
                name="EVSENominalVoltage", int_value=nominal_voltage
            )
            # TODO: map the pricing type
            pricing_parameter = Parameter(name="Pricing", int_value=0)

            parameter_set_id: int = 1
            # According to the spec, both EVSE and EV must offer Scheduled = 1 and
            # Dynamic = 2 control modes
            # As the EVCC Simulator will choose the first parameter set by default,
            # we first advertise the one with Dynamic control mode 2
            # The env variable 15118_20_PRIORITIZE_DYNAMIC_CONTROL_MODE is provided
            # if this is to be inverted. When set, the first parameter set will be for
            # scheduled control mode. This will be removed soon. For testing purposes
            # only.
            control_modes = [1, 2]

            for control_mode in control_modes:
                control_mode_parameter = Parameter(
                    name="ControlMode", int_value=control_mode
                )
                mobility_needs_parameter = Parameter(
                    name="MobilityNeedsMode", int_value=control_mode
                )
                parameters_list: list = [
                    connector_parameter,
                    nominal_voltage_parameter,
                    pricing_parameter,
                    control_mode_parameter,
                    mobility_needs_parameter,
                ]
                parameter_set = ParameterSet(
                    id=parameter_set_id, parameters=parameters_list
                )
                parameter_sets_list.append(parameter_set)
                # increment the parameter set id for the next set of them
                parameter_set_id += 1
                if control_mode == 2:
                    # [V2G20-2663]:The SECC shall only offer MobilityNeedsMode equal
                    # to ‘2’ when ControlMode is set to ‘2’ (Dynamic).
                    # So, for Dynamic mode the MobilityNeeds can have the value
                    # of 1 or 2 so in this if clause we insert another parameter set
                    # for Dynamic mode but for MobilityNeedsMode = 1 (MobilityNeeds
                    # provided by the EVCC).
                    parameters_list.remove(mobility_needs_parameter)
                    mobility_needs_parameter = Parameter(
                        name="MobilityNeedsMode", int_value=1
                    )
                    parameters_list.append(mobility_needs_parameter)
                    parameter_set = ParameterSet(
                        id=parameter_set_id, parameters=parameters_list
                    )
                    parameter_sets_list.append(parameter_set)
                    # increment the parameter set id for the next set
                    parameter_set_id += 1
        except AttributeError as e:
            logger.error(
                f"No ServiceParameterList available for service ID {service_id}"
            )
            raise e

        return ServiceParameterList(parameter_sets=parameter_sets_list)

    async def get_dynamic_se_params(
        self,
        selected_energy_service: SelectedEnergyService,
        schedule_exchange_req: ScheduleExchangeReq,
    ) -> DynamicScheduleExchangeResParams:
        """Overrides EVSEControllerInterface.get_dynamic_se_params().

        Retired structured read (ADR-0006 / #98): `departure_time`, `min_soc`,
        `target_soc`, and the price schedule duration no longer come from
        `personality.power.evse_schedule_exchange_v20`. The builder emits a
        model-default skeleton; the `ScheduleExchangeRes` tree leaves supply any
        configured wire values at the state's build site (mirroring #96).
        """
        evse_se = EVSEScheduleExchangeV20()
        price_level_schedule_entry = PriceLevelScheduleEntry(
            duration=evse_se.schedule_duration_s,
            price_level=1,
        )

        schedule_entries = PriceLevelScheduleEntryList(
            entries=[price_level_schedule_entry]
        )

        price_level_schedule = PriceLevelSchedule(
            id="id1",
            time_anchor=0,
            schedule_id=1,
            schedule_description="What a great description",
            num_price_levels=1,
            schedule_entries=schedule_entries,
        )

        dynamic_params = DynamicScheduleExchangeResParams(
            departure_time=evse_se.dynamic_departure_time_s,
            min_soc=evse_se.dynamic_min_soc_percent,
            target_soc=evse_se.dynamic_target_soc_percent,
            price_level_schedule=price_level_schedule,
        )

        return dynamic_params

    async def get_energy_service_list(self) -> ServiceList:
        """Overrides EVSEControllerInterface.get_energy_service_list()."""
        # AC = 1, DC = 2, AC_BPT = 5, DC_BPT = 6;
        # DC_ACDP = 4 and DC_ADCP_BPT NOT supported

        current_protocol = self.get_selected_protocol()
        if current_protocol == Protocol.ISO_15118_20_DC:
            service_ids = [2, 6]
        elif current_protocol == Protocol.ISO_15118_20_AC:
            service_ids = [1, 5]

        service_list: ServiceList = ServiceList(services=[])
        for service_id in service_ids:
            service_list.services.append(
                Service(service_id=service_id, free_service=False)
            )

        return service_list

    def is_eim_authorized(self) -> bool:
        """Overrides EVSEControllerInterface.is_eim_authorized()."""
        return False

    async def is_authorized(
        self,
        id_token: Optional[str] = None,
        id_token_type: Optional[AuthorizationTokenType] = None,
        certificate_chain: Optional[bytes] = None,
        hash_data: Optional[List[Dict[str, str]]] = None,
    ) -> AuthorizationResponse:
        """Overrides EVSEControllerInterface.is_authorized()."""
        protocol = self.get_selected_protocol()
        response_code: Optional[
            Union[ResponseCodeDINSPEC, ResponseCodeV2, ResponseCodeV20]
        ] = None
        if protocol == Protocol.DIN_SPEC_70121:
            response_code = ResponseCodeDINSPEC.OK
        elif protocol == Protocol.ISO_15118_20_COMMON_MESSAGES:
            response_code = ResponseCodeV20.OK
        else:
            response_code = ResponseCodeV2.OK

        return AuthorizationResponse(
            authorization_status=AuthorizationStatus.ACCEPTED,
            certificate_response_status=response_code,
        )

    async def get_sa_schedule_list(
        self,
        ev_data_context: EVDataContext,
        is_free_charging_service: bool,
        max_schedule_entries: Optional[int],
        departure_time: int = 0,
    ) -> Optional[List[SAScheduleTuple]]:
        """Overrides EVSEControllerInterface.get_sa_schedule_list()."""
        sa_schedule_list: List[SAScheduleTuple] = []

        if departure_time == 0:
            # [V2G2-304] If no departure_time is provided, the sum of the individual
            # time intervals shall be greater than or equal to 24 hours.
            departure_time = 86400

        # PMaxSchedule entries. The structured `evse_dc.iso2_sa_schedule_pmax_w`
        # / `iso2_sales_tariff_id` reads are retired (ADR-0006 / #96): the ISO-2
        # ChargeParameterDiscoveryRes -> SAScheduleList wire value is sourced from
        # the message field tree at the build site (a personality that carries an
        # SAScheduleList tree overrides this wholesale in apply_personality_tree).
        # This builds the skeleton from the DC-limit model defaults so it stays a
        # valid, stable schedule for the tree to override and for empty-/partial-
        # tree personalities to fall back on.
        skeleton_dc = EVSEDCLimits()
        configured_pmax_w = skeleton_dc.iso2_sa_schedule_pmax_w
        schedule_entries = []
        # SalesTariff
        sales_tariff_entries: List[SalesTariffEntry] = []
        remaining_charge_duration = departure_time
        counter = 1
        start = 0
        while remaining_charge_duration > 0:
            pmax_mult, pmax_val = PhysicalValue.get_exponent_value_repr(
                configured_pmax_w
            )
            p_max = PVPMax(multiplier=pmax_mult, value=pmax_val, unit=UnitSymbol.WATT)

            p_max_schedule_entry = PMaxScheduleEntry(
                p_max=p_max, time_interval=RelativeTimeInterval(start=start)
            )

            sales_tariff_entry = SalesTariffEntry(
                e_price_level=counter,
                time_interval=RelativeTimeInterval(start=start),
            )

            if remaining_charge_duration <= 86400:
                p_max_schedule_entry = PMaxScheduleEntry(
                    p_max=p_max,
                    time_interval=RelativeTimeInterval(
                        start=start, duration=remaining_charge_duration
                    ),
                )

                sales_tariff_entry = SalesTariffEntry(
                    e_price_level=counter,
                    time_interval=RelativeTimeInterval(
                        start=start, duration=remaining_charge_duration
                    ),
                )

            remaining_charge_duration -= 86400
            start += 86400
            counter += 1
            schedule_entries.append(p_max_schedule_entry)
            sales_tariff_entries.append(sales_tariff_entry)

        p_max_schedule = PMaxSchedule(schedule_entries=schedule_entries)

        sales_tariff = SalesTariff(
            id="id1",
            sales_tariff_id=skeleton_dc.iso2_sales_tariff_id,
            sales_tariff_entry=sales_tariff_entries,
            num_e_price_levels=len(sales_tariff_entries),
        )

        # Putting the list of SAScheduleTuple entries together
        sa_schedule_tuple = SAScheduleTuple(
            sa_schedule_tuple_id=1,
            p_max_schedule=p_max_schedule,
            sales_tariff=None if is_free_charging_service else sales_tariff,
        )

        # TODO We could also implement an optional SalesTariff, but for the sake of
        #      time we'll do that later (after the basics are implemented).
        #      When implementing the SalesTariff, we also need to apply a digital
        #      signature to it.
        sa_schedule_list.append(sa_schedule_tuple)

        # TODO We need to take care of [V2G2-741], which says that the SECC needs to
        #      resend a previously agreed SAScheduleTuple and the "period of time
        #      this SAScheduleTuple applies for shall be reduced by the time already
        #      elapsed".

        return sa_schedule_list

    async def get_meter_info_v2(self) -> MeterInfoV2:
        """Overrides EVSEControllerInterface.get_meter_info_v2().

        Per issue #8: `meter_id` and `meter_reading` are sourced from
        `personality.meter` when a personality is attached. The reading
        itself is the personality's `starting_reading_wh` baseline — the
        per-message live reading remains runtime-derived and is layered
        in by the wire codec on top of the baseline.
        """
        meter = self.personality.meter
        return MeterInfoV2(
            meter_id=meter.meter_id,
            meter_reading=meter.starting_reading_wh,
            t_meter=int(time.time()),
        )

    async def get_meter_info_v20(self) -> MeterInfoV20:
        """Overrides EVSEControllerInterface.get_meter_info_v20().

        Both `meter_id` and `charged_energy_reading_wh` are personality
        fields — the latter sourced from `meter.starting_reading_wh`
        (same field that seeds the ISO-2 / DIN meter reading) so the
        per-protocol wire values stay consistent for a given personality.
        """
        meter = self.personality.meter
        return MeterInfoV20(
            meter_id=meter.meter_id,
            charged_energy_reading_wh=meter.starting_reading_wh,
            meter_timestamp=int(time.time()),
        )

    async def get_supported_providers(self) -> Optional[List[ProviderID]]:
        """Overrides EVSEControllerInterface.get_supported_providers()."""
        return None

    async def set_hlc_charging(self, is_ongoing: bool) -> None:
        """Overrides EVSEControllerInterface.set_hlc_charging()."""
        pass

    async def stop_charger(self) -> None:
        pass

    async def get_cp_state(self) -> CpState:
        """Overrides EVSEControllerInterface.set_cp_state()."""
        return CpState.C2

    async def service_renegotiation_supported(self) -> bool:
        """Overrides EVSEControllerInterface.service_renegotiation_supported()."""
        return False

    async def is_contactor_closed(self) -> Optional[bool]:
        """Overrides EVSEControllerInterface.is_contactor_closed()."""
        return True

    async def is_contactor_opened(self) -> bool:
        """Overrides EVSEControllerInterface.is_contactor_opened()."""
        return True

    async def get_evse_status(self) -> Optional[EVSEStatus]:
        """Overrides EVSEControllerInterface.get_evse_status()."""
        # TODO: this function can be generic to all protocols.
        #       We can make use of the method `get_evse_id`
        #       or other way to get the evse_id to request
        #       status of a specific evse_id. We can also use the
        #       `self.comm_session.protocol` obtained during SAP,
        #       and inject its value into the `get_evse_status`
        #       to decide on providing the -2ß EVSEStatus or the
        #       -2 AC or DC one and the `selected_charging_type_is_ac` in -2
        #       to decide on returning the ACEVSEStatus or the DCEVSEStatus
        #
        # Just as an example, here is how the return could look like
        # from app.shared.messages.iso15118_20.common_types import (
        #    EVSENotification as EVSENotificationV20,
        # )
        # return EVSEStatus(
        #        notification_max_delay=0,
        #        evse_notification=EVSENotificationV20.TERMINATE
        #    )
        return None

    async def set_present_protocol_state(self, state: State):
        logger.debug(f"iso15118 state: {str(state)}")

    # ============================================================================
    # |                          AC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    async def get_ac_evse_status(self) -> ACEVSEStatus:
        """Overrides EVSEControllerInterface.get_ac_evse_status()."""
        return ACEVSEStatus(
            notification_max_delay=0,
            evse_notification=EVSENotificationV2.NONE,
            rcd=False,
        )

    async def get_ac_charge_params_v2(self) -> ACEVSEChargeParameter:
        """Overrides EVSEControllerInterface.get_ac_evse_charge_parameter().

        The structured `personality.power.evse_ac` read is retired (ADR-0006 /
        #96): the ISO-2 ChargeParameterDiscoveryRes.ac_charge_parameter wire value
        is sourced from the message field tree at the build site. This builds the
        skeleton from the AC-limit model defaults so it stays a valid envelope for
        the tree to override and for empty-/partial-tree personalities to fall
        back on.
        """
        evse_ac = EVSEACLimits()
        v_mult, v_val = PhysicalValue.get_exponent_value_repr(evse_ac.nominal_voltage_v)
        c_mult, c_val = PhysicalValue.get_exponent_value_repr(evse_ac.max_current_a)
        evse_nominal_voltage = PVEVSENominalVoltage(
            multiplier=v_mult, value=v_val, unit=UnitSymbol.VOLTAGE
        )
        evse_max_current = PVEVSEMaxCurrent(
            multiplier=c_mult, value=c_val, unit=UnitSymbol.AMPERE
        )
        return ACEVSEChargeParameter(
            ac_evse_status=await self.get_ac_evse_status(),
            evse_nominal_voltage=evse_nominal_voltage,
            evse_max_current=evse_max_current,
        )

    async def get_ac_charge_params_v20(
        self, energy_service: ServiceV20
    ) -> Optional[
        Union[
            ACChargeParameterDiscoveryResParams, BPTACChargeParameterDiscoveryResParams
        ]
    ]:
        """Overrides EVSEControllerInterface.get_ac_charge_params_v20().

        Per issue #9 / Slice 4 every AC envelope value comes from
        `personality.power.evse_ac_v20`. The phase-symmetric model holds
        a single magnitude per concept and the wire echoes it to L1/L2/L3.
        """
        evse_ac_v20 = self.personality.power.evse_ac_v20
        max_charge_power = evse_ac_v20.max_charge_power_w
        min_charge_power = evse_ac_v20.min_charge_power_w
        nominal_frequency = evse_ac_v20.nominal_frequency_hz
        max_power_asymmetry = evse_ac_v20.max_power_asymmetry_w
        power_ramp_limit = evse_ac_v20.power_ramp_limit_w_per_s
        ac_charge_parameter_discovery_res_params = ACChargeParameterDiscoveryResParams(
            evse_max_charge_power=RationalNumber.get_rational_repr(max_charge_power),
            evse_max_charge_power_l2=RationalNumber.get_rational_repr(
                max_charge_power
            ),
            evse_max_charge_power_l3=RationalNumber.get_rational_repr(
                max_charge_power
            ),
            evse_min_charge_power=RationalNumber.get_rational_repr(min_charge_power),
            evse_min_charge_power_l2=RationalNumber.get_rational_repr(
                min_charge_power
            ),
            evse_min_charge_power_l3=RationalNumber.get_rational_repr(
                min_charge_power
            ),
            evse_nominal_frequency=RationalNumber.get_rational_repr(
                nominal_frequency
            ),
            max_power_asymmetry=RationalNumber.get_rational_repr(
                max_power_asymmetry
            ),
            evse_power_ramp_limit=RationalNumber.get_rational_repr(power_ramp_limit),
            evse_present_active_power=RationalNumber.get_rational_repr(0),
            evse_present_active_power_l2=RationalNumber.get_rational_repr(0),
            evse_present_active_power_l3=RationalNumber.get_rational_repr(0),
        )
        if energy_service == ServiceV20.AC:
            return ac_charge_parameter_discovery_res_params
        elif energy_service == ServiceV20.AC_BPT:
            bpt_max_discharge = evse_ac_v20.bpt_max_discharge_power_w
            bpt_min_discharge = evse_ac_v20.bpt_min_discharge_power_w
            return BPTACChargeParameterDiscoveryResParams(
                **(ac_charge_parameter_discovery_res_params.model_dump()),
                evse_max_discharge_power=RationalNumber.get_rational_repr(
                    bpt_max_discharge
                ),
                evse_max_discharge_power_l2=RationalNumber.get_rational_repr(
                    bpt_max_discharge
                ),
                evse_max_discharge_power_l3=RationalNumber.get_rational_repr(
                    bpt_max_discharge
                ),
                evse_min_discharge_power=RationalNumber.get_rational_repr(
                    bpt_min_discharge
                ),
                evse_min_discharge_power_l2=RationalNumber.get_rational_repr(
                    bpt_min_discharge
                ),
                evse_min_discharge_power_l3=RationalNumber.get_rational_repr(
                    bpt_min_discharge
                ),
            )
        else:
            raise UnknownEnergyService(f"Unknown Service {energy_service}")

    # ============================================================================
    # |                          DC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    async def get_dc_evse_status(self) -> DCEVSEStatus:
        """Overrides EVSEControllerInterface.get_dc_evse_status()."""
        return DCEVSEStatus(
            evse_notification=EVSENotificationV2.NONE,
            notification_max_delay=0,
            evse_isolation_status=IsolationLevel.VALID,
            evse_status_code=DCEVSEStatusCode.EVSE_READY,
        )

    async def get_dc_charge_parameters(self) -> DCEVSEChargeParameter:
        """Overrides EVSEControllerInterface.get_dc_evse_charge_parameter().

        For DIN 70121 (#73) *and* ISO 15118-2 (#96) the structured `evse_dc` read
        is **retired**: the wire DC envelope is sourced from the message field
        tree at the ChargeParameterDiscoveryRes build site. This method builds the
        skeleton from the DC-limit model defaults so it stays a valid, stable
        envelope for the tree to override (and the fallback for empty-/partial-
        tree personalities). Both callers — `get_dc_charge_parameters_dinspec`
        and `get_dc_charge_parameters_v2` — are now tree-backed, so the read is
        the model default for either.
        """
        protocol = self.get_selected_protocol()
        evse_dc = EVSEDCLimits()

        max_p_mult, max_p_val = PhysicalValue.get_exponent_value_repr(
            evse_dc.max_power_w
        )
        max_c_mult, max_c_val = PhysicalValue.get_exponent_value_repr(
            evse_dc.max_current_a
        )
        max_v_mult, max_v_val = PhysicalValue.get_exponent_value_repr(
            evse_dc.max_voltage_v
        )
        min_c_mult, min_c_val = PhysicalValue.get_exponent_value_repr(
            evse_dc.min_current_a
        )
        min_v_mult, min_v_val = PhysicalValue.get_exponent_value_repr(
            evse_dc.min_voltage_v
        )
        ripple_mult, ripple_val = PhysicalValue.get_exponent_value_repr(
            evse_dc.peak_current_ripple_a
        )

        if protocol == Protocol.DIN_SPEC_70121:
            max_power = PVEVSEMaxPowerLimitDin(
                multiplier=max_p_mult, value=max_p_val, unit="W"
            )
            max_current = PVEVSEMaxCurrentLimitDin(
                multiplier=max_c_mult, value=max_c_val, unit="A"
            )
            max_voltage = PVEVSEMaxVoltageLimitDin(
                multiplier=max_v_mult, value=max_v_val, unit="V"
            )
            min_current = PVEVSEMinCurrentLimitDin(
                multiplier=min_c_mult, value=min_c_val, unit="A"
            )
            min_voltage = PVEVSEMinVoltageLimitDin(
                multiplier=min_v_mult, value=min_v_val, unit="V"
            )
            ripple = PVEVSEPeakCurrentRippleDin(
                multiplier=ripple_mult, value=ripple_val, unit="A"
            )
        else:
            max_power = PVEVSEMaxPowerLimit(
                multiplier=max_p_mult, value=max_p_val, unit="W"
            )
            max_current = PVEVSEMaxCurrentLimit(
                multiplier=max_c_mult, value=max_c_val, unit="A"
            )
            max_voltage = PVEVSEMaxVoltageLimit(
                multiplier=max_v_mult, value=max_v_val, unit="V"
            )
            min_current = PVEVSEMinCurrentLimit(
                multiplier=min_c_mult, value=min_c_val, unit="A"
            )
            min_voltage = PVEVSEMinVoltageLimit(
                multiplier=min_v_mult, value=min_v_val, unit="V"
            )
            ripple = PVEVSEPeakCurrentRipple(
                multiplier=ripple_mult, value=ripple_val, unit="A"
            )

        return DCEVSEChargeParameter(
            dc_evse_status=DCEVSEStatus(
                notification_max_delay=100,
                evse_notification=EVSENotificationV2.NONE,
                evse_isolation_status=IsolationLevel.VALID,
                evse_status_code=DCEVSEStatusCode.EVSE_READY,
            ),
            evse_maximum_power_limit=max_power,
            evse_maximum_current_limit=max_current,
            evse_maximum_voltage_limit=max_voltage,
            evse_minimum_current_limit=min_current,
            evse_minimum_voltage_limit=min_voltage,
            evse_peak_current_ripple=ripple,
        )

    async def get_dc_charge_parameters_dinspec(self) -> DCEVSEChargeParameter:
        previous = self.get_selected_protocol()
        self.set_selected_protocol(Protocol.DIN_SPEC_70121)
        try:
            return await self.get_dc_charge_parameters()
        finally:
            self.set_selected_protocol(previous)

    async def start_cable_check(self):
        """Overrides EVSEControllerInterface.start_cable_check()."""
        pass

    async def get_cable_check_status(self) -> Union[IsolationLevel, None]:
        """Overrides EVSEControllerInterface.get_cable_check_status()."""
        return IsolationLevel.VALID

    async def send_charging_command(
        self,
        ev_target_voltage: Optional[float],
        ev_target_current: Optional[float],
        is_precharge: bool = False,
        is_session_bpt: bool = False,
    ):
        pass

    async def is_evse_current_limit_achieved(self) -> bool:
        return False

    async def is_evse_voltage_limit_achieved(self) -> bool:
        return False

    async def is_evse_power_limit_achieved(self) -> bool:
        return False

    # async def get_evse_max_voltage_limit(self) -> PVEVSEMaxVoltageLimit:
    #     return PVEVSEMaxVoltageLimit(multiplier=0, value=600, unit="V")

    # async def get_evse_max_current_limit(self) -> PVEVSEMaxCurrentLimit:
    #     return PVEVSEMaxCurrentLimit(multiplier=0, value=300, unit="A")

    async def get_evse_max_power_limit(self, protocol: Protocol) -> PVEVSEMaxPowerLimit:
        # DIN (#73) and ISO-2 (#96): the structured evse_dc read is retired;
        # CurrentDemandRes.EVSEMaximumPowerLimit is tree-sourced at the build
        # site. Skeleton value = DC-limit model default. ISO-20 keeps its own
        # v20 getter and does not reach here.
        max_power_w = EVSEDCLimits().max_power_w
        mult, val = PhysicalValue.get_exponent_value_repr(max_power_w)
        if protocol == Protocol.DIN_SPEC_70121:
            return PVEVSEMaxPowerLimitDin(multiplier=mult, value=val, unit="W")
        else:
            return PVEVSEMaxPowerLimit(multiplier=mult, value=val, unit="W")

    async def get_evse_max_current_limit(
        self,
        protocol: Protocol,
    ):
        """Personality-driven override for the DC path.

        The interface implementation reads from session_limits and depends
        on `evse_data_context.current_type` being set by the CPD state. The
        DIN slice surfaces this limit directly from the personality so the
        wire value is stable across early-session calls. AC and ISO-15118-2
        / -20 paths fall back to the inherited behaviour.
        """
        if protocol == Protocol.DIN_SPEC_70121:
            # DIN: retired evse_dc read (ADR-0006 / #73);
            # CurrentDemandRes.EVSEMaximumCurrentLimit is tree-sourced at the
            # build site. Skeleton value = DC-limit model default.
            mult, val = PhysicalValue.get_exponent_value_repr(
                EVSEDCLimits().max_current_a
            )
            return PVEVSEMaxCurrentLimitDin(multiplier=mult, value=val, unit="A")
        if self.evse_data_context.current_type != CurrentType.DC:
            return await super().get_evse_max_current_limit(protocol)
        # ISO-2 DC: retired evse_dc read (ADR-0006 / #96); the CurrentDemandRes
        # EVSEMaximumCurrentLimit is tree-sourced at the build site. Skeleton
        # value = DC-limit model default.
        mult, val = PhysicalValue.get_exponent_value_repr(
            EVSEDCLimits().max_current_a
        )
        return PVEVSEMaxCurrentLimit(multiplier=mult, value=val, unit="A")

    async def get_evse_max_voltage_limit(
        self, protocol: Protocol
    ) -> PVEVSEMaxVoltageLimit:
        if protocol == Protocol.DIN_SPEC_70121:
            # DIN: retired evse_dc read (ADR-0006 / #73);
            # CurrentDemandRes.EVSEMaximumVoltageLimit is tree-sourced at the
            # build site. Skeleton value = DC-limit model default.
            mult, val = PhysicalValue.get_exponent_value_repr(
                EVSEDCLimits().max_voltage_v
            )
            return PVEVSEMaxVoltageLimitDin(multiplier=mult, value=val, unit="V")
        if self.evse_data_context.current_type != CurrentType.DC:
            return await super().get_evse_max_voltage_limit(protocol)
        # ISO-2 DC: retired evse_dc read (ADR-0006 / #96); the CurrentDemandRes
        # EVSEMaximumVoltageLimit is tree-sourced at the build site. Skeleton
        # value = DC-limit model default.
        mult, val = PhysicalValue.get_exponent_value_repr(
            EVSEDCLimits().max_voltage_v
        )
        return PVEVSEMaxVoltageLimit(multiplier=mult, value=val, unit="V")

    async def get_dc_charge_params_v20(
        self, energy_service: ServiceV20
    ) -> Union[
        DCChargeParameterDiscoveryResParams, BPTDCChargeParameterDiscoveryResParams
    ]:
        """Override EVSEControllerInterface.get_dc_charge_params_v20().

        Retired structured read (ADR-0006 / #98): the ISO-20 DC envelope (and
        DC-BPT discharge envelope) no longer comes from
        `personality.power.evse_dc_v20`. The builder now emits a model-default
        skeleton and the `DCChargeParameterDiscoveryRes` tree leaves
        (`{BPT_,}DC_CPDResEnergyTransferMode → …`) supply the wire values via
        construction-time substitution at the DC state's build site, mirroring
        the ISO-2 SECC retirement (#96). The tree value flows on into the EVSE
        session limits (the state applies it before `update_dc_charge_parameters_v20`),
        so the DCChargeLoopRes control-mode envelope inherits it too.
        """
        evse_dc_v20 = EVSEDCLimitsV20()
        dc_charge_parameter_discovery_res = DCChargeParameterDiscoveryResParams(
            evse_max_charge_power=RationalNumber.get_rational_repr(
                evse_dc_v20.max_charge_power_w
            ),
            evse_min_charge_power=RationalNumber.get_rational_repr(
                evse_dc_v20.min_charge_power_w
            ),
            evse_max_charge_current=RationalNumber.get_rational_repr(
                evse_dc_v20.max_charge_current_a
            ),
            evse_min_charge_current=RationalNumber.get_rational_repr(
                evse_dc_v20.min_charge_current_a
            ),
            evse_max_voltage=RationalNumber.get_rational_repr(
                evse_dc_v20.max_voltage_v
            ),
            evse_min_voltage=RationalNumber.get_rational_repr(
                evse_dc_v20.min_voltage_v
            ),
            evse_power_ramp_limit=RationalNumber.get_rational_repr(
                evse_dc_v20.power_ramp_limit_w_per_s
            ),
        )
        if energy_service == ServiceV20.DC:
            return dc_charge_parameter_discovery_res
        elif energy_service == ServiceV20.DC_BPT:
            return BPTDCChargeParameterDiscoveryResParams(
                **(dc_charge_parameter_discovery_res.model_dump()),
                evse_max_discharge_power=RationalNumber.get_rational_repr(
                    evse_dc_v20.bpt_max_discharge_power_w
                ),
                evse_min_discharge_power=RationalNumber.get_rational_repr(
                    evse_dc_v20.bpt_min_discharge_power_w
                ),
                evse_max_discharge_current=RationalNumber.get_rational_repr(
                    evse_dc_v20.bpt_max_discharge_current_a
                ),
                evse_min_discharge_current=RationalNumber.get_rational_repr(
                    evse_dc_v20.bpt_min_discharge_current_a
                ),
            )
        else:
            raise UnknownEnergyService(f"Unknown Service {energy_service}")

    async def get_15118_ev_certificate(
        self, base64_encoded_cert_installation_req: str, namespace: str
    ) -> str:
        """
        Overrides EVSEControllerInterface.get_15118_ev_certificate().

        Here we simply mock the actions of the backend.
        The code here is almost the same as what is done if USE_CPO_BACKEND
        is set to False. Except that both the request and response is base64 encoded.
        """
        cert_install_req_exi = base64.b64decode(base64_encoded_cert_installation_req)
        cert_install_req = EXI().from_exi_document(cert_install_req_exi, namespace)
        try:
            dh_pub_key, encrypted_priv_key_bytes = encrypt_priv_key(
                oem_prov_cert=load_cert(CertPath.OEM_LEAF_DER),
                priv_key_to_encrypt=load_priv_key(
                    KeyPath.CONTRACT_LEAF_PEM,
                    KeyEncoding.PEM,
                    KeyPasswordPath.CONTRACT_LEAF_KEY_PASSWORD,
                ),
            )
        except EncryptionError:
            raise EncryptionError(
                "EncryptionError while trying to encrypt the private key for the "
                "contract certificate"
            )
        except PrivateKeyReadError as exc:
            raise PrivateKeyReadError(
                f"Can't read private key to encrypt for CertificateInstallationRes:"
                f" {exc}"
            )

        # The elements that need to be part of the signature
        contract_cert_chain = CertificateChain(
            id="id1",
            certificate=load_cert(CertPath.CONTRACT_LEAF_DER),
            sub_certificates=SubCertificates(
                certificates=[
                    load_cert(CertPath.MO_SUB_CA2_DER),
                    load_cert(CertPath.MO_SUB_CA1_DER),
                ]
            ),
        )
        encrypted_priv_key = EncryptedPrivateKey(
            id="id2", value=encrypted_priv_key_bytes
        )
        dh_public_key = DHPublicKey(id="id3", value=dh_pub_key)
        emaid = EMAID(
            id="id4", value=get_cert_cn(load_cert(CertPath.CONTRACT_LEAF_DER))
        )
        cps_certificate_chain = CertificateChain(
            certificate=load_cert(CertPath.CPS_LEAF_DER),
            sub_certificates=SubCertificates(
                certificates=[
                    load_cert(CertPath.CPS_SUB_CA2_DER),
                    load_cert(CertPath.CPS_SUB_CA1_DER),
                ]
            ),
        )

        cert_install_res = CertificateInstallationRes(
            response_code=ResponseCodeV2.OK,
            cps_cert_chain=cps_certificate_chain,
            contract_cert_chain=contract_cert_chain,
            encrypted_private_key=encrypted_priv_key,
            dh_public_key=dh_public_key,
            emaid=emaid,
        )

        try:
            # Elements to sign, containing its id and the exi encoded stream
            contract_cert_tuple = (
                cert_install_res.contract_cert_chain.id,
                EXI().to_exi_fragment(
                    cert_install_res.contract_cert_chain,
                    Namespace.ISO_V2_MSG_DEF,
                    root_name="ContractSignatureCertChain",
                ),
            )
            encrypted_priv_key_tuple = (
                cert_install_res.encrypted_private_key.id,
                EXI().to_exi_fragment(
                    cert_install_res.encrypted_private_key, Namespace.ISO_V2_MSG_DEF
                ),
            )
            dh_public_key_tuple = (
                cert_install_res.dh_public_key.id,
                EXI().to_exi_fragment(
                    cert_install_res.dh_public_key, Namespace.ISO_V2_MSG_DEF
                ),
            )
            emaid_tuple = (
                cert_install_res.emaid.id,
                EXI().to_exi_fragment(cert_install_res.emaid, Namespace.ISO_V2_MSG_DEF),
            )

            elements_to_sign = [
                contract_cert_tuple,
                encrypted_priv_key_tuple,
                dh_public_key_tuple,
                emaid_tuple,
            ]
            # The private key to be used for the signature
            signature_key = load_priv_key(
                KeyPath.CPS_LEAF_PEM,
                KeyEncoding.PEM,
                KeyPasswordPath.CPS_LEAF_KEY_PASSWORD,
            )

            signature = create_signature(elements_to_sign, signature_key)

        except PrivateKeyReadError as exc:
            raise Exception(
                "Can't read private key needed to create signature "
                f"for CertificateInstallationRes: {exc}",
            )
        except Exception as exc:
            raise Exception(f"Error creating signature {exc}")

        if isinstance(cert_install_req, CertificateInstallationReq):
            header = MessageHeaderV2(
                session_id=cert_install_req.header.session_id,
                signature=signature,
            )
            body = Body.model_validate(
                {"CertificateInstallationRes": cert_install_res.model_dump()}
            )
            to_be_exi_encoded = V2GMessageV2(header=header, body=body)
            exi_encoded_cert_installation_res = EXI().to_exi_document(
                to_be_exi_encoded, Namespace.ISO_V2_MSG_DEF
            )

            # base64.b64encode in Python is a binary transform
            # so the return value is byte[]
            # But the CPO expects exi_encoded_cert_installation_res
            # as a string, hence the added .decode("utf-8")
            base64_encode_cert_install_res = base64.b64encode(
                exi_encoded_cert_installation_res
            ).decode("utf-8")

            return base64_encode_cert_install_res
        else:
            logger.info(f"Ignoring EXI decoding of a {type(cert_install_req)} message.")
            return ""

    async def update_data_link(self, action: SessionStopAction) -> None:
        """
        Overrides EVSEControllerInterface.update_data_link().
        """
        pass

    def ready_to_charge(self) -> bool:
        """
        Overrides EVSEControllerInterface.ready_to_charge().
        """
        return True

    async def session_ended(self, current_state: str, reason: str):
        """
        Reports the state and reason where the session ended.

        @param current_state: The current SDP/SAP/DIN/ISO15118-2/ISO15118-20 state.
        @param reason: Reason for ending the session.
        @param last_message: The last message that was either sent/received.
        """
        logger.info(f"Session ended in {current_state} ({reason}).")

    async def send_display_params(self):
        """
        Share display params with CS.
        """
        logger.debug("Send display params to CS.")

    async def send_rated_limits(self):
        """
        Overrides EVSEControllerInterface.send_rated_limits
        """
        logger.debug("Send rated limits to CS.")
