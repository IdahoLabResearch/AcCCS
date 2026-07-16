"""
    Copyright 2025, Ford Motor Company
    Copyright 2022, Switch

This module contains a dummy implementation of the abstract class for an EVCC to
retrieve data from the EV. The DummyEVController overrides all abstract methods from
EVControllerInterface.
"""

import logging
import random
import os
from types import SimpleNamespace
from typing import List, Optional, Tuple, Union

from app.evcc import EVCCConfig
from app.evcc.controller.interface import ChargeParamsV2, EVControllerInterface
from app.shared.exceptions import InvalidProtocolError, MACAddressNotFound
from app.shared.live_control import LiveControl
from app.shared.messages.datatypes import (
    DCEVChargeParams,
    PhysicalValue,
    PVEAmount,
    PVEVEnergyCapacity,
    PVEVMaxCurrent,
    PVEVMaxCurrentLimit,
    PVEVMaxPowerLimit,
    PVEVMaxVoltage,
    PVEVMaxVoltageLimit,
    PVEVMinCurrent,
    PVEVSEPresentVoltage,
    PVEVTargetCurrent,
    PVEVTargetVoltage,
    PVPMax,
    PVRemainingTimeToBulkSOC,
    PVRemainingTimeToFullSOC,
    PVEVMaxCurrentLimitDin,
    PVEVMaxPowerLimitDin,
    PVEVMaxVoltageLimitDin,
    PVEVEnergyCapacityDin,
    PVEVTargetCurrentDin,
    PVEVTargetVoltageDin,
    PVRemainingTimeToBulkSOCDin,
    PVRemainingTimeToFullSOCDin,
)
from app.shared.messages.din_spec.datatypes import (
    DCEVPowerDeliveryParameter as DCEVPowerDeliveryParameterDINSPEC,
)
from app.shared.messages.din_spec.datatypes import DCEVStatus as DCEVStatusDINSPEC
from app.shared.messages.din_spec.datatypes import (
    ProfileEntryDetails as ProfileEntryDetailsDINSPEC,
)
from app.shared.messages.din_spec.datatypes import (
    SAScheduleTupleEntry as SAScheduleTupleEntryDINSPEC,
)
from app.shared.messages.enums import (
    ControlMode,
    DCEVErrorCode,
    EnergyTransferModeEnum,
    Namespace,
    PriceAlgorithm,
    Protocol,
    ServiceV20,
    UnitSymbol,
)
from app.shared.messages.iso15118_2.datatypes import (
    ACEVChargeParameter,
)
from app.shared.messages.iso15118_2.datatypes import (
    ChargeProgress as ChargeProgressV2,
)
from app.shared.messages.iso15118_2.datatypes import (
    ChargingProfile,
    DCEVChargeParameter,
    DCEVPowerDeliveryParameter,
    DCEVStatus,
    ProfileEntryDetails,
    SAScheduleTuple,
)
from app.shared.messages.iso15118_20.ac import (
    ACChargeParameterDiscoveryReqParams,
    BPTACChargeParameterDiscoveryReqParams,
    BPTDynamicACChargeLoopReqParams,
    BPTScheduledACChargeLoopReqParams,
    DynamicACChargeLoopReqParams,
    ScheduledACChargeLoopReqParams,
)
from app.shared.messages.iso15118_20.common_messages import (
    ChargeProgress as ChargeProgressV20,
)
from app.shared.messages.iso15118_20.common_messages import (
    DynamicEVPowerProfile,
    DynamicScheduleExchangeReqParams,
    DynamicScheduleExchangeResParams,
    EMAIDList,
    EVAbsolutePriceSchedule,
    EVEnergyOffer,
    EVPowerProfile,
    EVPowerSchedule,
    EVPowerScheduleEntry,
    EVPowerScheduleEntryList,
    EVPowerProfileEntryList,
    EVPriceRule,
    EVPriceRuleStack,
    EVPriceRuleStackList,
    MatchedService,
    PowerToleranceAcceptance,
    ScheduledEVPowerProfile,
    ScheduledScheduleExchangeReqParams,
    ScheduledScheduleExchangeResParams,
    SelectedEnergyService,
    SelectedVAS,
)
from app.shared.messages.iso15118_20.common_types import (
    DisplayParameters,
    RationalNumber,
)
from app.shared.messages.iso15118_20.dc import (
    BPTDCChargeParameterDiscoveryReqParams,
    BPTDynamicDCChargeLoopReqParams,
    BPTScheduledDCChargeLoopReqParams,
    DCChargeParameterDiscoveryReqParams,
    DynamicDCChargeLoopReqParams,
    ScheduledDCChargeLoopReqParams,
)
from app.shared.network import get_nic_mac_address

logger = logging.getLogger(__name__)


# Skeleton wire-envelope defaults (ADR-0006 #102). The EV's announced DIN /
# ISO-2 / ISO-20 request envelopes are wire-owned by the [[message field tree]]
# and applied via construction-time substitution at each `*Req` build site; the
# ramping charge-loop / target leaves are allowlisted runtime-produced fields
# (ADR-0006 #83). These namespaces are the empty-/partial-tree fallback the tree
# overrides — formerly the personality `power.ev_*` model defaults, retired when
# the pre-tree structured wire sections were deleted. They are builder internals,
# not personality config; the genuinely residual DC target/remaining-time seeds
# live in `residual.charge_ramp` (surfaced on `self.config.ev_dc_target_*` /
# `ev_dc_remaining_*`), not here.
_EV_DC_SKELETON = SimpleNamespace(
    max_voltage_v=500.0,
    max_current_a=32.0,
    max_power_w=80000.0,
    energy_capacity_wh=70000.0,
    remaining_time_to_full_soc_s=100,
    remaining_time_to_bulk_soc_s=80,
)
_EV_AC_SKELETON = SimpleNamespace(
    e_amount_wh=60.0,
    max_voltage_v=400.0,
    max_current_a=32.0,
    min_current_a=10.0,
)
_EV_DC_V20_SKELETON = SimpleNamespace(
    max_charge_power_w=300000.0,
    min_charge_power_w=100.0,
    max_charge_current_a=300.0,
    min_charge_current_a=10.0,
    max_voltage_v=1000.0,
    min_voltage_v=10.0,
    target_voltage_v=20000.0,
    target_current_a=200.0,
    dynamic_target_energy_request_wh=200.0,
    dynamic_max_energy_request_wh=200.0,
    dynamic_min_energy_request_wh=20.0,
    dynamic_max_charge_power_w=4000.0,
    dynamic_min_charge_power_w=400.0,
    dynamic_max_charge_current_a=40.0,
    dynamic_max_voltage_v=400.0,
    dynamic_min_voltage_v=40.0,
    bpt_max_discharge_power_w=11000.0,
    bpt_min_discharge_power_w=1000.0,
    bpt_max_discharge_current_a=11.0,
    bpt_min_discharge_current_a=0.0,
    bpt_dynamic_max_discharge_power_w=300000.0,
    bpt_dynamic_min_discharge_power_w=300000.0,
    bpt_dynamic_max_discharge_current_a=300000.0,
)
_EV_AC_V20_SKELETON = SimpleNamespace(
    max_charge_power_w=11000.0,
    min_charge_power_w=100.0,
    bpt_max_discharge_power_w=11000.0,
    bpt_min_discharge_power_w=1.0,
    scheduled_present_active_power_w=200000.0,
    dynamic_max_charge_power_w=300000.0,
    dynamic_min_charge_power_w=100.0,
    dynamic_present_active_power_w=200000.0,
    dynamic_present_reactive_power_w=20000.0,
)
_SE_V20_SKELETON = SimpleNamespace(
    departure_time_s=7200,
    scheduled_target_energy_request_wh=10000.0,
    scheduled_max_energy_request_wh=20000.0,
    scheduled_min_energy_request_wh=0.05,
    dynamic_min_soc_percent=30,
    dynamic_target_soc_percent=80,
    dynamic_target_energy_request_wh=40000.0,
    dynamic_max_energy_request_wh=60000.0,
    dynamic_min_energy_request_wh=-20000.0,
    dynamic_max_v2x_energy_request_wh=5000.0,
    dynamic_min_v2x_energy_request_wh=0.0,
    ac_dynamic_loop_departure_time_s=2000,
    power_schedule_duration_s=3600,
    power_schedule_power_w=-10000.0,
    price_currency="EUR",
    price_energy_fee=0.0,
)


class SimEVController(EVControllerInterface):
    """
    A simulated version of an EV controller
    """

    def __init__(
        self,
        evcc_config: EVCCConfig,
        live_control: Optional["LiveControl"] = None,
    ):
        self.config = evcc_config
        # Live operator control (ADR-0004). `None` when no console/stall
        # plumbing was wired in (e.g. unit tests that construct the controller
        # directly) — the charge loop then behaves exactly as before.
        self.live_control = live_control
        self.charging_loop_cycles: int = max(evcc_config.charge_loop_cycle, 1)
        self.charge_loop_delay_time: int = min(evcc_config.charge_loop_delay_time, 50)
        self.increment = (1 / self.charging_loop_cycles) * 100
        self.precharge_loop_cycles: int = 0
        self.welding_detection_cycles: int = 0
        self._charging_is_completed = False
        self._soc = 10
        self.dc_ev_charge_params: DCEVChargeParams = self._build_dc_ev_charge_params(
            din=False
        )

    def _build_dc_ev_charge_params(self, din: bool) -> DCEVChargeParams:
        """Construct a DCEVChargeParams from the personality-derived config.

        Per ADR-0001 / issue #7 the EV DC envelope (max V/A/W, target V/A,
        battery capacity) is a personality field surfaced through
        `EVCCConfig.ev_dc_*`. DIN 70121 uses the *Din-suffixed PV classes
        because the EXI schema is distinct from ISO 15118-2; everything
        else uses the base PV classes.

        DIN (#74) and ISO-2 (#97) retirement (ADR-0006): on both protocols the
        *announced maxima* (max V/A/W) and battery capacity are wire-owned by the
        message field tree at each `*Req` build site, so they are sourced here
        from the EV DC-limit model defaults (`EVDCLimits`) rather than
        `config.ev_dc_*`. The structured `ev_dc` maxima no longer feed either
        wire; a personality that wants different maxima sets the tree leaves. The
        `target_*` fields are the issue's explicit carve-out — they stay
        computed/start-value from the config (and pick up the live override in
        `get_dc_charge_params`), because they ramp during the session and are not
        static baseline tree values. The only remaining `din`/non-`din`
        difference is the `*Din`-suffixed PV class selection (the DIN EXI schema
        is distinct from ISO 15118-2).
        """
        cfg = self.config
        limits = _EV_DC_SKELETON
        max_current_a = limits.max_current_a
        max_power_w = limits.max_power_w
        max_voltage_v = limits.max_voltage_v
        energy_capacity_wh = limits.energy_capacity_wh
        max_c_mult, max_c_val = PhysicalValue.get_exponent_value_repr(max_current_a)
        max_p_mult, max_p_val = PhysicalValue.get_exponent_value_repr(max_power_w)
        max_v_mult, max_v_val = PhysicalValue.get_exponent_value_repr(max_voltage_v)
        cap_mult, cap_val = PhysicalValue.get_exponent_value_repr(energy_capacity_wh)
        target_c_mult, target_c_val = PhysicalValue.get_exponent_value_repr(
            cfg.ev_dc_target_current_a
        )
        target_v_mult, target_v_val = PhysicalValue.get_exponent_value_repr(
            cfg.ev_dc_target_voltage_v
        )
        if din:
            return DCEVChargeParams(
                dc_max_current_limit=PVEVMaxCurrentLimitDin(
                    multiplier=max_c_mult, value=max_c_val, unit=UnitSymbol.AMPERE
                ),
                dc_max_power_limit=PVEVMaxPowerLimitDin(
                    multiplier=max_p_mult, value=max_p_val, unit=UnitSymbol.WATT
                ),
                dc_max_voltage_limit=PVEVMaxVoltageLimitDin(
                    multiplier=max_v_mult, value=max_v_val, unit=UnitSymbol.VOLTAGE
                ),
                dc_energy_capacity=PVEVEnergyCapacityDin(
                    multiplier=cap_mult, value=cap_val, unit=UnitSymbol.WATT_HOURS
                ),
                dc_target_current=PVEVTargetCurrentDin(
                    multiplier=target_c_mult,
                    value=target_c_val,
                    unit=UnitSymbol.AMPERE,
                ),
                dc_target_voltage=PVEVTargetVoltageDin(
                    multiplier=target_v_mult,
                    value=target_v_val,
                    unit=UnitSymbol.VOLTAGE,
                ),
            )
        return DCEVChargeParams(
            dc_max_current_limit=PVEVMaxCurrentLimit(
                multiplier=max_c_mult, value=max_c_val, unit=UnitSymbol.AMPERE
            ),
            dc_max_power_limit=PVEVMaxPowerLimit(
                multiplier=max_p_mult, value=max_p_val, unit=UnitSymbol.WATT
            ),
            dc_max_voltage_limit=PVEVMaxVoltageLimit(
                multiplier=max_v_mult, value=max_v_val, unit=UnitSymbol.VOLTAGE
            ),
            dc_energy_capacity=PVEVEnergyCapacity(
                multiplier=cap_mult, value=cap_val, unit=UnitSymbol.WATT_HOURS
            ),
            dc_target_current=PVEVTargetCurrent(
                multiplier=target_c_mult,
                value=target_c_val,
                unit=UnitSymbol.AMPERE,
            ),
            dc_target_voltage=PVEVTargetVoltage(
                multiplier=target_v_mult,
                value=target_v_val,
                unit=UnitSymbol.VOLTAGE,
            ),
        )

    # ============================================================================
    # |             COMMON FUNCTIONS (FOR ALL ENERGY TRANSFER MODES)             |
    # ============================================================================

    async def get_evcc_id(self, protocol: Protocol, iface: str) -> str:
        """Overrides EVControllerInterface.get_evcc_id()."""

        if protocol in (Protocol.ISO_15118_2, Protocol.DIN_SPEC_70121):
            try:
                hex_str = get_nic_mac_address(iface)
                return hex_str.replace(":", "").upper()
            except MACAddressNotFound as exc:
                logger.warning(
                    "Couldn't determine EVCCID (ISO 15118-2) - "
                    f"Reason: {exc}. Setting MAC address to "
                    "'000000000000'"
                )
                return "000000000000"
        elif protocol.ns.startswith(Namespace.ISO_V20_BASE):
            # ISO 15118-20 EVCCID is a VIN-shaped string. The retired
            # `identity.evcc_id` personality seam is gone (#102 — EVCCID is
            # tree-sourced per protocol, and this runtime helper is the
            # allowlisted fallback); a device that wants a specific ISO-20 EVCCID
            # pins it via the SessionSetupReq tree leaf, which overrides this
            # default through construction-time substitution.
            return "1FMVAA45B63C47DD58Y6"
        else:
            logger.error(f"Invalid protocol '{protocol}', can't determine EVCCID")
            raise InvalidProtocolError

    async def get_energy_transfer_mode(
        self, protocol: Protocol
    ) -> EnergyTransferModeEnum:
        """Overrides EVControllerInterface.get_energy_transfer_mode()."""
        return self.config.energy_transfer_mode

    async def get_supported_energy_services(self) -> List[ServiceV20]:
        """Overrides EVControllerInterface.get_energy_transfer_service()."""
        return self.config.supported_energy_services

    async def select_energy_service_v20(
        self, services: List[MatchedService]
    ) -> SelectedEnergyService:
        """Overrides EVControllerInterface.select_energy_service_v20()."""
        top_of_list: MatchedService = services[0]
        selected_service = SelectedEnergyService(
            service=top_of_list.service,
            is_free=top_of_list.is_free,
            parameter_set=top_of_list.parameter_sets[0],
        )
        return selected_service

    async def select_vas_services_v20(
        self, services: List[MatchedService]
    ) -> Optional[List[SelectedVAS]]:
        """Overrides EVControllerInterface.select_vas_services_v20()."""
        matched_vas_services = [
            service for service in services if not service.is_energy_service
        ]
        selected_vas_services: List[SelectedVAS] = []
        for vas_service in matched_vas_services:
            selected_vas_services.append(
                SelectedVAS(
                    service=vas_service.service,
                    is_free=vas_service.is_free,
                    parameter_set=vas_service.parameter_sets[0],
                )
            )
        return selected_vas_services

    async def get_charge_params_v2(self, protocol: Protocol) -> ChargeParamsV2:
        """Overrides EVControllerInterface.get_charge_params_v2().

        ISO-2 retirement (ADR-0006 / #97): the ChargeParameterDiscoveryReq wire
        values are sourced from the message field tree at the build site, so the
        structured reads are retired here. The DC envelope maxima come from the
        `EVDCLimits` model-default skeleton in `self.dc_ev_charge_params` (the
        tree overrides them to the Mach-E 500 A / 422 V / 211000 W). The Mach-E
        (`Mach-E-ISO.pcapng`) omits DepartureTime, EVEnergyCapacity,
        EVEnergyRequest, FullSOC and BulkSOC, so they are left unset to match the
        capture field-for-field — this also retires the structured
        `iso2_energy_request_wh` / `iso2_full_soc_percent` /
        `iso2_bulk_soc_percent` reads. The AC envelope is retired to the
        `EVACLimits` model defaults (no AC capture serves the baseline; the tree
        overrides it, synthetic-fallback per ADR-0006 option B).
        """
        ac_charge_params = None
        dc_charge_params = None

        if (await self.get_energy_transfer_mode(protocol)).startswith("AC"):
            ev_ac = _EV_AC_SKELETON
            e_mult, e_val = PhysicalValue.get_exponent_value_repr(ev_ac.e_amount_wh)
            v_mult, v_val = PhysicalValue.get_exponent_value_repr(ev_ac.max_voltage_v)
            max_c_mult, max_c_val = PhysicalValue.get_exponent_value_repr(
                ev_ac.max_current_a
            )
            min_c_mult, min_c_val = PhysicalValue.get_exponent_value_repr(
                ev_ac.min_current_a
            )
            ac_charge_params = ACEVChargeParameter(
                departure_time=0,
                e_amount=PVEAmount(
                    multiplier=e_mult, value=e_val, unit=UnitSymbol.WATT_HOURS
                ),
                ev_max_voltage=PVEVMaxVoltage(
                    multiplier=v_mult, value=v_val, unit=UnitSymbol.VOLTAGE
                ),
                ev_max_current=PVEVMaxCurrent(
                    multiplier=max_c_mult, value=max_c_val, unit=UnitSymbol.AMPERE
                ),
                ev_min_current=PVEVMinCurrent(
                    multiplier=min_c_mult, value=min_c_val, unit=UnitSymbol.AMPERE
                ),
            )
        else:
            dc_charge_params = DCEVChargeParameter(
                departure_time=None,
                dc_ev_status=await self.get_dc_ev_status(),
                ev_maximum_current_limit=self.dc_ev_charge_params.dc_max_current_limit,
                ev_maximum_power_limit=self.dc_ev_charge_params.dc_max_power_limit,
                ev_maximum_voltage_limit=self.dc_ev_charge_params.dc_max_voltage_limit,
                ev_energy_capacity=None,
                ev_energy_request=None,
                full_soc=None,
                bulk_soc=None,
            )
        return ChargeParamsV2(
            await self.get_energy_transfer_mode(protocol),
            ac_charge_params,
            dc_charge_params,
        )

    async def get_charge_params_v20(
        self, selected_service: SelectedEnergyService
    ) -> Union[
        ACChargeParameterDiscoveryReqParams,
        BPTACChargeParameterDiscoveryReqParams,
        DCChargeParameterDiscoveryReqParams,
        BPTDCChargeParameterDiscoveryReqParams,
    ]:
        """Overrides EVControllerInterface.get_charge_params_v20().

        Both branches are now tree-sourced at their ChargeParameterDiscoveryReq
        build sites, so each reads its model-default *skeleton* here rather than
        `personality.power.ev_{ac,dc}_v20`:

        * DC retirement (ADR-0006 / #99): the ISO-20 DC / DC-BPT requested
          envelope comes from the tree (`{BPT_,}DC_CPDReqEnergyTransferMode → …`);
          the DC branch reads the `EVDCLimitsV20` skeleton (the baseline pins the
          DC-BPT envelope decoded from `iso20.pcap`).
        * AC retirement (ADR-0006 / #101): the ISO-20 AC / AC-BPT requested
          envelope comes from the tree (`{BPT_,}AC_CPDReqEnergyTransferMode → …`);
          the AC branch reads the `EVACLimitsV20` skeleton (the baseline pins the
          plain-AC envelope decoded from `HAL+TCP_ISO_20_AC_Example.pcap`).
        """
        ev_ac_v20 = _EV_AC_V20_SKELETON
        ev_dc_v20 = _EV_DC_V20_SKELETON
        ac_cpd_params = ACChargeParameterDiscoveryReqParams(
            ev_max_charge_power=RationalNumber.get_rational_repr(
                ev_ac_v20.max_charge_power_w if ev_ac_v20 else 11000
            ),
            ev_min_charge_power=RationalNumber.get_rational_repr(
                ev_ac_v20.min_charge_power_w if ev_ac_v20 else 100
            ),
        )
        dc_cpd_params = DCChargeParameterDiscoveryReqParams(
            ev_max_charge_power=RationalNumber.get_rational_repr(
                ev_dc_v20.max_charge_power_w if ev_dc_v20 else 300000
            ),
            ev_min_charge_power=RationalNumber.get_rational_repr(
                ev_dc_v20.min_charge_power_w if ev_dc_v20 else 100
            ),
            ev_max_charge_current=RationalNumber.get_rational_repr(
                ev_dc_v20.max_charge_current_a if ev_dc_v20 else 300
            ),
            ev_min_charge_current=RationalNumber.get_rational_repr(
                ev_dc_v20.min_charge_current_a if ev_dc_v20 else 10
            ),
            ev_max_voltage=RationalNumber.get_rational_repr(
                ev_dc_v20.max_voltage_v if ev_dc_v20 else 1000
            ),
            ev_min_voltage=RationalNumber.get_rational_repr(
                ev_dc_v20.min_voltage_v if ev_dc_v20 else 10
            ),
        )
        if selected_service.service == ServiceV20.AC:
            return ac_cpd_params
        elif selected_service.service == ServiceV20.AC_BPT:
            return BPTACChargeParameterDiscoveryReqParams(
                **(ac_cpd_params.model_dump()),
                ev_max_discharge_power=RationalNumber.get_rational_repr(
                    ev_ac_v20.bpt_max_discharge_power_w if ev_ac_v20 else 11000
                ),
                ev_min_discharge_power=RationalNumber.get_rational_repr(
                    ev_ac_v20.bpt_min_discharge_power_w if ev_ac_v20 else 100
                ),
            )
        elif selected_service.service == ServiceV20.DC:
            return dc_cpd_params
        elif selected_service.service == ServiceV20.DC_BPT:
            return BPTDCChargeParameterDiscoveryReqParams(
                **(dc_cpd_params.model_dump()),
                ev_max_discharge_power=RationalNumber.get_rational_repr(
                    ev_dc_v20.bpt_max_discharge_power_w if ev_dc_v20 else 11000
                ),
                ev_min_discharge_power=RationalNumber.get_rational_repr(
                    ev_dc_v20.bpt_min_discharge_power_w if ev_dc_v20 else 1000
                ),
                ev_max_discharge_current=RationalNumber.get_rational_repr(
                    ev_dc_v20.bpt_max_discharge_current_a if ev_dc_v20 else 11
                ),
                ev_min_discharge_current=RationalNumber.get_rational_repr(
                    ev_dc_v20.bpt_min_discharge_current_a if ev_dc_v20 else 0
                ),
            )
        else:
            # TODO Implement the remaining energy transer services
            logger.error(
                f"Energy transfer service {selected_service.service} not supported"
            )
            raise NotImplementedError

    async def get_scheduled_se_params(
        self, selected_energy_service: SelectedEnergyService
    ) -> ScheduledScheduleExchangeReqParams:
        """Overrides EVControllerInterface.get_scheduled_se_params().

        DC retirement (ADR-0006 / #99): the ScheduleExchangeReq is a common
        ISO-20 message now tree-sourced at its build site, so this builder emits
        the `ScheduleExchangeV20` model-default *skeleton* rather than reading
        `personality.power.schedule_exchange_v20`; the tree overrides any
        configured leaf. (The shipped DC baseline uses Dynamic control mode, so
        it carries no ScheduleExchangeReq tree entry — the announcement stays
        builder-computed, mirroring the ISO-20 DC SECC retirement in #98.)
        """
        se = _SE_V20_SKELETON
        ev_price_rule = EVPriceRule(
            energy_fee=RationalNumber.get_rational_repr(
                se.price_energy_fee if se else 0
            ),
            power_range_start=RationalNumber(exponent=0, value=0),
        )

        ev_price_rule_stack = EVPriceRuleStack(
            duration=0, ev_price_rules=[ev_price_rule]
        )

        ev_price_rule_stack_list = EVPriceRuleStackList(
            ev_price_rule_stacks=[ev_price_rule_stack]
        )

        ev_absolute_price_schedule = EVAbsolutePriceSchedule(
            time_anchor=0,
            currency=se.price_currency if se else "EUR",
            price_algorithm=PriceAlgorithm.POWER,
            ev_price_rule_stacks=ev_price_rule_stack_list,
        )

        ev_power_schedule_entry = EVPowerScheduleEntry(
            duration=se.power_schedule_duration_s if se else 3600,
            power=RationalNumber.get_rational_repr(
                se.power_schedule_power_w if se else -10000
            ),
        )

        ev_power_schedule_entries = EVPowerScheduleEntryList(
            entries=[ev_power_schedule_entry]
        )

        ev_power_schedule = EVPowerSchedule(
            time_anchor=0, ev_power_schedule_entries=ev_power_schedule_entries
        )

        energy_offer = EVEnergyOffer(
            ev_power_schedule=ev_power_schedule,
            ev_absolute_price_schedule=ev_absolute_price_schedule,
        )

        scheduled_params = ScheduledScheduleExchangeReqParams(
            departure_time=se.departure_time_s if se else 7200,
            ev_target_energy_request=RationalNumber.get_rational_repr(
                se.scheduled_target_energy_request_wh if se else 10000
            ),
            ev_max_energy_request=RationalNumber.get_rational_repr(
                se.scheduled_max_energy_request_wh if se else 20000
            ),
            ev_min_energy_request=RationalNumber.get_rational_repr(
                se.scheduled_min_energy_request_wh if se else 0.05
            ),
            ev_energy_offer=energy_offer,
        )

        return scheduled_params

    async def get_dynamic_se_params(
        self, selected_energy_service: SelectedEnergyService
    ) -> DynamicScheduleExchangeReqParams:
        """Overrides EVControllerInterface.get_dynamic_se_params().

        DC retirement (ADR-0006 / #99): departure, SOC targets, and energy
        requests come from the `ScheduleExchangeV20` model-default skeleton, not
        `personality.power.schedule_exchange_v20` — the ScheduleExchangeReq wire
        values are tree-sourced at the build site now (mirroring #98).
        """
        se = _SE_V20_SKELETON
        dynamic_params = DynamicScheduleExchangeReqParams(
            departure_time=se.departure_time_s if se else 7200,
            min_soc=se.dynamic_min_soc_percent if se else 30,
            target_soc=se.dynamic_target_soc_percent if se else 80,
            ev_target_energy_request=RationalNumber.get_rational_repr(
                se.dynamic_target_energy_request_wh if se else 40000
            ),
            ev_max_energy_request=RationalNumber.get_rational_repr(
                se.dynamic_max_energy_request_wh if se else 60000
            ),
            ev_min_energy_request=RationalNumber.get_rational_repr(
                se.dynamic_min_energy_request_wh if se else -20000
            ),
            ev_max_v2x_energy_request=RationalNumber.get_rational_repr(
                se.dynamic_max_v2x_energy_request_wh if se else 5000
            ),
            ev_min_v2x_energy_request=RationalNumber.get_rational_repr(
                se.dynamic_min_v2x_energy_request_wh if se else 0
            ),
        )

        return dynamic_params

    async def process_scheduled_se_params(
        self, scheduled_params: ScheduledScheduleExchangeResParams, pause: bool
    ) -> Tuple[Optional[EVPowerProfile], ChargeProgressV20]:
        """Overrides EVControllerInterface.process_scheduled_se_params()."""
        is_ready = bool(random.getrandbits(1))
        if not is_ready:
            logger.debug("Scheduled parameters for ScheduleExchangeReq not yet ready")
            # TODO The standard doesn't clearly define what the ChargeProgress should
            #      be if EVProcessing is set to ONGOING. Will assume
            #      ChargeProgress.START but check with standardisation community
            return None, ChargeProgressV20.START

        charge_progress = ChargeProgressV20.START

        if pause:
            charge_progress = ChargeProgressV20.STOP

        # Let's just select the first schedule offered
        selected_schedule = scheduled_params.schedule_tuples[0]
        charging_schedule = selected_schedule.charging_schedule.power_schedule
        charging_schedule_entries = charging_schedule.schedule_entry_list.entries

        # We just copy the values from the charging schedule into the EV power profile
        # TODO: What's happening here?
        # ev_power_schedule_entries: List[EVPowerScheduleEntry] = []
        ev_power_schedule_entries = charging_schedule_entries
        # for entry in charging_schedule_entries:
        #     ev_power_schedule_entry = EVPowerScheduleEntry(
        #         duration=entry.duration, power=entry.power
        #     )
        #     ev_power_schedule_entries.append(ev_power_schedule_entry)
        
        ev_power_profile_entry_list = EVPowerProfileEntryList(
            entries=ev_power_schedule_entries
        )

        scheduled_profile = ScheduledEVPowerProfile(
            selected_schedule_tuple_id=selected_schedule.schedule_tuple_id,
            power_tolerance_acceptance=PowerToleranceAcceptance.CONFIRMED,
        )

        ev_power_profile = EVPowerProfile(
            time_anchor=0,
            entry_list=ev_power_profile_entry_list,
            scheduled_profile=scheduled_profile,
        )

        return ev_power_profile, charge_progress

    async def process_dynamic_se_params(
        self, dynamic_params: DynamicScheduleExchangeResParams, pause: bool
    ) -> Tuple[Optional[EVPowerProfile], ChargeProgressV20]:
        """Overrides EVControllerInterface.process_dynamic_se_params()."""
        is_ready = bool(random.getrandbits(1))
        if not is_ready:
            logger.debug("Dynamic parameters for ScheduleExchangeReq not yet ready")
            # TODO The standard doesn't clearly define what the ChargeProgress should
            #      be if EVProcessing is set to ONGOING. Will assume
            #      ChargeProgress.START but check with standardisation community
            return None, ChargeProgressV20.START

        charge_progress = ChargeProgressV20.START

        if pause:
            charge_progress = ChargeProgressV20.STOP

        ev_power_schedule_entry = EVPowerScheduleEntry(
            duration=3600, power=RationalNumber(exponent=0, value=11000)
        )

        ev_power_profile_entry_list = EVPowerScheduleEntryList(
            entries=[ev_power_schedule_entry]
        )

        ev_power_profile = EVPowerProfile(
            time_anchor=0,
            entry_list=ev_power_profile_entry_list,
            dynamic_profile=DynamicEVPowerProfile(),
        )

        return ev_power_profile, charge_progress

    async def is_cert_install_needed(self) -> bool:
        """Overrides EVControllerInterface.is_cert_install_needed()."""
        return self.config.is_cert_install_needed

    async def process_sa_schedules_dinspec(
        self, sa_schedules: List[SAScheduleTupleEntryDINSPEC]
    ) -> int:
        """Overrides EVControllerInterface.process_sa_schedules_dinspec()."""
        schedule = sa_schedules.pop()
        profile_entry_list: List[ProfileEntryDetailsDINSPEC] = []

        # The charging schedule coming from the SECC is called 'schedule', the
        # pendant coming from the EVCC (after having processed the offered
        # schedule(s)) is called 'profile'. Therefore, we use the prefix
        # 'schedule_' for data from the SECC, and 'profile_' for data from the EVCC.
        for schedule_entry_details in schedule.p_max_schedule.entry_details:
            profile_entry_details = ProfileEntryDetailsDINSPEC(
                start=schedule_entry_details.time_interval.start,
                max_power=schedule_entry_details.p_max,
            )
            profile_entry_list.append(profile_entry_details)

            # The last PMaxSchedule element has an optional 'duration' field. if
            # 'duration' is present, then there'll be no more PMaxSchedule element
            # with p_max set to 0 kW. Instead, the 'duration' informs how long the
            # current power level applies before the offered charging schedule ends.
            if schedule_entry_details.time_interval.duration:
                zero_power = 1
                last_profile_entry_details = ProfileEntryDetailsDINSPEC(
                    start=(
                        schedule_entry_details.time_interval.start
                        + schedule_entry_details.time_interval.duration
                    ),
                    max_power=zero_power,
                )
                profile_entry_list.append(last_profile_entry_details)

        return schedule.sa_schedule_tuple_id

    async def process_sa_schedules_v2(
        self, sa_schedules: List[SAScheduleTuple]
    ) -> Tuple[ChargeProgressV2, int, ChargingProfile]:
        """Overrides EVControllerInterface.process_sa_schedules()."""
        secc_schedule = sa_schedules.pop()
        evcc_profile_entry_list: List[ProfileEntryDetails] = []

        # The charging schedule coming from the SECC is called 'schedule', the
        # pendant coming from the EVCC (after having processed the offered
        # schedule(s)) is called 'profile'. Therefore, we use the prefix
        # 'schedule_' for data from the SECC, and 'profile_' for data from the EVCC.
        for schedule_entry_details in secc_schedule.p_max_schedule.schedule_entries:
            profile_entry_details = ProfileEntryDetails(
                start=schedule_entry_details.time_interval.start,
                max_power=schedule_entry_details.p_max,
            )
            evcc_profile_entry_list.append(profile_entry_details)

            # The last PMaxSchedule element has an optional 'duration' field. if
            # 'duration' is present, then there'll be no more PMaxSchedule element
            # (with p_max set to 0 kW). Instead, the 'duration' informs how long the
            # current power level applies before the offered charging schedule ends.
            if schedule_entry_details.time_interval.duration:
                zero_power = PVPMax(multiplier=0, value=0, unit=UnitSymbol.WATT)
                last_profile_entry_details = ProfileEntryDetails(
                    start=(
                        schedule_entry_details.time_interval.start
                        + schedule_entry_details.time_interval.duration
                    ),
                    max_power=zero_power,
                )
                evcc_profile_entry_list.append(last_profile_entry_details)

        # TODO If a SalesTariff is present and digitally signed (and TLS is used),
        #      verify each sales tariff with the mobility operator sub 2 certificate

        return (
            ChargeProgressV2.START,
            secc_schedule.sa_schedule_tuple_id,
            ChargingProfile(profile_entries=evcc_profile_entry_list),
        )

    async def charge_loop_delay(self) -> int:
        """Overrides EVControllerInterface.delay_charge_loop()."""
        return self.charge_loop_delay_time

    async def continue_charging(self) -> bool:
        """Overrides EVControllerInterface.continue_charging()."""
        # Operator stall (ADR-0004): while the charge-loop gate is armed, hold
        # the CurrentDemand loop open indefinitely — ignore the cycle cap and
        # SOC completion — until the operator presses [a]dvance, which releases
        # the gate exactly once so the loop ends via PowerDelivery(STOP).
        if self.live_control is not None and self.live_control.stall_charge_loop:
            if self.live_control.take_charge_loop_release():
                logger.info(
                    "Operator advanced the charge-loop gate; ending "
                    "CurrentDemand loop."
                )
                return False
            return True
        if self.charging_loop_cycles == 0 or await self.is_charging_complete():
            # To simulate a bit of a charging loop, we'll let it run chargingLoopCycle
            # times specified in config file
            return False
        else:
            self.charging_loop_cycles -= 1
            self._soc = min(int(self._soc + self.increment), 100)
            # The line below can just be called once process_message in all states
            # are converted to async calls
            # await asyncio.sleep(0.5)
            return True

    async def store_contract_cert_and_priv_key(
        self, contract_cert: bytes, priv_key: bytes
    ):
        """Overrides EVControllerInterface.store_contract_cert_and_priv_key()."""
        # TODO Need to store the contract cert and private key
        pass

    async def get_prioritised_emaids(self) -> Optional[EMAIDList]:
        return None

    async def ready_to_charge(self) -> bool:
        return await self.continue_charging()

    async def is_precharged(
        self, present_voltage_evse: Union[PVEVSEPresentVoltage, RationalNumber]
    ) -> bool:
        if (
            self.precharge_loop_cycles == 5
            or present_voltage_evse.get_decimal_value()
            == (await self.get_present_voltage()).get_decimal_value()
        ):
            logger.info("Precharge complete.")
            return True
        self.precharge_loop_cycles += 1
        return False

    async def get_dc_ev_power_delivery_parameter_dinspec(
        self,
    ) -> DCEVPowerDeliveryParameterDINSPEC:
        return DCEVPowerDeliveryParameterDINSPEC(
            dc_ev_status=await self.get_dc_ev_status_dinspec(),
            bulk_charging_complete=False,
            charging_complete=await self.continue_charging(),
        )

    async def get_dc_ev_power_delivery_parameter(self) -> DCEVPowerDeliveryParameter:
        # The Mach-E omits BulkChargingComplete from PowerDeliveryReq's
        # DC_EVPowerDeliveryParameter (Mach-E-ISO.pcapng), so it is left unset to
        # match the capture field-for-field (#97); it is Optional.
        return DCEVPowerDeliveryParameter(
            dc_ev_status=await self.get_dc_ev_status(),
            bulk_charging_complete=None,
            charging_complete=await self.continue_charging(),
        )

    async def is_bulk_charging_complete(self) -> bool:
        return False

    async def is_charging_complete(self) -> bool:
        if self._soc == 100 or self._charging_is_completed:
            return True
        else:
            return False

    async def get_remaining_time_to_full_soc(
            self, protocol: Protocol) -> PVRemainingTimeToFullSOC:
        # DIN retirement (ADR-0006 / #74): CurrentDemandReq's remaining-time
        # estimate is wire-owned by the message field tree, so the DIN path uses
        # the EV DC-limit model default rather than `config.ev_dc_remaining_*`.
        if protocol == Protocol.DIN_SPEC_70121:
            mult, val = PhysicalValue.get_exponent_value_repr(
                _EV_DC_SKELETON.remaining_time_to_full_soc_s
            )
            return PVRemainingTimeToFullSOCDin(multiplier=mult, value=val, unit="s")
        mult, val = PhysicalValue.get_exponent_value_repr(
            self.config.ev_dc_remaining_time_to_full_soc_s
        )
        return PVRemainingTimeToFullSOC(multiplier=mult, value=val, unit="s")

    async def get_remaining_time_to_bulk_soc(
            self, protocol: Protocol) -> PVRemainingTimeToBulkSOC:
        # DIN retirement (ADR-0006 / #74): see get_remaining_time_to_full_soc.
        if protocol == Protocol.DIN_SPEC_70121:
            mult, val = PhysicalValue.get_exponent_value_repr(
                _EV_DC_SKELETON.remaining_time_to_bulk_soc_s
            )
            return PVRemainingTimeToBulkSOCDin(multiplier=mult, value=val, unit="s")
        mult, val = PhysicalValue.get_exponent_value_repr(
            self.config.ev_dc_remaining_time_to_bulk_soc_s
        )
        return PVRemainingTimeToBulkSOC(multiplier=mult, value=val, unit="s")

    async def welding_detection_has_finished(self):
        if self.welding_detection_cycles == 3:
            return True
        self.welding_detection_cycles += 1
        return False

    async def stop_charging(self) -> None:
        self._charging_is_completed = True

    async def get_ac_charge_loop_params_v20(
        self, control_mode: ControlMode, selected_service: ServiceV20
    ) -> Union[
        ScheduledACChargeLoopReqParams,
        BPTScheduledACChargeLoopReqParams,
        DynamicACChargeLoopReqParams,
        BPTDynamicACChargeLoopReqParams,
    ]:
        """Overrides EVSControllerInterface.get_ac_charge_loop_params_v20().

        AC retirement (ADR-0006 / #101): the ACChargeLoopReq is tree-sourced at
        its build site now, so the scheduled/dynamic charge-loop magnitudes come
        from the `EVACLimitsV20` / `ScheduleExchangeV20` model-default *skeletons*
        rather than `personality.power.ev_ac_v20` + `schedule_exchange_v20`. These
        loop magnitudes (present active/reactive power, energy requests) are
        runtime-produced and allowlisted — never baseline-pinned — mirroring the
        ISO-20 DC EVCC charge-loop retirement in #99.
        """
        ev_ac_v20 = _EV_AC_V20_SKELETON
        se = _SE_V20_SKELETON
        if control_mode == ControlMode.SCHEDULED:
            scheduled_params = ScheduledACChargeLoopReqParams(
                ev_present_active_power=RationalNumber.get_rational_repr(
                    ev_ac_v20.scheduled_present_active_power_w
                    if ev_ac_v20
                    else 200000
                ),
            )
            if selected_service == ServiceV20.AC_BPT:
                bpt_scheduled_params = BPTScheduledACChargeLoopReqParams(
                    **(scheduled_params.model_dump()),
                )
                return bpt_scheduled_params
            return scheduled_params
        else:
            # Dynamic Mode
            dynamic_params = DynamicACChargeLoopReqParams(
                departure_time=se.ac_dynamic_loop_departure_time_s if se else 2000,
                ev_target_energy_request=RationalNumber.get_rational_repr(
                    se.dynamic_target_energy_request_wh if se else 40000
                ),
                ev_max_energy_request=RationalNumber.get_rational_repr(
                    se.dynamic_max_energy_request_wh if se else 60000
                ),
                ev_min_energy_request=RationalNumber.get_rational_repr(
                    se.dynamic_min_energy_request_wh if se else -20000
                ),
                ev_max_charge_power=RationalNumber.get_rational_repr(
                    ev_ac_v20.dynamic_max_charge_power_w if ev_ac_v20 else 300000
                ),
                ev_min_charge_power=RationalNumber.get_rational_repr(
                    ev_ac_v20.dynamic_min_charge_power_w if ev_ac_v20 else 100
                ),
                ev_present_active_power=RationalNumber.get_rational_repr(
                    ev_ac_v20.dynamic_present_active_power_w
                    if ev_ac_v20
                    else 200000
                ),
                ev_present_reactive_power=RationalNumber.get_rational_repr(
                    ev_ac_v20.dynamic_present_reactive_power_w
                    if ev_ac_v20
                    else 20000
                ),
            )
            if selected_service == ServiceV20.AC_BPT:
                bpt_dynamic_params = BPTDynamicACChargeLoopReqParams(
                    **(dynamic_params.model_dump()),
                    ev_max_discharge_power=RationalNumber.get_rational_repr(
                        ev_ac_v20.bpt_max_discharge_power_w if ev_ac_v20 else 11000
                    ),
                    ev_min_discharge_power=RationalNumber.get_rational_repr(
                        ev_ac_v20.bpt_min_discharge_power_w if ev_ac_v20 else 1
                    ),
                )
                return bpt_dynamic_params
            return dynamic_params

    # ============================================================================
    # |                          DC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    async def get_dc_charge_params(self, protocol: Protocol) -> DCEVChargeParams:
        """Applies to both DIN SPEC and 15118-2."""
        if protocol not in (Protocol.ISO_15118_2, Protocol.DIN_SPEC_70121):
            logger.error(
                f"Invalid protocol '{protocol}' for DC charge params, "
                "expected ISO 15118-2 or DIN SPEC 70121"
            )
            raise InvalidProtocolError
        is_din = protocol == Protocol.DIN_SPEC_70121
        self.dc_ev_charge_params = self._build_dc_ev_charge_params(din=is_din)
        # Live override (ADR-0004, issues #29 / #31): on an EVCC the operator
        # console replaces the EV's *requested target* current/voltage on the DC
        # charge loop — both ISO 15118-2 and DIN SPEC 70121 (DIN parity landed
        # in #31). A `None` field falls back to the personality value built
        # above. Unchecked — the value is whatever the operator typed, bounded
        # only by what `PhysicalValue` can encode. The target uses the DIN
        # PhysicalValue subtypes on the DIN path so the encoded message stays in
        # the right namespace.
        if self.live_control is not None:
            current_cls = PVEVTargetCurrentDin if is_din else PVEVTargetCurrent
            voltage_cls = PVEVTargetVoltageDin if is_din else PVEVTargetVoltage
            if self.live_control.override_current_a is not None:
                c_mult, c_val = PhysicalValue.get_exponent_value_repr(
                    self.live_control.override_current_a
                )
                self.dc_ev_charge_params.dc_target_current = current_cls(
                    multiplier=c_mult, value=c_val, unit=UnitSymbol.AMPERE
                )
            if self.live_control.override_voltage_v is not None:
                v_mult, v_val = PhysicalValue.get_exponent_value_repr(
                    self.live_control.override_voltage_v
                )
                self.dc_ev_charge_params.dc_target_voltage = voltage_cls(
                    multiplier=v_mult, value=v_val, unit=UnitSymbol.VOLTAGE
                )
        return self.dc_ev_charge_params

    async def get_dc_ev_status_dinspec(self) -> DCEVStatusDINSPEC:
        return DCEVStatusDINSPEC(
            ev_ready=True,
            ev_error_code=DCEVErrorCode.NO_ERROR,
            ev_ress_soc=self._soc,
        )

    async def get_dc_ev_status(self) -> DCEVStatus:
        return DCEVStatus(
            ev_ready=True,
            ev_error_code=DCEVErrorCode.NO_ERROR,
            ev_ress_soc=self._soc,
        )

    def _iso20_override_or(self, field: str, fallback: float) -> float:
        """Return the operator's live override for `field`, else `fallback`.

        Live override (ADR-0004, issue #32 — ISO 15118-20 DC parity): on an
        EVCC the operator console replaces the EV's *requested target*
        current/voltage on the ISO-20 DC charge loop, the mirror of what
        `get_dc_charge_params` does for ISO 15118-2 / DIN SPEC 70121. The
        ISO-20 read sites are RationalNumber-valued (no `PVEVTarget*` subtypes),
        so the override flows in as a plain magnitude that the caller hands to
        `RationalNumber.get_rational_repr`. A `None` field — or no
        `live_control` — falls back to the personality value. Unchecked, like
        the ISO-2/DIN paths: bounded only by what `get_rational_repr` encodes.
        """
        if self.live_control is not None:
            override = getattr(self.live_control, field)
            if override is not None:
                return override
        return fallback

    async def get_scheduled_dc_charge_loop_params(
        self,
    ) -> ScheduledDCChargeLoopReqParams:
        """Overrides EVControllerInterface.get_scheduled_dc_charge_loop_params().

        DC retirement (ADR-0006 / #99): the `ev_target_current` /
        `ev_target_voltage` ramping targets are allowlisted (runtime-produced),
        so their `personality.power.ev_dc_v20` fallback retires to the
        `EVDCLimitsV20` model-default skeleton; the operator's live override
        (issue #32) still wins over that fallback via `_iso20_override_or`, and
        these ramping leaves are never baseline-pinned (mirroring #98).
        """
        ev_dc_v20 = _EV_DC_V20_SKELETON
        return ScheduledDCChargeLoopReqParams(
            ev_target_current=RationalNumber.get_rational_repr(
                self._iso20_override_or(
                    "override_current_a",
                    ev_dc_v20.target_current_a if ev_dc_v20 else 200,
                )
            ),
            ev_target_voltage=RationalNumber.get_rational_repr(
                self._iso20_override_or(
                    "override_voltage_v",
                    ev_dc_v20.target_voltage_v if ev_dc_v20 else 20000,
                )
            ),
        )

    async def get_dynamic_dc_charge_loop_params(self) -> DynamicDCChargeLoopReqParams:
        """Overrides EVControllerInterface.get_dynamic_dc_charge_loop_params().

        DC retirement (ADR-0006 / #99): every magnitude comes from the
        `EVDCLimitsV20` model-default skeleton (`dynamic_*` sub-set), not
        `personality.power.ev_dc_v20` — the DCChargeLoopReq is tree-sourced now.
        The live override (issue #32) still lands on the dynamic-mode
        current/voltage limits (`ev_max_charge_current` / `ev_max_voltage`) via
        `_iso20_override_or`; those ramping leaves are allowlisted, never
        baseline-pinned (mirroring #98).
        """
        ev_dc_v20 = _EV_DC_V20_SKELETON
        return DynamicDCChargeLoopReqParams(
            ev_target_energy_request=RationalNumber.get_rational_repr(
                ev_dc_v20.dynamic_target_energy_request_wh if ev_dc_v20 else 200
            ),
            ev_max_energy_request=RationalNumber.get_rational_repr(
                ev_dc_v20.dynamic_max_energy_request_wh if ev_dc_v20 else 200
            ),
            ev_min_energy_request=RationalNumber.get_rational_repr(
                ev_dc_v20.dynamic_min_energy_request_wh if ev_dc_v20 else 20
            ),
            ev_max_charge_power=RationalNumber.get_rational_repr(
                ev_dc_v20.dynamic_max_charge_power_w if ev_dc_v20 else 4000
            ),
            ev_min_charge_power=RationalNumber.get_rational_repr(
                ev_dc_v20.dynamic_min_charge_power_w if ev_dc_v20 else 400
            ),
            ev_max_charge_current=RationalNumber.get_rational_repr(
                self._iso20_override_or(
                    "override_current_a",
                    ev_dc_v20.dynamic_max_charge_current_a if ev_dc_v20 else 40,
                )
            ),
            ev_max_voltage=RationalNumber.get_rational_repr(
                self._iso20_override_or(
                    "override_voltage_v",
                    ev_dc_v20.dynamic_max_voltage_v if ev_dc_v20 else 400,
                )
            ),
            ev_min_voltage=RationalNumber.get_rational_repr(
                ev_dc_v20.dynamic_min_voltage_v if ev_dc_v20 else 40
            ),
        )

    async def get_bpt_scheduled_dc_charge_loop_params(
        self,
    ) -> BPTScheduledDCChargeLoopReqParams:
        """Overrides EVControllerInterface.get_bpt_scheduled_dc_charge_loop_params()."""
        dc_scheduled_dc_charge_loop_params_v20 = (
            await self.get_scheduled_dc_charge_loop_params()
        ).model_dump()
        return BPTScheduledDCChargeLoopReqParams(
            **dc_scheduled_dc_charge_loop_params_v20
        )

    async def get_bpt_dynamic_dc_charge_loop_params(
        self,
    ) -> BPTDynamicDCChargeLoopReqParams:
        """Overrides EVControllerInterface.get_bpt_dynamic_dc_charge_loop_params().

        DC retirement (ADR-0006 / #99): the BPT dynamic-mode discharge envelope
        (`bpt_dynamic_*` sub-set) comes from the `EVDCLimitsV20` model-default
        skeleton, not `personality.power.ev_dc_v20`; the DCChargeLoopReq is
        tree-sourced now (mirroring #98).
        """
        ev_dc_v20 = _EV_DC_V20_SKELETON
        dc_dynamic_dc_charge_loop_params_v20 = (
            await self.get_dynamic_dc_charge_loop_params()
        ).model_dump()
        return BPTDynamicDCChargeLoopReqParams(
            **dc_dynamic_dc_charge_loop_params_v20,
            ev_max_discharge_power=RationalNumber.get_rational_repr(
                ev_dc_v20.bpt_dynamic_max_discharge_power_w if ev_dc_v20 else 300000
            ),
            ev_min_discharge_power=RationalNumber.get_rational_repr(
                ev_dc_v20.bpt_dynamic_min_discharge_power_w if ev_dc_v20 else 300000
            ),
            ev_max_discharge_current=RationalNumber.get_rational_repr(
                ev_dc_v20.bpt_dynamic_max_discharge_current_a
                if ev_dc_v20
                else 300000
            ),
        )

    async def get_present_voltage(self) -> RationalNumber:
        """Overrides EVControllerInterface.get_present_voltage().

        This is the ISO-20 DC charge loop's `ev_present_voltage` read site
        (present on `DCChargeLoopReq` in both scheduled and dynamic modes), so
        the voltage override (issue #32) rides here too. DC retirement (ADR-0006
        / #99): the override's fallback is the `EVDCLimitsV20` model-default
        skeleton, not `personality.power.ev_dc_v20` — this ramping present
        voltage is allowlisted, never baseline-pinned (mirroring #98).
        """
        ev_dc_v20 = _EV_DC_V20_SKELETON
        return RationalNumber.get_rational_repr(
            self._iso20_override_or(
                "override_voltage_v",
                ev_dc_v20.target_voltage_v if ev_dc_v20 else 20000,
            )
        )

    async def get_target_voltage(self) -> RationalNumber:
        """Overrides EVControllerInterface.get_target_voltage().

        DC retirement (ADR-0006 / #99): the DCPreChargeReq target voltage is
        allowlisted (runtime-produced), so its fallback retires to the
        `EVDCLimitsV20` model-default skeleton, not
        `personality.power.ev_dc_v20`.
        """
        ev_dc_v20 = _EV_DC_V20_SKELETON
        return RationalNumber.get_rational_repr(
            ev_dc_v20.target_voltage_v if ev_dc_v20 else 20000
        )

    async def enable_charging(self, enabled: bool) -> None:
        """Overrides EVControllerInterface.enable_charging()."""
        pass

    async def get_display_params(self) -> DisplayParameters:
        """Overrides EVControllerInterface.get_display_params()."""
        return DisplayParameters(
            present_soc=self._soc,
            charging_complete=await self.is_charging_complete(),
        )
