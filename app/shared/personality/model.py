"""Pydantic models for AcCCS personality + runtime configuration.

Per ADR-0001 a personality describes *who* the emulated device is — IDs,
supported protocols, power/charging profile, TLS posture, SLAC timings, cert
paths. Runtime knobs are *per-invocation operator* concerns (logging level,
NMAP toggles, virtual mode).

The sections (identity / network / slac / tls / capabilities / power /
charge_profile / certificates) are concern-first per ADR-0001's "Considered
Options" section. Per-protocol override blocks within sections are
explicitly deferred.

Strict validation: unknown keys at any level are a hard error. That is what
makes a personality a contract rather than a suggestion. The future
`raw_overrides:` section reserved by ADR-0001 will live in a separately-
validated submodel and is out of scope for Slice 1.
"""

from __future__ import annotations

from typing import List, Literal, Optional, Type

from pydantic import BaseModel, ConfigDict, Field

from app.shared.messages.enums import (
    AuthEnum,
    EnergyTransferModeEnum,
    Protocol,
    ServiceV20,
)


Role = Literal["evcc", "secc"]


class _StrictBase(BaseModel):
    """Base class for every personality section.

    `extra=forbid` is what gives us the "unknown fields are a hard error"
    promise from ADR-0001. Anything that looks like a typo blows up at load
    time rather than silently being ignored.
    """

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# Section models
# ---------------------------------------------------------------------------


class Identity(_StrictBase):
    """Identity fields the device advertises.

    `evcc_id` is the EVCCID (today: a VIN-shaped string on the EVCC side).
    `evse_id` follows DIN SPEC 91286 / ISO 15118 EVSEID formatting on the
    SECC side. Both fields are present on the model so a single personality
    file shape works for both roles, but each role only consumes the field
    relevant to it.
    """

    evcc_id: str = "1FMVAA45B63C47DD58Y6"
    evse_id: str = "49A89A6360"


class Network(_StrictBase):
    """Network attachment knobs (per-deployment topology)."""

    interface: str = "eth0"


class SLAC(_StrictBase):
    """SLAC / HomePlug GreenPHY timing + network identity.

    `nid` and `nmk` are per-AVLN identifiers — the original CLI surfaced
    them as `--NID` / `--NMK` byte strings on the SECC. They are personality
    fields because they describe how this device joins the PLC network.
    `sound_timeout_ms` mirrors the historical `--slacSoundTimeout` CLI flag
    on the EVCC.
    """

    sound_timeout_ms: int = 1000
    # Default NID/NMK match the hard-coded historical bytes in run_secc.py.
    nid_hex: str = "9cb0b2bbf56c0e"
    nmk_hex: str = "48fe5602dbaccde51edadc3e081a52d1"


class TLS(_StrictBase):
    """TLS posture.

    - `enable_tls_1_3`: if False, ISO 15118-20 sessions are refused (it
      mandates TLS 1.3).
    - `use_tls`: EVCC's hint in the SDP request; ignored when
      `enforce_tls` is True.
    - `enforce_tls`: hard requirement — refuse non-TLS sessions.
    - `sdp_retry_cycles`: how many SDP retries before falling back to PWM.
    """

    enable_tls_1_3: bool = True
    use_tls: bool = True
    enforce_tls: bool = False
    sdp_retry_cycles: int = 1


class Capabilities(_StrictBase):
    """Negotiable capabilities offered/announced during a session.

    Concern-first per ADR-0001: a single value per field, no per-protocol
    override blocks (deferred). Slices 2–4 may add fields that some
    protocols ignore — that is fine; the field is announced or not based on
    which protocol got negotiated.
    """

    supported_protocols: List[str] = Field(
        default_factory=lambda: [
            "DIN_SPEC_70121",
            "ISO_15118_2",
            "ISO_15118_20_AC",
            "ISO_15118_20_DC",
        ]
    )
    supported_auth_modes: List[str] = Field(default_factory=lambda: ["PNC", "EIM"])
    supported_energy_services: List[str] = Field(default_factory=lambda: ["DC"])
    energy_transfer_mode: str = "DC_extended"

    free_charging_service: bool = False
    free_cert_install_service: bool = True
    allow_cert_install_service: bool = True
    use_cpo_backend: bool = False
    standby_allowed: bool = False
    is_cert_install_needed: bool = False
    max_supporting_points: int = 1024

    def resolved_protocols(self) -> List[Protocol]:
        from app.shared.utils import load_requested_protocols

        return load_requested_protocols(self.supported_protocols)

    def resolved_auth_modes(self) -> List[AuthEnum]:
        from app.shared.utils import load_requested_auth_modes

        return load_requested_auth_modes(self.supported_auth_modes)

    def resolved_energy_services(self) -> List[ServiceV20]:
        from app.shared.utils import load_requested_energy_services

        return load_requested_energy_services(self.supported_energy_services)

    def resolved_energy_transfer_mode(self) -> EnergyTransferModeEnum:
        return EnergyTransferModeEnum(self.energy_transfer_mode)


class EVSEDCLimits(_StrictBase):
    """SECC-side DC power-electronics envelope.

    These fields go on the wire as the PVEVSE* physical values inside DIN
    70121 ChargeParameterDiscoveryRes (the per-session maxima/minima and
    peak ripple) and CurrentDemandRes (the max current/voltage/power
    advertised during the charge loop). They describe what the EVSE *can*
    deliver — not what it is presently delivering, which is a runtime-derived
    measurement and remains computed at message-build time.
    """

    # Voltage envelope advertised by the EVSE.
    max_voltage_v: float = 500.0
    min_voltage_v: float = 0.0
    # Current envelope advertised by the EVSE.
    max_current_a: float = 400.0
    min_current_a: float = 0.0
    # Maximum DC power the EVSE can source. The same value is reused for
    # both ChargeParameterDiscoveryRes.evse_maximum_power_limit and the
    # CurrentDemandRes.evse_max_power_limit field in DIN 70121.
    max_power_w: float = 80000.0
    # Peak ripple current the EVSE may emit on the DC bus.
    peak_current_ripple_a: float = 5.0
    # AC-side nominal voltage at the EVSE inlet — referenced by
    # interface.get_evse_max_current_limit() when current_type is AC.
    nominal_voltage_v: float = 400.0
    # DIN SAScheduleList PMaxScheduleEntry — the EVSE-advertised power
    # envelope for the charging schedule. Personality because it describes
    # what the EVSE *would offer* before any per-session negotiation. DIN
    # 70121's PMaxScheduleEntry.p_max is an XSD `int` clamped to int16
    # (0..32767 W) so the schema enforces that range here too.
    sa_schedule_pmax_w: int = Field(default=30000, ge=0, le=32767)
    sa_schedule_duration_s: int = 3600
    # ISO 15118-2 SAScheduleList PMaxScheduleEntry — the EVSE-advertised
    # power envelope for the ISO-2 charging schedule. Distinct from DIN's
    # field because ISO-2's PMax goes on the wire as a PVPMax (PhysicalValue
    # with multiplier) so the XSD does not pin it to int16.
    iso2_sa_schedule_pmax_w: int = Field(default=11000, ge=0)
    # SalesTariff.sales_tariff_id advertised alongside the PMax schedule.
    # The XSD constrains this to xs:unsignedByte (1..255).
    iso2_sales_tariff_id: int = Field(default=10, ge=1, le=255)


class EVDCLimits(_StrictBase):
    """EVCC-side DC charging envelope.

    These fields go on the wire as the PVEVMax* physical values in DIN
    70121 ChargeParameterDiscoveryReq (the EV's announced maxima) and
    CurrentDemandReq (the same maxima resent each loop). The `target_*`
    fields populate the EV's PreCharge and start-of-loop CurrentDemand
    intent before the runtime charge controller substitutes real targets.
    """

    max_voltage_v: float = 500.0
    max_current_a: float = 32.0
    max_power_w: float = 80000.0
    # EV battery nameplate energy capacity — DIN
    # ChargeParameterDiscoveryReq.dc_energy_capacity.
    energy_capacity_wh: float = 70000.0
    # EV's initial target voltage/current used for the first PreCharge and
    # CurrentDemand messages.
    target_voltage_v: float = 500.0
    target_current_a: float = 1.0
    # DIN CurrentDemandReq's optional EV-supplied remaining-time estimates.
    remaining_time_to_full_soc_s: int = 100
    remaining_time_to_bulk_soc_s: int = 80
    # ISO 15118-2 DCEVChargeParameter additions (no DIN equivalent on the
    # wire). EnergyRequest is what the EV asks the EVSE to deliver this
    # session; the full_soc / bulk_soc fields are EV-side battery targets.
    iso2_energy_request_wh: float = 6000.0
    iso2_full_soc_percent: int = Field(default=90, ge=0, le=100)
    iso2_bulk_soc_percent: int = Field(default=80, ge=0, le=100)


class EVSEACLimits(_StrictBase):
    """SECC-side AC charging envelope (ISO 15118-2 AC mode).

    Goes on the wire as ACEVSEChargeParameter.evse_nominal_voltage and
    evse_max_current advertised during ChargeParameterDiscoveryRes when
    the negotiated energy mode is AC.
    """

    nominal_voltage_v: float = 400.0
    max_current_a: float = 32.0


class EVACLimits(_StrictBase):
    """EVCC-side AC charging envelope (ISO 15118-2 AC mode).

    Goes on the wire as ACEVChargeParameter fields in
    ChargeParameterDiscoveryReq: e_amount (energy requested),
    ev_max_voltage / ev_max_current / ev_min_current.
    """

    # ISO-2 sends e_amount in Wh; the wire field uses PVEAmount with a
    # multiplier so the value here is the plain Wh number.
    e_amount_wh: float = 60.0
    max_voltage_v: float = 400.0
    max_current_a: float = 32.0
    min_current_a: float = 10.0


class EVSEDCLimitsV20(_StrictBase):
    """SECC-side DC envelope advertised in ISO 15118-20 sessions.

    Goes on the wire as the EVSE* fields inside
    `DCChargeParameterDiscoveryResParams` and (for DC-BPT) the
    `BPTDCChargeParameterDiscoveryResParams` extension. ISO 15118-20's DC
    envelope is distinct from the DIN/ISO-2 `evse_dc` block both in
    XSD shape (RationalNumber rather than PhysicalValue) and in which
    fields exist (min_charge_power, power_ramp_limit, BPT discharge).
    Defaults preserve the historical placeholder values from the
    simulator, so wire behaviour is unchanged when a personality is loaded
    from `default-secc.yaml`.
    """

    max_charge_power_w: float = 1000.0
    min_charge_power_w: float = 100.0
    max_charge_current_a: float = 100.0
    min_charge_current_a: float = 10.0
    max_voltage_v: float = 500.0
    min_voltage_v: float = 10.0
    power_ramp_limit_w_per_s: float = 10.0
    # ISO 15118-20 DC-BPT discharge envelope (BPTDCChargeParameterDiscoveryRes).
    bpt_max_discharge_power_w: float = 1000.0
    bpt_min_discharge_power_w: float = 100.0
    bpt_max_discharge_current_a: float = 100.0
    bpt_min_discharge_current_a: float = 10.0


class EVDCLimitsV20(_StrictBase):
    """EV-side DC envelope announced in ISO 15118-20 sessions.

    Splits into three groups: `ChargeParameterDiscoveryReq` (the static
    envelope), DC `PreCharge` + scheduled `ChargeLoop` targets, and the
    `dynamic_*` set used by `DynamicDCChargeLoopReqParams` (which the
    Tester simulator emits with smaller stub magnitudes — kept distinct
    so a personality can sweep them independently of CPD).

    All fields are EV-announced — the SECC is not expected to ever exceed
    them. Defaults match the simulator stubs in
    `SimEVController.get_charge_params_v20()` /
    `get_dynamic_dc_charge_loop_params()` so existing wire behaviour is
    preserved.
    """

    # DCChargeParameterDiscoveryReq (DC + DC-BPT).
    max_charge_power_w: float = 300000.0
    min_charge_power_w: float = 100.0
    max_charge_current_a: float = 300.0
    min_charge_current_a: float = 10.0
    max_voltage_v: float = 1000.0
    min_voltage_v: float = 10.0
    # PreCharge + scheduled DC ChargeLoop target voltage/current.
    target_voltage_v: float = 20000.0
    target_current_a: float = 200.0
    # Dynamic DC ChargeLoop stubs (kept distinct from CPD because the
    # simulator emits very different magnitudes here).
    dynamic_target_energy_request_wh: float = 200.0
    dynamic_max_energy_request_wh: float = 200.0
    dynamic_min_energy_request_wh: float = 20.0
    dynamic_max_charge_power_w: float = 4000.0
    dynamic_min_charge_power_w: float = 400.0
    dynamic_max_charge_current_a: float = 40.0
    dynamic_max_voltage_v: float = 400.0
    dynamic_min_voltage_v: float = 40.0
    # DC-BPT CPD discharge envelope.
    bpt_max_discharge_power_w: float = 11000.0
    bpt_min_discharge_power_w: float = 1000.0
    bpt_max_discharge_current_a: float = 11.0
    bpt_min_discharge_current_a: float = 0.0
    # BPT dynamic DC ChargeLoop discharge (separate from CPD because the
    # simulator emits 300 kW / 300 A here).
    bpt_dynamic_max_discharge_power_w: float = 300000.0
    bpt_dynamic_min_discharge_power_w: float = 300000.0
    bpt_dynamic_max_discharge_current_a: float = 300000.0


class EVSEACLimitsV20(_StrictBase):
    """SECC-side AC envelope advertised in ISO 15118-20 sessions.

    Distinct from the ISO-2 `evse_ac` block: ISO 15118-20 AC is
    multiphase (L1/L2/L3), declares nominal frequency, power asymmetry
    tolerance, and a power ramp limit. The per-phase values are modelled
    here as a single magnitude that's replicated to L1/L2/L3 on the wire
    — variant personalities that need asymmetric phases can be added
    later without breaking this contract.
    """

    max_charge_power_w: float = 30000.0
    min_charge_power_w: float = 100.0
    nominal_frequency_hz: float = 50.0
    max_power_asymmetry_w: float = 0.0
    power_ramp_limit_w_per_s: float = 100.0
    # ISO 15118-20 AC-BPT discharge envelope.
    bpt_max_discharge_power_w: float = 30000.0
    bpt_min_discharge_power_w: float = 100.0


class EVACLimitsV20(_StrictBase):
    """EV-side AC envelope announced in ISO 15118-20 sessions.

    Splits into the static CPD envelope, the scheduled charge loop's
    present-active-power stub, and the dynamic AC charge loop stubs.
    The dynamic-loop fields are separate from the CPD envelope because
    the simulator emits very different stub magnitudes there.
    """

    # ACChargeParameterDiscoveryReq (AC + AC-BPT).
    max_charge_power_w: float = 11000.0
    min_charge_power_w: float = 100.0
    # AC-BPT discharge envelope (CPD).
    bpt_max_discharge_power_w: float = 11000.0
    bpt_min_discharge_power_w: float = 1.0
    # ACChargeLoop simulator stubs (present-active-power in scheduled
    # mode; full set of dynamic-mode magnitudes).
    scheduled_present_active_power_w: float = 200000.0
    dynamic_max_charge_power_w: float = 300000.0
    dynamic_min_charge_power_w: float = 100.0
    dynamic_present_active_power_w: float = 200000.0
    dynamic_present_reactive_power_w: float = 20000.0


class ScheduleExchangeV20(_StrictBase):
    """EV-side ScheduleExchange announcement (ISO 15118-20 only).

    Covers the values the EV declares in `ScheduledScheduleExchangeReq`,
    `DynamicScheduleExchangeReq`, and the dynamic AC ChargeLoop (which
    re-states a departure-time stub). The two "modes" — scheduled and
    dynamic — carry different magnitudes in the simulator, so the model
    splits them rather than collapsing.
    """

    departure_time_s: int = 7200
    # ScheduledScheduleExchangeReq energy requests.
    scheduled_target_energy_request_wh: float = 10000.0
    scheduled_max_energy_request_wh: float = 20000.0
    scheduled_min_energy_request_wh: float = 0.05
    # DynamicScheduleExchangeReq SOC + energy + V2X-energy requests.
    dynamic_min_soc_percent: int = Field(default=30, ge=0, le=100)
    dynamic_target_soc_percent: int = Field(default=80, ge=0, le=100)
    dynamic_target_energy_request_wh: float = 40000.0
    dynamic_max_energy_request_wh: float = 60000.0
    dynamic_min_energy_request_wh: float = -20000.0
    dynamic_max_v2x_energy_request_wh: float = 5000.0
    dynamic_min_v2x_energy_request_wh: float = 0.0
    # Dynamic AC ChargeLoop carries its own departure-time stub distinct
    # from the SE-level one (simulator emits 2000 s here).
    ac_dynamic_loop_departure_time_s: int = 2000
    # EVPowerScheduleEntry + EVPriceRule offered alongside the schedule.
    power_schedule_duration_s: int = 3600
    power_schedule_power_w: float = -10000.0
    price_currency: str = "EUR"
    price_energy_fee: float = 0.0


class EVSEScheduleExchangeV20(_StrictBase):
    """SECC-side ScheduleExchange schedule envelope (ISO 15118-20).

    Mirrors the Slice 2 pattern (`EVSEDCLimits.sa_schedule_pmax_w` etc.) by
    surfacing the *envelope* of the EVSE's offered schedule — power,
    duration, available energy, tolerance — and the dynamic-mode SOC
    targets. The pricing / tax / overstay meta-structures the simulator
    embeds for protocol-interop completeness are deliberately left
    hardcoded; they don't shape "who the EVSE is" the way an envelope does.
    """

    schedule_duration_s: int = 3600
    charge_power_w: float = 10000.0
    available_energy_wh: float = 300000.0
    power_tolerance_w: float = 2000.0
    discharge_power_w: float = 10000.0
    # Dynamic SE response — the EVSE confirms the EV's departure + SOC
    # ask. Defaults track `ScheduleExchangeV20.dynamic_*` so the simulator
    # round-trips cleanly under stock personalities.
    dynamic_departure_time_s: int = 7200
    dynamic_min_soc_percent: int = Field(default=30, ge=0, le=100)
    dynamic_target_soc_percent: int = Field(default=80, ge=0, le=100)


class Power(_StrictBase):
    """Power envelopes for both roles.

    Each role only reads its own side — the EVCC consumes `ev_dc` / `ev_ac`
    / `ev_dc_v20` / `ev_ac_v20` / `schedule_exchange_v20`; the SECC
    consumes `evse_dc` / `evse_ac` / `evse_dc_v20` / `evse_ac_v20` /
    `evse_schedule_exchange_v20`. The `*_v20` sub-blocks are ISO
    15118-20-specific because the protocol's wire shape (RationalNumber,
    multiphase AC, BPT discharge, schedule exchange) does not collapse
    cleanly into the DIN/ISO-2 envelope.
    """

    evse_dc: EVSEDCLimits = Field(default_factory=EVSEDCLimits)
    ev_dc: EVDCLimits = Field(default_factory=EVDCLimits)
    evse_ac: EVSEACLimits = Field(default_factory=EVSEACLimits)
    ev_ac: EVACLimits = Field(default_factory=EVACLimits)
    # ISO 15118-20 sub-blocks (Slice 4 / issue #9).
    evse_dc_v20: EVSEDCLimitsV20 = Field(default_factory=EVSEDCLimitsV20)
    ev_dc_v20: EVDCLimitsV20 = Field(default_factory=EVDCLimitsV20)
    evse_ac_v20: EVSEACLimitsV20 = Field(default_factory=EVSEACLimitsV20)
    ev_ac_v20: EVACLimitsV20 = Field(default_factory=EVACLimitsV20)
    schedule_exchange_v20: ScheduleExchangeV20 = Field(
        default_factory=ScheduleExchangeV20
    )
    evse_schedule_exchange_v20: EVSEScheduleExchangeV20 = Field(
        default_factory=EVSEScheduleExchangeV20
    )


class ChargeProfile(_StrictBase):
    """Charge-loop pacing for the simulated EV."""

    cycle: int = 10
    delay_seconds: int = 0


class Certificates(_StrictBase):
    """Certificate / PKI material location and limits."""

    pki_path: str = "app/shared/pki/"
    max_contract_certs: int = 3


class Meter(_StrictBase):
    """Meter identity advertised by the SECC.

    `meter_id` rides every MeterInfo block emitted by the SECC (ISO 15118-2
    MeteringReceipt, ChargingStatus, CurrentDemand, etc.). `starting_reading_wh`
    is the seed value the simulator advertises before runtime accumulation —
    the per-message reading itself is runtime-derived and not a personality
    field.
    """

    meter_id: str = "Switch-Meter-123"
    starting_reading_wh: int = 12345


# ---------------------------------------------------------------------------
# Role personalities
# ---------------------------------------------------------------------------


class _PersonalityBase(_StrictBase):
    """Shared shape for EVCC + SECC personalities.

    Both roles use the same section names — the difference between them is
    *which* fields each role consumes, not which sections exist. Keeping the
    shape symmetrical means a `default-evcc.yaml` and `default-secc.yaml`
    look familiar side-by-side, and the drift test can iterate sections
    uniformly.
    """

    identity: Identity = Field(default_factory=Identity)
    network: Network = Field(default_factory=Network)
    slac: SLAC = Field(default_factory=SLAC)
    tls: TLS = Field(default_factory=TLS)
    capabilities: Capabilities = Field(default_factory=Capabilities)
    power: Power = Field(default_factory=Power)
    charge_profile: ChargeProfile = Field(default_factory=ChargeProfile)
    certificates: Certificates = Field(default_factory=Certificates)
    meter: Meter = Field(default_factory=Meter)


class EVCCPersonality(_PersonalityBase):
    role: Literal["evcc"] = "evcc"

    # Per-role network defaults. The base class uses "eth0" so a personality
    # authored without a network section still validates; these overrides
    # mirror the historical .env values, which is what `default-evcc.yaml`
    # ships.
    network: Network = Field(default_factory=lambda: Network(interface="acccs_evcc"))


class SECCPersonality(_PersonalityBase):
    role: Literal["secc"] = "secc"

    network: Network = Field(default_factory=lambda: Network(interface="acccs_secc"))


# Discriminated union for callers that don't know the role at type-check
# time. Used by the loader's auto-detect helper.
Personality = EVCCPersonality | SECCPersonality


# The TLS posture for the cert-free "smoke" personalities. It differs from
# the stock default `TLS()` only in the three encryption toggles — every
# other knob (including `sdp_retry_cycles`) keeps its default.
NO_TLS = TLS(enable_tls_1_3=False, use_tls=False, enforce_tls=False)

# ISO 15118-20 mandates TLS 1.3 (ADR-0001), and the loader hard-refuses to
# start a session that pairs a -20 protocol with TLS 1.3 off (see
# `app/secc/secc_settings.py` / `app/evcc/states/sap_states.py`). So the
# cert-free smoke variants drop the two -20 protocols from the stock list and
# keep only the protocols that can actually negotiate without TLS.
NO_TLS_SUPPORTED_PROTOCOLS = ["DIN_SPEC_70121", "ISO_15118_2"]


def no_tls_personality(model_cls: Type["_PersonalityBase"]) -> "_PersonalityBase":
    """Build a cert-free smoke personality for the given role class.

    The result is the stock default persona minus encryption: identical to
    `model_cls()` except for two sections —

    - `tls:` is replaced with `NO_TLS` (encryption off), and
    - `capabilities.supported_protocols` drops `ISO_15118_20_*`, because those
      mandate TLS 1.3 and the loader refuses to start without it.

    Used to generate `default-no-tls-{evcc,secc}.yaml` (issue #23) so a fresh
    clone can run the virtual demo without first generating PKI certs. The
    cert-enabled stock default remains the realistic-testing path.
    """
    caps = model_cls().capabilities.model_copy(
        update={"supported_protocols": list(NO_TLS_SUPPORTED_PROTOCOLS)}
    )
    return model_cls(tls=NO_TLS, capabilities=caps)


# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------


class LogRuntime(_StrictBase):
    console_level: str = "INFO"
    file_level: str = "DEBUG"
    message_log_json: bool = True
    message_log_exi: bool = False


class NmapRuntime(_StrictBase):
    enabled: bool = False
    args: str = "-sS -sU -6"
    ports: str = "-"


class Runtime(_StrictBase):
    """Operational knobs — CLI-overridable.

    Personality fields are *never* CLI-overridable per ADR-0001; that
    promise is enforced by the CLI builder (it only constructs flags for
    runtime fields).
    """

    virtual: bool = False
    log: LogRuntime = Field(default_factory=LogRuntime)
    nmap: NmapRuntime = Field(default_factory=NmapRuntime)
    # Source port for the EVCC/SECC TCP listener. `None` means "random in
    # the dynamic range" (EVCC) or 25565 (SECC); both run scripts retain
    # their historical defaults when this is unset.
    source_port: Optional[int] = None
    # SECC-only knob: enable the modified-cordset behaviour exposed by the
    # historical `--modified-cordset` CLI flag.
    modified_cordset: bool = False
