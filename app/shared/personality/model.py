"""Pydantic models for AcCCS personality + runtime configuration.

Per ADR-0001 a personality describes *who* the emulated device is — IDs,
supported protocols, power/charging profile, TLS posture, SLAC timings, cert
paths. Runtime knobs are *per-invocation operator* concerns (logging level,
NMAP toggles, virtual mode).

Per ADR-0006 a personality has two parts: a `message_field_tree` (everything
emitted on the wire, keyed by protocol + message + field path) and a `residual`
section (everything with no wire representation — TLS/SLAC/certificates/network/
charge-pacing/charge-ramp seeds/behavior). The dividing rule is mechanical: on
the wire -> tree; not on the wire -> residual; never duplicated. The pre-tree
concern-first wire sections (`identity` and `power`) are retired now that every
protocol is tree-backed (#102) — their genuinely residual seeds (the EV DC
target/remaining-time ramp values) moved into `residual.charge_ramp`. Two
top-level sections remain: `capabilities` (the cross-cutting negotiation inputs,
plus the still-pre-tree `energy_transfer_mode`) and `meter` (awaiting its own
MeterInfo tree migration).

Strict validation: unknown keys at any level are a hard error. That is what
makes a personality a contract rather than a suggestion.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Type

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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


class ChargeRamp(_StrictBase):
    """EV-side DC charge-ramp start seeds (EVCC, residual section).

    The initial PreCharge / CurrentDemand target voltage & current the EV
    requests, plus the EV-supplied remaining-time estimates. These have **no
    static wire representation**: the emitted target/present voltage & current
    ramp during the session and are allowlisted runtime-produced fields
    (ADR-0006 #83), so per the mechanical dividing rule (not on the wire ->
    residual) they belong here, not in the [[message field tree]]. They seed the
    ramp before the runtime charge controller (or a [[live-override]]) takes
    over.

    Formerly `power.ev_dc.{target_voltage_v,target_current_a,remaining_time_*}`
    on the retired concern-first `Power` model; relocated to the residual
    section when the pre-tree structured wire sections were deleted (#102). The
    ``target_current_a`` default stays below the IEC 61851-23 CC.5.2 PreCharge
    inrush limit (< 2 A).
    """

    target_voltage_v: float = 500.0
    target_current_a: float = 1.0
    # DIN / ISO-2 CurrentDemandReq optional EV-supplied remaining-time estimates.
    remaining_time_to_full_soc_s: int = 100
    remaining_time_to_bulk_soc_s: int = 80


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


class Behavior(_StrictBase):
    """Behavioral path-selecting flags with no wire representation.

    These select which *code path* the emulator takes; they are never emitted
    as a protocol field, so per ADR-0006's dividing rule they belong in the
    [[residual]] section rather than the [[message field tree]].

    `use_cpo_backend` moved here out of `capabilities` (where it sat alongside
    genuinely-advertised capabilities) once the tree/residual split made the
    "not on the wire -> residual" rule mechanical.
    """

    use_cpo_backend: bool = False


class Residual(_StrictBase):
    """The residual section of a personality (ADR-0006).

    Everything that configures the device but has *no wire representation* —
    TLS posture, SLAC layer-2 timings, certificate file paths, the network
    interface, charge-loop pacing, the EV's DC charge-ramp start seeds, and
    behavioral path-selecting flags. The dividing rule is mechanical: on the
    wire -> [[message field tree]]; not on the wire -> here. A value is
    therefore never duplicated across the two.

    The pre-tree structured wire sections (`identity`, `power`, and the
    wire-bits of `meter`) that once lived at the personality top level are
    retired (#102): every emitted field is tree-sourced, and the genuinely
    residual runtime seeds they carried (the EV DC target/remaining-time
    values) moved here as `charge_ramp`. `capabilities` and `meter` stay at the
    top level — the former holds the cross-cutting negotiation inputs (plus the
    still-pre-tree `energy_transfer_mode`), the latter awaits its own
    MeterInfo tree migration.
    """

    network: Network = Field(default_factory=Network)
    slac: SLAC = Field(default_factory=SLAC)
    tls: TLS = Field(default_factory=TLS)
    certificates: Certificates = Field(default_factory=Certificates)
    charge_profile: ChargeProfile = Field(default_factory=ChargeProfile)
    # EV DC charge-ramp start seeds (EVCC): initial PreCharge/CurrentDemand
    # target V/A + remaining-time estimates. No static wire form (they ramp),
    # so residual — relocated from the retired `power.ev_dc` block (#102).
    charge_ramp: ChargeRamp = Field(default_factory=ChargeRamp)
    behavior: Behavior = Field(default_factory=Behavior)


class _EVCCResidual(Residual):
    """EVCC residual with the per-role network interface default.

    The default lives at the *field* level (not on the personality) so it
    survives a personality that specifies some residual sub-keys but omits
    `network` — a personality-level default_factory would only fire when the
    whole `residual` section is absent, silently reverting to the generic
    ``eth0`` the moment a file set, say, only `residual.tls`.
    """

    network: Network = Field(default_factory=lambda: Network(interface="acccs_evcc"))


class _SECCResidual(Residual):
    """SECC residual with the per-role network interface default."""

    network: Network = Field(default_factory=lambda: Network(interface="acccs_secc"))


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

    capabilities: Capabilities = Field(default_factory=Capabilities)
    meter: Meter = Field(default_factory=Meter)
    # Residual section (ADR-0006): all non-wire config — TLS/SLAC/certs/
    # network/charge-pacing/charge-ramp seeds/behavior. `network` gets a
    # per-role interface default via the EVCC/SECC subclasses below.
    residual: Residual = Field(default_factory=Residual)

    # The [[message field tree]] (ADR-0006): per-message, per-field emitted
    # wire values, keyed by message name and nested field path mirroring the
    # DIN message models down to each leaf. Validation is path-strict (a bad
    # path is a hard error) but value-raw (leaf values are not range/enum
    # checked — illegal-but-encodable is the point). It sits outside the
    # concern-first sections above: those describe the residual, non-tree
    # config, while this is the wire-value model. Empty by default, so a leaf
    # set nowhere falls back to whatever the message builder computes.
    message_field_tree: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("message_field_tree")
    @classmethod
    def _validate_message_field_tree(cls, value: Any) -> Dict[str, Any]:
        # Lazy import: the tree machinery reaches into the message models,
        # which must not be pulled in at personality-model import time.
        from app.shared.personality.message_field_tree import (
            validate_message_field_tree,
        )

        return validate_message_field_tree(value)

    @model_validator(mode="after")
    def _check_message_field_tree_completeness(self) -> "_PersonalityBase":
        """Fail at load on a missing mandatory tree-sourced wire field (#83).

        Runs after the baseline + device deep-merge (the loader merges, then
        validates), so it sees the *merged* tree. Per-protocol (ADR-0006
        protocol-keyed amendment): for every protocol the personality both
        supports and that is *tree-backed* (DIN today), every mandatory wire
        field of a message the role emits and the protocol's subtree carries must
        resolve in the tree or be on the ADR-0006 #83 optional-field allowlist;
        otherwise this raises, naming the protocol, message, and field path.

        A supported protocol that is not yet tree-backed (ISO-2 / ISO-20 this
        slice) is skipped entirely — it still sources its wire values from the
        builders' pre-tree path, so it carries no subtree (or a partial
        single-field red-team probe, which the per-message-present rule tolerates
        because completeness only demands leaves for messages the subtree names).
        This lets each protocol slice become tree-backed independently. Lazy
        import for the same reason as the field validator above.
        """
        from app.shared.personality.completeness import (
            check_message_field_tree_completeness,
        )

        check_message_field_tree_completeness(
            self.message_field_tree,
            self.role,
            self.capabilities.supported_protocols,
        )
        return self


class EVCCPersonality(_PersonalityBase):
    role: Literal["evcc"] = "evcc"

    # Per-role residual (with the acccs_evcc network default) — see
    # `_EVCCResidual` for why the interface default lives on the residual field
    # rather than a personality-level default_factory.
    residual: _EVCCResidual = Field(default_factory=_EVCCResidual)


class SECCPersonality(_PersonalityBase):
    role: Literal["secc"] = "secc"

    residual: _SECCResidual = Field(default_factory=_SECCResidual)

    @model_validator(mode="after")
    def _validate_advertised_energy_transfer_mode(self) -> "SECCPersonality":
        """Fail early on a mistyped DIN EnergyTransferType leaf (#76).

        The DIN ``ServiceDiscoveryRes -> ChargeService -> EnergyTransferType``
        leaf is single-sourced from the tree (ADR-0006) and encodes as a
        *restricted EXI enumeration*, so the codec accepts only the
        :class:`EnergyTransferModeEnum` wire values. For this field ADR-0006's
        value-raw seam is vacuous: every codec-serializable value already
        coerces to a real enum member, and a value that fails coercion — e.g.
        the enum *name* ``DC_EXTENDED`` instead of the wire *value*
        ``DC_extended`` — can never reach the wire. Rather than let such a leaf
        detonate later as an opaque ``ValidationError`` (plain ``ChargeService``
        constructor) or ``EXIEncodingError`` (codec) mid-session at
        ServiceDiscovery, reject it here with a message that names the fix.
        """
        from app.shared.personality.message_field_tree import (
            UNSET,
            resolve_tree_leaf,
        )

        leaf = resolve_tree_leaf(
            self.message_field_tree,
            "DIN_SPEC_70121",
            "ServiceDiscoveryRes",
            ("charge_service", "energy_transfer_type"),
        )
        if leaf is UNSET:
            return self
        try:
            EnergyTransferModeEnum(leaf)
        except (ValueError, TypeError) as exc:
            valid = ", ".join(repr(mode.value) for mode in EnergyTransferModeEnum)
            raise ValueError(
                f"ServiceDiscoveryRes -> ChargeService -> EnergyTransferType "
                f"{leaf!r} is not a valid energy transfer mode and cannot be "
                f"advertised on the wire. Use a wire value (e.g. 'DC_extended', "
                f"not the enum name 'DC_EXTENDED'); one of: {valid}."
            ) from exc
        return self


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

    - `residual.tls` is replaced with `NO_TLS` (encryption off), and
    - `capabilities.supported_protocols` drops `ISO_15118_20_*`, because those
      mandate TLS 1.3 and the loader refuses to start without it.

    Used to generate `default-no-tls-{evcc,secc}.yaml` (issue #23) so a fresh
    clone can run the virtual demo without first generating PKI certs. The
    cert-enabled stock default remains the realistic-testing path.
    """
    base = model_cls()
    caps = base.capabilities.model_copy(
        update={"supported_protocols": list(NO_TLS_SUPPORTED_PROTOCOLS)}
    )
    residual = base.residual.model_copy(update={"tls": NO_TLS})
    return model_cls(capabilities=caps, residual=residual)


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


class StallRuntime(_StrictBase):
    """Operator [[stall]] arming, per ADR-0004.

    Stall arming lives in `runtime.yaml` (not the personality): it is a
    per-invocation, CLI-overridable operator decision, and the personality is
    immutable. `charge_loop` is the EVCC's forceful hold over the ISO 15118-2
    DC CurrentDemand loop (issue #28); `authorization` is the SECC's forceful
    hold over the ISO 15118-2 Authorization gate (issue #30). Each is consumed
    only by the role that owns that gate.
    """

    charge_loop: bool = False
    authorization: bool = False


class RearmRuntime(_StrictBase):
    """Auto-rearm mode, per ADR-0005.

    `auto` opts into [[auto-rearm]]: instead of returning to [[idle]] and
    waiting for an operator advance after a [[session cycle]] ends, the side
    re-arms itself the instant the cycle ends and runs the next one. With both
    sides in auto-rearm the emulators cycle sessions continuously until quit.
    Like the stall flags it is a per-invocation, CLI-overridable operator
    decision (`--auto-rearm`, live `r` toggle), off by default, and never a
    [[personality]] field.
    """

    auto: bool = False


class PollRuntime(_StrictBase):
    """Pacing for the EVCC's ONGOING poll loops (issue #88).

    An SECC that answers `EVSEProcessing.ONGOING` — as a real charger does at
    ContractAuthentication while it waits on external payment authorization —
    keeps the EVCC re-sending the same request. Unpaced, that re-send is a hot
    spin (~190 req/s observed in the field); `ongoing_interval_seconds` is the
    beat the EVCC waits between re-sends instead. It never delays the FINISHED
    transition, which is taken the moment the SECC reports it.

    A per-invocation operational decision, not device identity, so per ADR-0001
    it is a runtime knob (`--poll-interval`) and never a [[personality]] field.
    Only the EVCC polls, so only the EVCC reads it. `0` disables pacing and
    restores the un-paced re-send, which stays available for red-team probing.
    """

    ongoing_interval_seconds: float = Field(default=1.0, ge=0)


class ConsoleRuntime(_StrictBase):
    """Operator console activation mode, per ADR-0004.

    - ``auto`` (default): active when stdout is a TTY, silently headless
      otherwise — keeps the conformance E2E / CI / replay paths untouched.
    - ``on`` (CLI ``--console``): request the console; warns and stays
      headless if there is no TTY.
    - ``off`` (CLI ``--no-console``): never active.
    """

    mode: Literal["auto", "on", "off"] = "auto"

    @field_validator("mode", mode="before")
    @classmethod
    def _coerce_yaml_bools(cls, value):
        """Accept YAML's bareword ``on``/``off`` (which parse as bools).

        `console.mode: on` in a runtime.yaml is read by PyYAML as the boolean
        ``True`` (YAML 1.1), so without this a perfectly natural config would
        fail strict validation. Map the booleans onto the string literals.
        """
        if value is True:
            return "on"
        if value is False:
            return "off"
        return value


class Runtime(_StrictBase):
    """Operational knobs — CLI-overridable.

    Personality fields are *never* CLI-overridable per ADR-0001; that
    promise is enforced by the CLI builder (it only constructs flags for
    runtime fields).
    """

    virtual: bool = False
    log: LogRuntime = Field(default_factory=LogRuntime)
    nmap: NmapRuntime = Field(default_factory=NmapRuntime)
    # Operator console + stall arming (ADR-0004). Both are per-invocation
    # operator intent, CLI-overridable, and deliberately not personality fields.
    stall: StallRuntime = Field(default_factory=StallRuntime)
    console: ConsoleRuntime = Field(default_factory=ConsoleRuntime)
    # Auto-rearm (ADR-0005): opt-in continuous session cycling. Per-invocation
    # operator intent, CLI-overridable (--auto-rearm), off by default, and
    # deliberately not a personality field.
    rearm: RearmRuntime = Field(default_factory=RearmRuntime)
    # EVCC ONGOING-poll pacing (issue #88): how long the EVCC waits before
    # re-sending a request the SECC answered with EVSEProcessing.ONGOING.
    poll: PollRuntime = Field(default_factory=PollRuntime)
    # Source port for the EVCC/SECC TCP listener. `None` means "random in
    # the dynamic range" (EVCC) or 25565 (SECC); both run scripts retain
    # their historical defaults when this is unset.
    source_port: Optional[int] = None
    # SECC-only knob: enable the modified-cordset behaviour exposed by the
    # historical `--modified-cordset` CLI flag.
    modified_cordset: bool = False
