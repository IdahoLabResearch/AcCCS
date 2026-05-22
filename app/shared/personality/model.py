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

from typing import List, Literal, Optional

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


class Power(_StrictBase):
    """Power-limit advertisements.

    Empty in Slice 1 — the limits are currently hardcoded inside
    `app/secc/controller/simulator.get_evse_context()`. ADR-0001 calls out
    that surfacing these "is the bulk of the work and is sliced by protocol
    (DIN → ISO-15118-2 → ISO-15118-20)" in subsequent slices.
    """


class ChargeProfile(_StrictBase):
    """Charge-loop pacing for the simulated EV."""

    cycle: int = 10
    delay_seconds: int = 0


class Certificates(_StrictBase):
    """Certificate / PKI material location and limits."""

    pki_path: str = "app/shared/pki/"
    max_contract_certs: int = 3


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
