"""Load-time completeness check for the [[message field tree]] (ADR-0006 #83).

Once a personality is mandatory to run, the loader can guarantee a wire value
exists for every field the emulated device emits. This module enforces that
guarantee at load time: for every **mandatory** wire field (a Pydantic-required
leaf — ``Field(...)``, no default) of a DIN message the personality is
responsible for, if the merged (baseline + device) tree resolves to **no value**
there, that is a **load-time error naming the message and field path** — unless
the field is on the :data:`OPTIONAL_FIELD_ALLOWLIST`, the standalone list of
fields the emulator produces on its own at runtime.

Scope (ADR-0006 #83 + the protocol-keyed amendment):

* **Per supported, tree-backed protocol.** The gate is now per-protocol
  (:func:`is_tree_backed`): a supported protocol whose slice has landed (its
  values actually flow to the wire from the tree — DIN, ISO-2, ISO-20 DC, and
  ISO-20 AC SECC today) must carry a **present and complete** subtree; a
  supported protocol still on the builders' pre-tree structured path (the ISO-20
  AC EVCC side) needs *nothing* in the tree and is exempt. Each protocol
  slice can therefore land independently — no
  flag-day cutover — while the end state (every supported protocol tree-backed
  and checked) is the strong "a personality cannot claim a protocol it does not
  fully back" guarantee. The caller passes the personality's
  ``supported_protocols``; only the supported *and* tree-backed ones are walked.
  This replaces the old DIN-exclusive scoping: a multi-protocol personality that
  advertises DIN is now checked for DIN too (its tree is typically empty, so the
  per-message-present rule below makes the walk a no-op there).
* **Per protocol's own message set + allowlist.** DIN's message set comes from
  :func:`app.shared.messages.din_spec.body.get_msg_type` via the tree machinery;
  ISO-15118-2 / -20 register their own message sets and allowlist entries as
  those slices become tree-backed.
* **Per-message-present.** Within a tree-backed protocol subtree a required leaf
  is only demanded for a message the subtree *contains an entry for* — the same
  "validate only what the tree actually specifies" stance the #76
  energy-transfer-mode check takes (an absent tree leaf is UNSET → skipped
  there; an absent *message* is skipped here). A DIN personality ``extends`` a
  baseline that spells out every DIN message, so its merged subtree carries
  every message and gets full coverage.

The required-leaf walk and the "resolves to a value" query reuse the tree
machinery in :mod:`app.shared.personality.message_field_tree` rather than a
hand-maintained parallel schema.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Set, Tuple, Type

from pydantic import BaseModel

from app.shared.personality.message_field_tree import (
    UNSET,
    _list_element_model,
    _message_class,
    _model_in_annotation,
    resolve_tree_leaf,
)

# A leaf path is the tuple of *Python* field names from the message root to the
# leaf (e.g. ``("dc_evse_status", "evse_status_code")``), matching the argument
# `resolve_tree_leaf` walks.
LeafPath = Tuple[str, ...]


class MessageFieldTreeIncompleteError(ValueError):
    """A mandatory tree-sourced wire field is missing from the merged tree.

    Subclasses :class:`ValueError` so it surfaces through Pydantic validation at
    personality-load time exactly like every other strict-config failure.
    """


# The tree-backed protocol strings. DIN's slice (#73) landed first; the ISO-2
# SECC slice (#96) makes ISO-2 tree-backed too, so a personality that advertises
# ISO_15118_2 must carry a complete ISO-2 subtree (when it carries one at all —
# the per-message-present rule keeps the empty-subtree multi-protocol defaults a
# no-op). ISO-20 joins this set when its slice migrates its wire values.
_DIN_PROTOCOL = "DIN_SPEC_70121"
_ISO2_PROTOCOL = "ISO_15118_2"
_ISO20_DC_PROTOCOL = "ISO_15118_20_DC"
_ISO20_AC_PROTOCOL = "ISO_15118_20_AC"

# The protocols whose emitted wire values actually come from the tree today. A
# supported protocol in this set must carry a complete subtree; a supported
# protocol outside it is still driven by the builders' pre-tree path and needs
# nothing in the tree (ADR-0006 protocol-keyed amendment). ISO-20 DC joins for
# the SECC role as of #98 and the EVCC role as of #99; ISO-20 AC joins for the
# SECC role as of #100 (the ISO-20 AC EVCC side adds its own entry as that slice
# lands).
_TREE_BACKED_PROTOCOLS: frozenset = frozenset(
    {_DIN_PROTOCOL, _ISO2_PROTOCOL, _ISO20_DC_PROTOCOL, _ISO20_AC_PROTOCOL}
)


# The ISO-20 message models mirror the *full* message, `header` envelope
# included (SessionID, timestamp, and — for signed messages — the signature),
# unlike the DIN / ISO-2 body models whose header rides the separate V2G
# envelope and never reaches ``get_msg_type``. Per ADR-0006 (#83 and the
# protocol-keyed amendment) the header/envelope stays **compute-only /
# deferred** — the tree is message-*body* only — so a required header leaf is
# never demanded of the tree. This exclusion is a no-op for DIN / ISO-2 (their
# body models carry no ``header`` field) and only bites for ISO-20.
_ENVELOPE_ROOT_FIELDS: frozenset = frozenset({"header"})


def is_tree_backed(protocol: str) -> bool:
    """True when *protocol*'s emitted wire values are sourced from the tree.

    The per-protocol replacement for the old ``is_din_exclusive`` all-or-nothing
    scoping (ADR-0006 protocol-keyed amendment). A tree-backed *and* supported
    protocol must carry a present, complete subtree (the completeness gate runs
    for it); a supported protocol that is not yet tree-backed drives its wire
    values through the builders' pre-tree path and is exempt from the gate until
    its slice lands. Tree-backed today: DIN (both roles), ISO-2 (both roles),
    ISO-20 DC (both roles: SECC #98, EVCC #99), and ISO-20 AC (SECC role, #100).
    See :data:`_TREE_BACKED_PROTOCOLS`.
    """
    return protocol in _TREE_BACKED_PROTOCOLS


# ---------------------------------------------------------------------------
# The messages each role is responsible for emitting (DIN, this slice)
# ---------------------------------------------------------------------------

# The SECC emits every ``*Res``; the EVCC emits every ``*Req``. The completeness
# check only walks messages the role emits *and* that the tree carries.
SECC_MESSAGES: Tuple[str, ...] = (
    "SessionSetupRes",
    "ServiceDiscoveryRes",
    "ServicePaymentSelectionRes",
    "ContractAuthenticationRes",
    "ChargeParameterDiscoveryRes",
    "CableCheckRes",
    "PreChargeRes",
    "PowerDeliveryRes",
    "CurrentDemandRes",
    "WeldingDetectionRes",
    "SessionStopRes",
)
EVCC_MESSAGES: Tuple[str, ...] = (
    "SessionSetupReq",
    "ServiceDiscoveryReq",
    "ServicePaymentSelectionReq",
    "ContractAuthenticationReq",
    "ChargeParameterDiscoveryReq",
    "CableCheckReq",
    "PreChargeReq",
    "PowerDeliveryReq",
    "CurrentDemandReq",
    "WeldingDetectionReq",
    "SessionStopReq",
)

# The ISO-15118-2 SECC-emitted message set (issue #96). Covers the AC and DC
# subset the state machine actually emits; the per-message-present rule means a
# DC-EIM baseline that carries no AC / PnC message entries simply skips them.
ISO2_SECC_MESSAGES: Tuple[str, ...] = (
    "SessionSetupRes",
    "ServiceDiscoveryRes",
    "ServiceDetailRes",
    "PaymentServiceSelectionRes",
    "CertificateInstallationRes",
    "PaymentDetailsRes",
    "AuthorizationRes",
    "ChargeParameterDiscoveryRes",
    "CableCheckRes",
    "PreChargeRes",
    "PowerDeliveryRes",
    "CurrentDemandRes",
    "ChargingStatusRes",
    "MeteringReceiptRes",
    "WeldingDetectionRes",
    "SessionStopRes",
)

# The ISO-15118-2 EVCC-emitted message set (issue #97). The vehicle-side mirror
# of ISO2_SECC_MESSAGES: every ``*Req`` the EVCC state machine emits. The
# per-message-present rule means the shipped DC-EIM Mach-E baseline (which carries
# only the DC messages that bear tree leaves) simply skips the AC / PnC entries.
ISO2_EVCC_MESSAGES: Tuple[str, ...] = (
    "SessionSetupReq",
    "ServiceDiscoveryReq",
    "ServiceDetailReq",
    "PaymentServiceSelectionReq",
    "CertificateInstallationReq",
    "PaymentDetailsReq",
    "AuthorizationReq",
    "ChargeParameterDiscoveryReq",
    "CableCheckReq",
    "PreChargeReq",
    "PowerDeliveryReq",
    "CurrentDemandReq",
    "ChargingStatusReq",
    "MeteringReceiptReq",
    "WeldingDetectionReq",
    "SessionStopReq",
)


# The ISO-15118-20 DC SECC-emitted message set (issue #98). Every common ``*Res``
# (shared with the ISO-20 AC session) plus the DC-specific ``*Res`` the DC state
# machine emits; the per-message-present rule means an entry the merged tree does
# not carry is skipped. BPT is a *mode* whose discharge params ride inside these
# DC messages (``BPTDCChargeParameterDiscoveryResParams`` …), not its own message,
# so there is no separate BPT message here.
ISO20_DC_SECC_MESSAGES: Tuple[str, ...] = (
    # --- common (both AC and DC ISO-20 sessions) ---
    "SessionSetupRes",
    "AuthorizationSetupRes",
    "AuthorizationRes",
    "ServiceDiscoveryRes",
    "ServiceDetailRes",
    "ServiceSelectionRes",
    "ScheduleExchangeRes",
    "PowerDeliveryRes",
    "SessionStopRes",
    # --- DC-specific ---
    "DCChargeParameterDiscoveryRes",
    "DCCableCheckRes",
    "DCPreChargeRes",
    "DCChargeLoopRes",
    "DCWeldingDetectionRes",
)


# The ISO-15118-20 DC EVCC-emitted message set (issue #99). The vehicle-side
# mirror of ISO20_DC_SECC_MESSAGES: every common ``*Req`` (shared with the ISO-20
# AC session) plus the DC-specific ``*Req`` the DC state machine emits. The
# per-message-present rule means an entry the merged tree does not carry is
# skipped — the shipped DC-BPT baseline carries only the messages that bear a
# tree leaf (``DCChargeParameterDiscoveryReq``), so the PnC-only
# ``CertificateInstallationReq`` and the all-runtime messages simply skip. BPT is
# a *mode* whose discharge params ride inside these DC messages
# (``BPTDCChargeParameterDiscoveryReqParams`` …), not its own message, so there
# is no separate BPT message here.
ISO20_DC_EVCC_MESSAGES: Tuple[str, ...] = (
    # --- common (both AC and DC ISO-20 sessions) ---
    "SessionSetupReq",
    "AuthorizationSetupReq",
    "AuthorizationReq",
    "ServiceDiscoveryReq",
    "ServiceDetailReq",
    "ServiceSelectionReq",
    "ScheduleExchangeReq",
    "PowerDeliveryReq",
    "CertificateInstallationReq",
    "SessionStopReq",
    # --- DC-specific ---
    "DCChargeParameterDiscoveryReq",
    "DCCableCheckReq",
    "DCPreChargeReq",
    "DCChargeLoopReq",
    "DCWeldingDetectionReq",
)


# The ISO-15118-20 AC SECC-emitted message set (issue #100). The AC sibling of
# ISO20_DC_SECC_MESSAGES: the same nine common ``*Res`` (shared with the ISO-20
# DC session and single-sourced via the same YAML anchor the baseline declares
# once) plus the AC-specific ``*Res`` the AC state machine emits. There is no
# DC-style CableCheck / PreCharge / WeldingDetection on the AC path. AC-BPT is a
# *mode* whose discharge params ride inside these AC messages
# (``BPTACChargeParameterDiscoveryResParams`` …), not its own message, so there
# is no separate BPT message here — exactly as on the DC side.
ISO20_AC_SECC_MESSAGES: Tuple[str, ...] = (
    # --- common (both AC and DC ISO-20 sessions) ---
    "SessionSetupRes",
    "AuthorizationSetupRes",
    "AuthorizationRes",
    "ServiceDiscoveryRes",
    "ServiceDetailRes",
    "ServiceSelectionRes",
    "ScheduleExchangeRes",
    "PowerDeliveryRes",
    "SessionStopRes",
    # --- AC-specific ---
    "ACChargeParameterDiscoveryRes",
    "ACChargeLoopRes",
)


# ---------------------------------------------------------------------------
# The optional-field allowlist (ADR-0006 #83)
# ---------------------------------------------------------------------------
#
# Required leaves the emulator produces on its own at runtime, so they may be
# omitted from the tree. Leaf-path granular (a `DC_EVStatus` is mixed — EVReady /
# EVErrorCode are here, but the adjacent EVRESSSOC is config-only), per message,
# role-aware. The list is **standalone**, not derived from any baseline: deriving
# "optional" from what a baseline happens to set would let a baseline that drops a
# required leaf silently reclassify it as optional, masking the very regression
# this check exists to catch. Each entry is guarded by a test asserting the
# builder still populates it from an empty tree (so the list cannot claim a
# fallback that does not exist).

# ResponseCode rides every SECC ``*Res`` (the ``Response`` base class) and is set
# by the SECC state machine per message — a small base set, applied to every
# emitted SECC message.
_SECC_BASE_ALLOWLIST: Set[LeafPath] = {
    ("response_code",),
}

_SECC_MESSAGE_ALLOWLIST: Dict[str, Set[LeafPath]] = {
    # EVSEProcessing progresses ONGOING -> FINISHED at runtime.
    "ChargeParameterDiscoveryRes": {("evse_processing",)},
    "CableCheckRes": {("evse_processing",)},
    # Present voltage/current are runtime measurements.
    "PreChargeRes": {
        ("evse_present_voltage", "value"),
        ("evse_present_voltage", "multiplier"),
    },
    "CurrentDemandRes": {
        ("evse_present_voltage", "value"),
        ("evse_present_voltage", "multiplier"),
        ("evse_present_current", "value"),
        ("evse_present_current", "multiplier"),
        ("evse_current_limit_achieved",),
        ("evse_voltage_limit_achieved",),
        ("evse_power_limit_achieved",),
    },
    "WeldingDetectionRes": {
        ("evse_present_voltage", "value"),
        ("evse_present_voltage", "multiplier"),
    },
}

_EVCC_MESSAGE_ALLOWLIST: Dict[str, Set[LeafPath]] = {
    # EVCCID is the NIC MAC, resolved at runtime.
    "SessionSetupReq": {("evcc_id",)},
    # The SelectedServiceList must reference a service the SECC advertised, so
    # the EVCC echoes the ServiceID from the received ServiceDiscoveryRes rather
    # than emitting a static wire value — a real charger may advertise any
    # xs:unsignedShort (the Tellus Power uses 4660), and pinning it would send an
    # unadvertised ServiceID and draw FAILED_ServiceSelectionInvalid. Runtime-
    # produced (an echo), so it is omitted from the tree.
    "ServicePaymentSelectionReq": {("selected_service_list", "selected_service")},
    # EVRequestedEnergyTransferType is single-sourced from the pre-tree
    # `capabilities.energy_transfer_mode` section this slice (its tree migration
    # is deferred), so the builder always produces it without the tree (#83
    # finding 2).
    "ChargeParameterDiscoveryReq": {("requested_energy_mode",)},
    # ReadyToChargeState is computed True/False per charge phase, like
    # ChargingComplete (#83 finding 3).
    "PowerDeliveryReq": {("ready_to_charge",)},
    # DC_EVStatus is mixed: EVReady / EVErrorCode are runtime-produced, the
    # adjacent EVRESSSOC is config-only. The EV's target voltage/current ramp
    # during the session.
    "CableCheckReq": {
        ("dc_ev_status", "ev_ready"),
        ("dc_ev_status", "ev_error_code"),
    },
    "PreChargeReq": {
        ("dc_ev_status", "ev_ready"),
        ("dc_ev_status", "ev_error_code"),
        ("ev_target_voltage", "value"),
        ("ev_target_voltage", "multiplier"),
        ("ev_target_current", "value"),
        ("ev_target_current", "multiplier"),
    },
    "CurrentDemandReq": {
        ("dc_ev_status", "ev_ready"),
        ("dc_ev_status", "ev_error_code"),
        ("ev_target_voltage", "value"),
        ("ev_target_voltage", "multiplier"),
        ("ev_target_current", "value"),
        ("ev_target_current", "multiplier"),
        ("charging_complete",),
    },
    "WeldingDetectionReq": {
        ("dc_ev_status", "ev_ready"),
        ("dc_ev_status", "ev_error_code"),
    },
}


# The ISO-15118-2 SECC allowlist (issue #96). The runtime-produced required
# leaves, decoded field-for-field from `HAL+TCP_ISO_2_DC_Example.pcap`: the
# EVSEProcessing ONGOING->FINISHED progression, the ramping present voltage /
# current (value/multiplier/unit — ISO-2 makes the unit a required leaf, and the
# builder always emits the constant V/A), the CurrentDemandRes limit-achieved
# flags, and the runtime-echoed EVSEID (`get_evse_id`) and selected
# SAScheduleTupleID (`comm_session.selected_schedule`). As on the DIN side the
# isolation-bearing `DC_EVSEStatus` is deliberately *not* allowlisted — it is the
# config-in-tree red-team surface the baseline pins (Invalid/IsolationMonitoring
# ->Valid/Ready), with the completing FINISHED frame handled by the CableCheck
# `skip_fields` seam rather than the allowlist.
_ISO2_SECC_MESSAGE_ALLOWLIST: Dict[str, Set[LeafPath]] = {
    "AuthorizationRes": {("evse_processing",)},
    "ChargeParameterDiscoveryRes": {("evse_processing",)},
    "CableCheckRes": {("evse_processing",)},
    "PreChargeRes": {
        ("evse_present_voltage", "value"),
        ("evse_present_voltage", "multiplier"),
        ("evse_present_voltage", "unit"),
    },
    "CurrentDemandRes": {
        ("evse_present_voltage", "value"),
        ("evse_present_voltage", "multiplier"),
        ("evse_present_voltage", "unit"),
        ("evse_present_current", "value"),
        ("evse_present_current", "multiplier"),
        ("evse_present_current", "unit"),
        ("evse_current_limit_achieved",),
        ("evse_voltage_limit_achieved",),
        ("evse_power_limit_achieved",),
        ("evse_id",),
        ("sa_schedule_tuple_id",),
    },
    "ChargingStatusRes": {
        ("evse_id",),
        ("sa_schedule_tuple_id",),
    },
    "WeldingDetectionRes": {
        ("evse_present_voltage", "value"),
        ("evse_present_voltage", "multiplier"),
        ("evse_present_voltage", "unit"),
    },
}


# The ISO-15118-2 EVCC allowlist (issue #97). The runtime-produced required
# leaves, decoded field-for-field from `Mach-E-ISO.pcapng`: the NIC-MAC EVCCID,
# the negotiated SelectedPaymentOption and the echoed SelectedServiceList
# ServiceID, the single-sourced RequestedEnergyTransferMode (from the pre-tree
# `capabilities.energy_transfer_mode`, as on the DIN side), the DC_EVStatus
# EVReady / EVErrorCode (the adjacent EVRESSSOC is config-only, pinned by the
# baseline — mirroring the DIN Cadillac's 88 %), the ramping target voltage /
# current (value/multiplier/unit — ISO-2 makes the unit a required leaf), the
# runtime PowerDeliveryReq ChargeProgress / SAScheduleTupleID, the per-loop
# ChargingComplete and the SessionStopReq ChargingSession. The DC envelope
# maxima the Mach-E *does* emit (500 A / 422 V / 211000 W) are deliberately
# tree-owned, not allowlisted, so the baseline pins them; the Optional fields the
# Mach-E omits (EVEnergyRequest, FullSOC, BulkSOC, RemainingTime*,
# BulkChargingComplete) are left unset by the builder and never reach the tree.
# The AC-/PnC-only messages (ServiceDetailReq, CertificateInstallationReq,
# PaymentDetailsReq, MeteringReceiptReq, ChargingStatusReq) carry no entry: the
# DC/EIM baseline never sources them, so per-message-present skips them; a future
# AC / PnC baseline adds their allowlist entries as its slice lands.
_ISO2_EVCC_MESSAGE_ALLOWLIST: Dict[str, Set[LeafPath]] = {
    "SessionSetupReq": {("evcc_id",)},
    "PaymentServiceSelectionReq": {
        ("selected_auth_option",),
        ("selected_service_list", "selected_service"),
    },
    "ChargeParameterDiscoveryReq": {("requested_energy_mode",)},
    "CableCheckReq": {
        ("dc_ev_status", "ev_ready"),
        ("dc_ev_status", "ev_error_code"),
    },
    "PreChargeReq": {
        ("dc_ev_status", "ev_ready"),
        ("dc_ev_status", "ev_error_code"),
        ("ev_target_voltage", "value"),
        ("ev_target_voltage", "multiplier"),
        ("ev_target_voltage", "unit"),
        ("ev_target_current", "value"),
        ("ev_target_current", "multiplier"),
        ("ev_target_current", "unit"),
    },
    "PowerDeliveryReq": {
        ("charge_progress",),
        ("sa_schedule_tuple_id",),
    },
    "CurrentDemandReq": {
        ("dc_ev_status", "ev_ready"),
        ("dc_ev_status", "ev_error_code"),
        ("ev_target_current", "value"),
        ("ev_target_current", "multiplier"),
        ("ev_target_current", "unit"),
        ("ev_target_voltage", "value"),
        ("ev_target_voltage", "multiplier"),
        ("ev_target_voltage", "unit"),
        ("charging_complete",),
    },
    "WeldingDetectionReq": {
        ("dc_ev_status", "ev_ready"),
        ("dc_ev_status", "ev_error_code"),
    },
    "SessionStopReq": {("charging_session",)},
}


# The ISO-15118-20 DC SECC allowlist (issue #98). The runtime-produced required
# leaves, decoded field-for-field from `iso20.pcap` (a real DC-BPT / Dynamic /
# EIM session, plaintext, SECC source port 53927): the EVSEProcessing
# ONGOING->FINISHED progression (Authorization / ScheduleExchange / DCCableCheck),
# the ramping DCChargeLoopRes / DCPreChargeRes / DCWeldingDetectionRes present
# voltage / current (each a RationalNumber `exponent`+`value` leaf pair), the
# DCChargeLoopRes limit-achieved flags, the ServiceDiscoveryRes energy-service
# advertisement (`get_energy_service_list`, single-sourced from
# `capabilities.supported_energy_services`) and renegotiation flag, and the
# ServiceDetailRes echoed ServiceID + emulator-built ParameterSet list. The
# AuthorizationSetupRes auth services / cert-install flag come from
# `capabilities.supported_auth_modes` and the SECC config. The `header` envelope
# (SessionID, timestamp) is excluded structurally (`_ENVELOPE_ROOT_FIELDS`), not
# allowlisted. As on the DIN / ISO-2 side the config-owned identity
# `SessionSetupRes.EVSEID` is deliberately *not* allowlisted — it is the tree
# value the baseline pins (`PcLoadLetter`). The BPT DC envelope
# (`DCChargeParameterDiscoveryRes`) is an Optional sub-model, so it is never
# completeness-required; the baseline pins it in the tree (the retired
# `power.evse_dc_v20` values) and it flows on into the session limits that feed
# the DCChargeLoopRes control-mode envelope.
_ISO20_DC_SECC_MESSAGE_ALLOWLIST: Dict[str, Set[LeafPath]] = {
    "AuthorizationSetupRes": {
        ("auth_services",),
        ("cert_install_service",),
    },
    "AuthorizationRes": {("evse_processing",)},
    "ServiceDiscoveryRes": {
        ("service_renegotiation_supported",),
        ("energy_service_list", "services"),
    },
    "ServiceDetailRes": {
        ("service_id",),
        ("service_parameter_list", "parameter_sets"),
    },
    "ScheduleExchangeRes": {("evse_processing",)},
    "DCCableCheckRes": {("evse_processing",)},
    "DCPreChargeRes": {
        ("evse_present_voltage", "exponent"),
        ("evse_present_voltage", "value"),
    },
    "DCChargeLoopRes": {
        ("evse_present_current", "exponent"),
        ("evse_present_current", "value"),
        ("evse_present_voltage", "exponent"),
        ("evse_present_voltage", "value"),
        ("evse_power_limit_achieved",),
        ("evse_current_limit_achieved",),
        ("evse_voltage_limit_achieved",),
    },
    "DCWeldingDetectionRes": {
        ("evse_present_voltage", "exponent"),
        ("evse_present_voltage", "value"),
    },
}


# The ISO-15118-20 DC EVCC allowlist (issue #99). The runtime-produced required
# leaves, mirroring the ISO-20 DC SECC allowlist (#98) across the vehicle side and
# decoded field-for-field from `iso20.pcap` (the same real DC-BPT / Dynamic / EIM
# session): the NIC-MAC EVCCID; the negotiated SelectedAuthorizationService
# (EIM/PnC); the echoed ServiceDetailReq ServiceID and the session-scoped
# ServiceSelectionReq SelectedEnergyService (ServiceID + ParameterSetID, chosen at
# runtime from the SECC's advertisement); the ScheduleExchangeReq
# MaximumSupportingPoints (a config-owned knob, single-sourced from `EVCCConfig`
# like the SECC's config-derived leaves); the PowerDeliveryReq EVProcessing /
# ChargeProgress ready flags; the ramping DCPreChargeReq / DCChargeLoopReq present
# voltage and DCPreChargeReq target voltage (each a RationalNumber
# `exponent`+`value` leaf pair) with their EVProcessing; the DCChargeLoopReq
# MeterInfoRequested (a constant `False` the builder always emits); and the
# SessionStopReq ChargingSession (TERMINATE/PAUSE at runtime). The `header`
# envelope (SessionID, timestamp, signature) is excluded structurally
# (`_ENVELOPE_ROOT_FIELDS`), not allowlisted. The DC-BPT requested envelope
# (`DCChargeParameterDiscoveryReq.BPT_DC_CPDReqEnergyTransferMode`) is an Optional
# sub-model, so it is never completeness-required; the baseline pins it in the
# tree (the retired `power.ev_dc_v20` values). The PnC-only
# `CertificateInstallationReq` carries no entry — the EIM baseline never sources
# it, so per-message-present skips it; a future PnC baseline adds its allowlist
# entries as its slice lands.
_ISO20_DC_EVCC_MESSAGE_ALLOWLIST: Dict[str, Set[LeafPath]] = {
    "SessionSetupReq": {("evcc_id",)},
    "AuthorizationReq": {("selected_auth_service",)},
    "ServiceDetailReq": {("service_id",)},
    "ServiceSelectionReq": {
        ("selected_energy_service", "service_id"),
        ("selected_energy_service", "parameter_set_id"),
    },
    "ScheduleExchangeReq": {("max_supporting_points",)},
    "PowerDeliveryReq": {
        ("ev_processing",),
        ("charge_progress",),
    },
    "SessionStopReq": {("charging_session",)},
    "DCPreChargeReq": {
        ("ev_processing",),
        ("ev_present_voltage", "exponent"),
        ("ev_present_voltage", "value"),
        ("ev_target_voltage", "exponent"),
        ("ev_target_voltage", "value"),
    },
    "DCChargeLoopReq": {
        ("meter_info_requested",),
        ("ev_present_voltage", "exponent"),
        ("ev_present_voltage", "value"),
    },
    "DCWeldingDetectionReq": {("ev_processing",)},
}


# The ISO-15118-20 AC SECC allowlist (issue #100). The AC sibling of
# _ISO20_DC_SECC_MESSAGE_ALLOWLIST: exactly its *common*-message entries, because
# the ISO-20 common ``*Res`` are the same models regardless of energy transfer
# mode, decoded field-for-field from `HAL+TCP_ISO_20_AC_Example.pcap` (a real
# plain-AC / Dynamic / EIM session, plaintext TCP): the EVSEProcessing
# ONGOING->FINISHED progression (Authorization / ScheduleExchange), the
# ServiceDiscoveryRes energy-service advertisement (`get_energy_service_list`,
# single-sourced from `capabilities.supported_energy_services`) and renegotiation
# flag, the ServiceDetailRes echoed ServiceID + emulator-built ParameterSet list,
# and the AuthorizationSetupRes auth services / cert-install flag (from
# `capabilities.supported_auth_modes` and the SECC config). The AC-specific
# ``ACChargeParameterDiscoveryRes`` and ``ACChargeLoopRes`` carry *no* entry: their
# only completeness-required leaf is ``response_code`` (folded in from
# ``_SECC_BASE_ALLOWLIST``); the AC / AC-BPT envelopes ride inside Optional
# sub-models (``{bpt_,}ac_params``), never completeness-required, and the baseline
# pins the plain-AC envelope in the tree (the retired `power.evse_ac_v20` values).
# The `header` envelope (SessionID, timestamp) is excluded structurally
# (`_ENVELOPE_ROOT_FIELDS`), not allowlisted; the config-owned
# `SessionSetupRes.EVSEID` is likewise not allowlisted — it is the tree value the
# baseline pins.
_ISO20_AC_SECC_MESSAGE_ALLOWLIST: Dict[str, Set[LeafPath]] = {
    "AuthorizationSetupRes": {
        ("auth_services",),
        ("cert_install_service",),
    },
    "AuthorizationRes": {("evse_processing",)},
    "ServiceDiscoveryRes": {
        ("service_renegotiation_supported",),
        ("energy_service_list", "services"),
    },
    "ServiceDetailRes": {
        ("service_id",),
        ("service_parameter_list", "parameter_sets"),
    },
    "ScheduleExchangeRes": {("evse_processing",)},
}


# Per-protocol, per-role allowlist tables: (emitted message set, per-message
# allowlist). The SECC base set (ResponseCode) folds into every SECC message of
# every protocol. ISO-2 is tree-backed for both roles as of #96 (SECC) / #97
# (EVCC); ISO-20 DC is tree-backed for the SECC role as of #98 and the EVCC role
# as of #99; ISO-20 AC is tree-backed for the SECC role as of #100. Keyed
# protocol -> the table `allowlist_for` folds.
_SECC_ALLOWLIST_TABLES: Dict[str, Tuple[Tuple[str, ...], Dict[str, Set[LeafPath]]]] = {
    _DIN_PROTOCOL: (SECC_MESSAGES, _SECC_MESSAGE_ALLOWLIST),
    _ISO2_PROTOCOL: (ISO2_SECC_MESSAGES, _ISO2_SECC_MESSAGE_ALLOWLIST),
    _ISO20_DC_PROTOCOL: (ISO20_DC_SECC_MESSAGES, _ISO20_DC_SECC_MESSAGE_ALLOWLIST),
    _ISO20_AC_PROTOCOL: (ISO20_AC_SECC_MESSAGES, _ISO20_AC_SECC_MESSAGE_ALLOWLIST),
}
_EVCC_ALLOWLIST_TABLES: Dict[str, Tuple[Tuple[str, ...], Dict[str, Set[LeafPath]]]] = {
    _DIN_PROTOCOL: (EVCC_MESSAGES, _EVCC_MESSAGE_ALLOWLIST),
    _ISO2_PROTOCOL: (ISO2_EVCC_MESSAGES, _ISO2_EVCC_MESSAGE_ALLOWLIST),
    _ISO20_DC_PROTOCOL: (ISO20_DC_EVCC_MESSAGES, _ISO20_DC_EVCC_MESSAGE_ALLOWLIST),
}


def allowlist_for(
    role: str, protocol: str = _DIN_PROTOCOL
) -> Dict[str, Set[LeafPath]]:
    """Return ``{message_name: {allowlisted leaf paths}}`` for *role*/*protocol*.

    Folds the per-role base set (SECC ``ResponseCode``) into every emitted
    message so callers see one flat per-message view. Also the single source the
    guard tests iterate to assert each entry has a real builder fallback.
    ``protocol`` defaults to DIN so existing single-arg callers keep their DIN
    view; the completeness check passes the protocol it is walking. Returns an
    empty mapping for a protocol/role with no allowlist table (e.g. an ISO-20
    role, still pre-tree).
    """
    if role == "secc":
        table, base = _SECC_ALLOWLIST_TABLES, _SECC_BASE_ALLOWLIST
    elif role == "evcc":
        table, base = _EVCC_ALLOWLIST_TABLES, set()
    else:
        raise ValueError(f"unknown role {role!r}; expected 'evcc' or 'secc'")
    entry = table.get(protocol)
    if entry is None:
        return {}
    messages, per_message = entry
    return {msg: set(base) | per_message.get(msg, set()) for msg in messages}


# ---------------------------------------------------------------------------
# Required-leaf walk (single-sourced from the message models)
# ---------------------------------------------------------------------------


def _required_leaf_paths(
    model_cls: Type[BaseModel], prefix: LeafPath = ()
) -> List[LeafPath]:
    """Enumerate the Python-name path of every mandatory leaf of *model_cls*.

    "Mandatory" = the field is required (``Field(...)``, no default). Recurses
    into *required* sub-models only: an ``Optional`` sub-model (default ``None``)
    is omissible as a whole subtree, so nothing inside it is mandatory and it is
    not walked. A required ``List[...]`` of sub-models (a list-nested wire field,
    ADR-0006 #81) yields the list path itself — its cardinality/elements are
    value-raw, so completeness only asks that the list be present, not that each
    element be complete.
    """
    leaves: List[LeafPath] = []
    for name, field in model_cls.model_fields.items():
        if not field.is_required():
            continue
        annotation = field.annotation
        if _list_element_model(annotation) is not None:
            leaves.append(prefix + (name,))
            continue
        child_cls = _model_in_annotation(annotation)
        if (
            child_cls is not None
            and isinstance(child_cls, type)
            and issubclass(child_cls, BaseModel)
        ):
            leaves.extend(_required_leaf_paths(child_cls, prefix + (name,)))
            continue
        leaves.append(prefix + (name,))
    return leaves


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------


# The completeness data (which messages a role emits, and which required leaves
# are emulator-produced) is per-protocol. DIN (both roles) and ISO-2 (both roles)
# are tree-backed; ISO-20 adds its own entry as it migrates. Keyed protocol ->
# role -> emitted message set, mirroring the tree-backed set in
# :data:`_TREE_BACKED_PROTOCOLS`.
_PROTOCOL_ROLE_MESSAGES: Dict[str, Dict[str, Tuple[str, ...]]] = {
    _DIN_PROTOCOL: {"secc": SECC_MESSAGES, "evcc": EVCC_MESSAGES},
    # ISO-2 is tree-backed for both roles: SECC (#96) and EVCC (#97).
    _ISO2_PROTOCOL: {"secc": ISO2_SECC_MESSAGES, "evcc": ISO2_EVCC_MESSAGES},
    # ISO-20 DC is tree-backed for the SECC role (#98) and the EVCC role (#99).
    _ISO20_DC_PROTOCOL: {
        "secc": ISO20_DC_SECC_MESSAGES,
        "evcc": ISO20_DC_EVCC_MESSAGES,
    },
    # ISO-20 AC is tree-backed for the SECC role (#100); the EVCC side has no
    # entry yet, so an ISO-20 AC EVCC personality carries no required subtree.
    _ISO20_AC_PROTOCOL: {"secc": ISO20_AC_SECC_MESSAGES},
}


def check_message_field_tree_completeness(
    tree: Dict, role: str, supported_protocols: Iterable[str]
) -> None:
    """Raise if a supported, tree-backed protocol's subtree is incomplete.

    Per-protocol (ADR-0006 protocol-keyed amendment): for each protocol the
    personality both *supports* and that :func:`is_tree_backed` (DIN, ISO-2,
    ISO-20 DC, and ISO-20 AC SECC today) — the
    protocol's subtree must carry a value for every mandatory wire field of every
    message the *role* emits, unless the leaf is on the role's allowlist. A
    supported but not-yet-tree-backed protocol is skipped entirely (its wire
    values come from the builders' pre-tree path).

    Per-message-present (see the module docstring): only messages the role emits
    *and* that appear as a key in the protocol's subtree are walked. The first
    violation raises :class:`MessageFieldTreeIncompleteError` naming the
    protocol, message, and field path. A no-op for an empty tree.
    """
    if not tree:
        return
    if role not in ("secc", "evcc"):
        raise ValueError(f"unknown role {role!r}; expected 'evcc' or 'secc'")

    for protocol in supported_protocols:
        if not is_tree_backed(protocol):
            continue
        subtree = tree.get(protocol)
        if not subtree:
            continue
        messages = _PROTOCOL_ROLE_MESSAGES.get(protocol, {}).get(role)
        if messages is None:  # pragma: no cover - defensive; tree-backed => known
            continue
        allowlist = allowlist_for(role, protocol)
        for message_name in messages:
            if message_name not in subtree:
                continue
            model_cls = _message_class(protocol, message_name)
            if model_cls is None:  # pragma: no cover - defensive
                continue
            allowed = allowlist.get(message_name, set())
            for path in _required_leaf_paths(model_cls):
                if path and path[0] in _ENVELOPE_ROOT_FIELDS:
                    # Header/envelope stays compute-only (ADR-0006); the tree is
                    # message-body only. No-op for DIN / ISO-2 (no header field).
                    continue
                if path in allowed:
                    continue
                if resolve_tree_leaf(tree, protocol, message_name, path) is UNSET:
                    pretty = " -> ".join(path)
                    raise MessageFieldTreeIncompleteError(
                        f"{protocol} -> {message_name} -> {pretty}: mandatory wire "
                        f"field is absent from the merged message field tree and is "
                        f"not an emulator-produced (allowlisted) field. Either set "
                        f"it in the personality's message_field_tree or, if the "
                        f"emulator produces it at runtime, add it to the ADR-0006 "
                        f"#83 optional-field allowlist."
                    )
