"""Load-time completeness check for the [[message field tree]] (ADR-0006 #83).

Once a personality is mandatory to run, the loader can guarantee a wire value
exists for every field the emulated device emits. This module enforces that
guarantee at load time: for every **mandatory** wire field (a Pydantic-required
leaf — ``Field(...)``, no default) of a DIN message the personality is
responsible for, if the merged (baseline + device) tree resolves to **no value**
there, that is a **load-time error naming the message and field path** — unless
the field is on the :data:`OPTIONAL_FIELD_ALLOWLIST`, the standalone list of
fields the emulator produces on its own at runtime.

Scope (ADR-0006 #83, "DIN-only this slice"):

* **DIN only.** The message set comes from
  :func:`app.shared.messages.din_spec.body.get_msg_type`; ISO-15118-2 / -20
  add their own allowlist entries and message sets as those slices land.
* **DIN-exclusive personalities only.** The caller (the personality model
  validator) runs this check only when the personality advertises DIN SPEC
  70121 as its *sole* protocol — see :func:`is_din_exclusive`. That is exactly
  the shipped DIN baselines and the devices that ``extends`` them. A
  multi-protocol personality (the stock ``default-*``, the ISO / no-TLS smokes)
  still sources its DIN wire values from the builders' pre-tree path, so its
  tree is empty or a partial single-field red-team probe; demanding a complete
  DIN tree there would mis-fire and forbid that probing pattern.
* **Per-message-present.** Within a DIN-exclusive personality a required leaf is
  only demanded for a message the tree *contains an entry for* — the same
  "validate only what the tree actually specifies" stance the #76
  energy-transfer-mode check takes (an absent tree leaf is UNSET → skipped
  there; an absent *message* is skipped here). A DIN personality ``extends`` a
  baseline that spells out every DIN message, so its merged tree carries every
  message and gets full coverage.

The required-leaf walk and the "resolves to a value" query reuse the tree
machinery in :mod:`app.shared.personality.message_field_tree` rather than a
hand-maintained parallel schema.
"""

from __future__ import annotations

from typing import Dict, List, Set, Tuple, Type

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


# The one DIN protocol string, matched against a personality's advertised
# `capabilities.supported_protocols` to decide whether the completeness check
# applies (see the module docstring).
_DIN_PROTOCOL = "DIN_SPEC_70121"


def is_din_exclusive(supported_protocols) -> bool:
    """True when DIN SPEC 70121 is the *only* protocol the personality offers.

    That is the discriminator between a DIN device (whose wire output is fully
    tree-sourced and must therefore be complete) and a multi-protocol
    personality (which still drives DIN via the builders' pre-tree path and may
    carry an empty or partial tree). Order- and duplicate-insensitive.
    """
    return set(supported_protocols) == {_DIN_PROTOCOL}


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


def allowlist_for(role: str) -> Dict[str, Set[LeafPath]]:
    """Return ``{message_name: {allowlisted leaf paths}}`` for *role* (DIN).

    Folds the per-role base set (SECC ``ResponseCode``) into every emitted
    message so callers see one flat per-message view. Also the single source the
    guard test iterates to assert each entry has a real builder fallback.
    """
    if role == "secc":
        return {
            msg: set(_SECC_BASE_ALLOWLIST) | _SECC_MESSAGE_ALLOWLIST.get(msg, set())
            for msg in SECC_MESSAGES
        }
    if role == "evcc":
        return {
            msg: set(_EVCC_MESSAGE_ALLOWLIST.get(msg, set())) for msg in EVCC_MESSAGES
        }
    raise ValueError(f"unknown role {role!r}; expected 'evcc' or 'secc'")


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


def check_message_field_tree_completeness(tree: Dict, role: str) -> None:
    """Raise if the merged *tree* omits a mandatory, non-allowlisted DIN leaf.

    Per-message-present (see the module docstring): only messages the *role*
    emits *and* that appear as a key in *tree* are walked. For each such message,
    every mandatory leaf must either resolve to a value in the tree or be on the
    role's allowlist; the first violation raises
    :class:`MessageFieldTreeIncompleteError` naming the message and the field
    path. A no-op for an empty tree.
    """
    if not tree:
        return
    if role == "secc":
        messages = SECC_MESSAGES
    elif role == "evcc":
        messages = EVCC_MESSAGES
    else:
        raise ValueError(f"unknown role {role!r}; expected 'evcc' or 'secc'")

    allowlist = allowlist_for(role)
    for message_name in messages:
        if message_name not in tree:
            continue
        model_cls = _message_class(message_name)
        if model_cls is None:  # pragma: no cover - defensive; role sets are DIN
            continue
        allowed = allowlist.get(message_name, set())
        for path in _required_leaf_paths(model_cls):
            if path in allowed:
                continue
            if resolve_tree_leaf(tree, message_name, path) is UNSET:
                pretty = " -> ".join(path)
                raise MessageFieldTreeIncompleteError(
                    f"{message_name} -> {pretty}: mandatory wire field is absent "
                    f"from the merged message field tree and is not an "
                    f"emulator-produced (allowlisted) field. Either set it in the "
                    f"personality's message_field_tree or, if the emulator "
                    f"produces it at runtime, add it to the ADR-0006 #83 "
                    f"optional-field allowlist."
                )
