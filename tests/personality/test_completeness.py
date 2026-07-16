"""Load-time completeness check for the message field tree (ADR-0006 #83).

A *mandatory* wire field (a Pydantic-required leaf) of a DIN message the tree
carries must resolve to a value in the merged tree, unless it is on the
optional-field allowlist (fields the emulator produces at runtime). These tests
cover the load-time behaviour; the companion guard that every allowlist entry
has a real builder fallback lives in
`tests/conformance/state_machine/test_din_allowlist_fallback_guard.py`.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.shared.personality.completeness import (
    allowlist_for,
    check_message_field_tree_completeness,
    is_tree_backed,
)
from app.shared.personality.loader import _apply_extends, _load_yaml, load_personality
from app.shared.personality.model import EVCCPersonality, SECCPersonality

PERSONALITIES_DIR = Path(__file__).resolve().parents[2] / "personalities"


def _merged_tree_data(filename: str) -> dict:
    """Load a personality YAML and resolve its `extends:` baseline (no validation)."""
    data = _load_yaml(PERSONALITIES_DIR / filename)
    return _apply_extends(data, seen={filename})


# ---------------------------------------------------------------------------
# Acceptance: the shipped DIN baselines + devices pass unchanged
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,role",
    [
        ("din-secc-baseline", "secc"),
        ("din-evcc-baseline", "evcc"),
        ("din_dc_extended-secc", "secc"),
        ("din_dc_extended-evcc", "evcc"),
    ],
)
def test_shipped_din_personalities_pass_completeness(name, role):
    # Loading is the check — it raises on an incomplete tree.
    load_personality(name, role)


# ---------------------------------------------------------------------------
# Acceptance: empty-tree / non-DIN personalities are untouched
# ---------------------------------------------------------------------------


def test_empty_tree_personalities_load():
    # The stock defaults ship an empty message_field_tree; the check is a no-op.
    assert SECCPersonality().message_field_tree == {}
    assert EVCCPersonality().message_field_tree == {}


@pytest.mark.parametrize(
    "name,role",
    [
        ("default-secc", "secc"),
        ("default-evcc", "evcc"),
        ("default-no-tls-secc", "secc"),
        # ISO-2 EVCC is still pre-tree, so its shipped personality carries no
        # tree and loads as the empty-tree case does.
        ("iso2_eim_dc-evcc", "evcc"),
        ("iso20_dc", "secc"),
    ],
)
def test_non_din_shipped_personalities_load(name, role):
    load_personality(name, role)


@pytest.mark.parametrize(
    "name",
    ["iso2-secc-baseline", "iso2_eim_dc-secc", "iso2_pnc_dc-secc"],
)
def test_shipped_iso2_secc_personalities_pass_completeness(name):
    # ISO-2 is tree-backed as of #96: the shipped SECC baseline and the device
    # files that `extends` it must carry a complete ISO-2 subtree. Loading is the
    # check — it raises on an incomplete tree.
    load_personality(name, "secc")


# ---------------------------------------------------------------------------
# Acceptance: a missing required, non-allowlisted field fails at load,
# naming the message and field path
# ---------------------------------------------------------------------------


def test_missing_required_secc_leaf_fails_at_load():
    data = _merged_tree_data("din-secc-baseline.yaml")
    # EVSEStatusCode is a required DIN wire field, not on the allowlist.
    tree = data["message_field_tree"]["DIN_SPEC_70121"]
    del tree["CableCheckRes"]["DC_EVSEStatus"]["EVSEStatusCode"]
    with pytest.raises(
        ValidationError,
        match="DIN_SPEC_70121 -> CableCheckRes -> dc_evse_status -> evse_status_code",
    ):
        SECCPersonality.model_validate(data)


def test_missing_required_evcc_leaf_fails_at_load():
    data = _merged_tree_data("din-evcc-baseline.yaml")
    # EVRESSSOC is required and config-only (the Cadillac pins 88%), not allowlisted.
    tree = data["message_field_tree"]["DIN_SPEC_70121"]
    del tree["CableCheckReq"]["DC_EVStatus"]["EVRESSSOC"]
    with pytest.raises(
        ValidationError,
        match="DIN_SPEC_70121 -> CableCheckReq -> dc_ev_status -> ev_ress_soc",
    ):
        EVCCPersonality.model_validate(data)


def test_missing_nested_secc_leaf_names_full_path():
    data = _merged_tree_data("din-secc-baseline.yaml")
    # Drop only the EVSENotification leaf; siblings keep the message in the tree.
    tree = data["message_field_tree"]["DIN_SPEC_70121"]
    del tree["PreChargeRes"]["DC_EVSEStatus"]["EVSENotification"]
    with pytest.raises(
        ValidationError,
        match="DIN_SPEC_70121 -> PreChargeRes -> dc_evse_status -> evse_notification",
    ):
        SECCPersonality.model_validate(data)


# ---------------------------------------------------------------------------
# Acceptance: omitting an allowlisted field loads cleanly
# ---------------------------------------------------------------------------


def test_omitting_allowlisted_field_loads_clean():
    # A DIN-exclusive SECC personality (so the check runs) whose CurrentDemandRes
    # spells out the required config leaves (DC_EVSEStatus) but omits every
    # allowlisted field — present voltage/current, the limit-achieved flags, and
    # ResponseCode. It must load cleanly.
    personality = SECCPersonality.model_validate(
        {
            "capabilities": {"supported_protocols": ["DIN_SPEC_70121"]},
            "message_field_tree": {
                "DIN_SPEC_70121": {
                    "CurrentDemandRes": {
                        "DC_EVSEStatus": {
                            "NotificationMaxDelay": 0,
                            "EVSENotification": "None",
                            "EVSEStatusCode": "EVSE_Ready",
                        }
                    }
                }
            },
        }
    )
    assert "CurrentDemandRes" in personality.message_field_tree["DIN_SPEC_70121"]


def test_response_code_omission_is_allowed_everywhere():
    # ResponseCode is allowlisted for every SECC *Res via the base set — a tree
    # that pins other required leaves but never ResponseCode loads.
    check_message_field_tree_completeness(
        {
            "DIN_SPEC_70121": {
                "SessionSetupRes": {"EVSEID": "00"},
                "SessionStopRes": {},
            },
        },
        "secc",
        ["DIN_SPEC_70121"],
    )


# ---------------------------------------------------------------------------
# Acceptance: an allowlisted field SET in the tree is applied (override works)
# ---------------------------------------------------------------------------


def test_allowlisted_field_set_in_tree_is_applied():
    from app.secc.states.din_spec_states import apply_personality_tree
    from app.secc.controller.simulator import SimEVSEController
    from app.shared.messages.din_spec.body import CurrentDemandRes, ResponseCode
    from app.shared.messages.datatypes import (
        DCEVSEStatus,
        DCEVSEStatusCode,
        PVEVSEPresentCurrentDin,
        PVEVSEPresentVoltageDin,
    )
    from app.shared.messages.datatypes import EVSENotification

    # Pin an allowlisted field (EVSECurrentLimitAchieved) in the tree — a
    # red-team override of a normally-runtime value.
    personality = SECCPersonality.model_validate(
        {
            "message_field_tree": {
                "DIN_SPEC_70121": {
                    "CurrentDemandRes": {
                        "DC_EVSEStatus": {
                            "NotificationMaxDelay": 0,
                            "EVSENotification": "None",
                            "EVSEStatusCode": "EVSE_Ready",
                        },
                        "EVSECurrentLimitAchieved": True,
                    }
                }
            }
        }
    )
    ctrl = SimEVSEController(personality=personality)
    res = CurrentDemandRes(
        response_code=ResponseCode.OK,
        dc_evse_status=DCEVSEStatus(
            notification_max_delay=0,
            evse_notification=EVSENotification.NONE,
            evse_status_code=DCEVSEStatusCode.EVSE_READY,
        ),
        evse_present_voltage=PVEVSEPresentVoltageDin(multiplier=0, value=400),
        evse_present_current=PVEVSEPresentCurrentDin(multiplier=0, value=10),
        evse_current_limit_achieved=False,
        evse_voltage_limit_achieved=False,
        evse_power_limit_achieved=False,
    )

    class _Session:
        evse_controller = ctrl

    apply_personality_tree(_Session(), res, "CurrentDemandRes")
    # The configured override replaced the builder's computed False.
    assert res.evse_current_limit_achieved is True


# ---------------------------------------------------------------------------
# The allowlist itself
# ---------------------------------------------------------------------------


def test_allowlist_is_role_aware_and_leaf_path_granular():
    secc = allowlist_for("secc")
    evcc = allowlist_for("evcc")
    # ResponseCode is on every SECC message (base set); EVSEProcessing only where
    # the SECC actually withholds it.
    assert ("response_code",) in secc["SessionStopRes"]
    assert ("evse_processing",) in secc["ChargeParameterDiscoveryRes"]
    assert ("evse_processing",) not in secc["PreChargeRes"]
    # DC_EVStatus is mixed on the EVCC side: EVReady/EVErrorCode allowlisted,
    # EVRESSSOC deliberately NOT (config-only).
    assert ("dc_ev_status", "ev_ready") in evcc["CableCheckReq"]
    assert ("dc_ev_status", "ev_error_code") in evcc["CableCheckReq"]
    assert ("dc_ev_status", "ev_ress_soc") not in evcc["CableCheckReq"]
    # Findings 2 & 3.
    assert ("requested_energy_mode",) in evcc["ChargeParameterDiscoveryReq"]
    assert ("ready_to_charge",) in evcc["PowerDeliveryReq"]


def test_unknown_role_rejected():
    with pytest.raises(ValueError, match="unknown role"):
        allowlist_for("bogus")
    with pytest.raises(ValueError, match="unknown role"):
        check_message_field_tree_completeness(
            {"DIN_SPEC_70121": {"SessionSetupRes": {}}}, "bogus", ["DIN_SPEC_70121"]
        )


# ---------------------------------------------------------------------------
# The per-protocol tree-backed gate: the check runs per supported, tree-backed
# protocol (DIN today); a supported-but-not-tree-backed protocol is exempt.
# ---------------------------------------------------------------------------


def test_is_tree_backed_gate():
    assert is_tree_backed("DIN_SPEC_70121") is True
    # ISO-2 became tree-backed in #96; ISO-20 is still on the pre-tree path.
    assert is_tree_backed("ISO_15118_2") is True
    assert is_tree_backed("ISO_15118_20_DC") is False
    assert is_tree_backed("ISO_15118_20_AC") is False


def test_incomplete_din_subtree_fails_whenever_din_is_supported():
    # An incomplete ServiceDiscoveryRes (only the EnergyTransferType leaf; the
    # required PaymentOptions / ServiceTag / FreeService are absent), under the
    # DIN protocol key.
    incomplete_tree = {
        "message_field_tree": {
            "DIN_SPEC_70121": {
                "ServiceDiscoveryRes": {
                    "ChargeService": {"EnergyTransferType": "DC_extended"}
                }
            }
        }
    }

    # DIN-only → the DIN subtree is walked and the partial message rejected.
    din_only = dict(
        incomplete_tree,
        capabilities={"supported_protocols": ["DIN_SPEC_70121"]},
    )
    with pytest.raises(
        ValidationError, match="DIN_SPEC_70121 -> ServiceDiscoveryRes -> auth_option_list"
    ):
        SECCPersonality.model_validate(din_only)

    # Multi-protocol → per-protocol scoping: DIN is still tree-backed and
    # supported, so its subtree is still checked and the partial message still
    # fails (the old all-or-nothing "DIN-exclusive" gate is gone).
    multi_protocol = dict(
        incomplete_tree,
        capabilities={"supported_protocols": ["DIN_SPEC_70121", "ISO_15118_2"]},
    )
    with pytest.raises(
        ValidationError, match="DIN_SPEC_70121 -> ServiceDiscoveryRes -> auth_option_list"
    ):
        SECCPersonality.model_validate(multi_protocol)


def test_multi_protocol_personality_with_absent_din_subtree_loads():
    # A SECC advertising DIN + ISO_15118_2 whose tree carries no DIN subtree:
    # DIN is supported and tree-backed, but the per-message-present rule finds no
    # DIN messages to walk (its subtree is absent), so the gate stays silent.
    SECCPersonality.model_validate(
        {"capabilities": {"supported_protocols": ["DIN_SPEC_70121", "ISO_15118_2"]}}
    )


def test_supported_but_not_tree_backed_protocol_subtree_is_exempt():
    # ISO_15118_20_DC is supported and even carries a (deliberately bare)
    # subtree, but it is not yet tree-backed, so it is never walked — an
    # incomplete ISO-20 subtree cannot trip the completeness gate, and the absent
    # DIN subtree is a no-op.
    check_message_field_tree_completeness(
        {"ISO_15118_20_DC": {"SessionSetupRes": {}}},
        "secc",
        ["DIN_SPEC_70121", "ISO_15118_20_DC"],
    )


def test_incomplete_iso2_subtree_fails_now_that_iso2_is_tree_backed():
    # ISO-2 is tree-backed (#96): a present-but-incomplete ISO-2 subtree (a
    # SessionSetupRes missing the required EVSEID) trips the completeness gate.
    with pytest.raises(
        ValidationError,
        match="ISO_15118_2 -> SessionSetupRes -> evse_id",
    ):
        SECCPersonality.model_validate(
            {
                "capabilities": {"supported_protocols": ["ISO_15118_2"]},
                "message_field_tree": {"ISO_15118_2": {"SessionSetupRes": {}}},
            }
        )
