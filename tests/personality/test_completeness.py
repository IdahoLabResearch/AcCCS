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
    is_din_exclusive,
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
        ("iso2_eim_dc", "secc"),
        ("iso20_dc", "secc"),
    ],
)
def test_non_din_shipped_personalities_load(name, role):
    load_personality(name, role)


# ---------------------------------------------------------------------------
# Acceptance: a missing required, non-allowlisted field fails at load,
# naming the message and field path
# ---------------------------------------------------------------------------


def test_missing_required_secc_leaf_fails_at_load():
    data = _merged_tree_data("din-secc-baseline.yaml")
    # EVSEStatusCode is a required DIN wire field, not on the allowlist.
    del data["message_field_tree"]["CableCheckRes"]["DC_EVSEStatus"]["EVSEStatusCode"]
    with pytest.raises(
        ValidationError, match="CableCheckRes -> dc_evse_status -> evse_status_code"
    ):
        SECCPersonality.model_validate(data)


def test_missing_required_evcc_leaf_fails_at_load():
    data = _merged_tree_data("din-evcc-baseline.yaml")
    # EVRESSSOC is required and config-only (the Cadillac pins 88%), not allowlisted.
    del data["message_field_tree"]["CableCheckReq"]["DC_EVStatus"]["EVRESSSOC"]
    with pytest.raises(
        ValidationError, match="CableCheckReq -> dc_ev_status -> ev_ress_soc"
    ):
        EVCCPersonality.model_validate(data)


def test_missing_nested_secc_leaf_names_full_path():
    data = _merged_tree_data("din-secc-baseline.yaml")
    # Drop only the EVSENotification leaf; siblings keep the message in the tree.
    del data["message_field_tree"]["PreChargeRes"]["DC_EVSEStatus"]["EVSENotification"]
    with pytest.raises(
        ValidationError,
        match="PreChargeRes -> dc_evse_status -> evse_notification",
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
                "CurrentDemandRes": {
                    "DC_EVSEStatus": {
                        "NotificationMaxDelay": 0,
                        "EVSENotification": "None",
                        "EVSEStatusCode": "EVSE_Ready",
                    }
                }
            },
        }
    )
    assert "CurrentDemandRes" in personality.message_field_tree


def test_response_code_omission_is_allowed_everywhere():
    # ResponseCode is allowlisted for every SECC *Res via the base set — a tree
    # that pins other required leaves but never ResponseCode loads.
    check_message_field_tree_completeness(
        {
            "SessionSetupRes": {"EVSEID": "00"},
            "SessionStopRes": {},
        },
        "secc",
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
        check_message_field_tree_completeness({"SessionSetupRes": {}}, "bogus")


# ---------------------------------------------------------------------------
# The DIN-exclusive gate: the check only runs for DIN-only personalities
# ---------------------------------------------------------------------------


def test_is_din_exclusive_gate():
    assert is_din_exclusive(["DIN_SPEC_70121"]) is True
    assert is_din_exclusive(["DIN_SPEC_70121", "ISO_15118_2"]) is False
    assert is_din_exclusive(["ISO_15118_2"]) is False
    assert is_din_exclusive([]) is False


def test_incomplete_din_tree_fails_only_when_din_exclusive():
    # An incomplete ServiceDiscoveryRes (only the EnergyTransferType leaf; the
    # required PaymentOptions / ServiceTag / FreeService are absent).
    incomplete_tree = {
        "message_field_tree": {
            "ServiceDiscoveryRes": {
                "ChargeService": {"EnergyTransferType": "DC_extended"}
            }
        }
    }

    # DIN-exclusive → the check runs and rejects the partial message.
    din_exclusive = dict(
        incomplete_tree,
        capabilities={"supported_protocols": ["DIN_SPEC_70121"]},
    )
    with pytest.raises(
        ValidationError, match="ServiceDiscoveryRes -> auth_option_list"
    ):
        SECCPersonality.model_validate(din_exclusive)

    # Multi-protocol (the default) → the gate is off, so the same partial tree
    # loads: setting one field of one message stays a legal red-team probe.
    SECCPersonality.model_validate(incomplete_tree)
