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
        ("iso20_dc-secc", "secc"),
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


@pytest.mark.parametrize(
    "name",
    ["iso2-evcc-baseline", "iso2_eim_dc-evcc", "iso2_pnc_dc-evcc"],
)
def test_shipped_iso2_evcc_personalities_pass_completeness(name):
    # ISO-2 is tree-backed for the EVCC as of #97: the shipped Mach-E baseline and
    # the device files that `extends` it must carry a complete ISO-2 subtree.
    # Loading is the check — it raises on an incomplete tree.
    load_personality(name, "evcc")


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
    # RequestedEnergyTransferMode is tree-sourced now (#105), so it is NOT
    # allowlisted — the baseline must pin it in the tree.
    assert ("requested_energy_mode",) not in evcc["ChargeParameterDiscoveryReq"]
    # Finding 3.
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
    # ISO-2 became tree-backed in #96; ISO-20 DC in #98 (SECC); ISO-20 AC in #100
    # (SECC). WPT / ACDP remain on the pre-tree path.
    assert is_tree_backed("ISO_15118_2") is True
    assert is_tree_backed("ISO_15118_20_DC") is True
    assert is_tree_backed("ISO_15118_20_AC") is True
    assert is_tree_backed("ISO_15118_20_WPT") is False


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
    # ISO_15118_20_WPT is supported and even carries a (deliberately bare)
    # subtree, but it is not tree-backed, so it is never walked — an incomplete
    # WPT subtree cannot trip the completeness gate, and the absent DIN subtree is
    # a no-op. (ISO-20 DC became tree-backed in #98 and ISO-20 AC in #100, so
    # neither is the exempt example any more.)
    check_message_field_tree_completeness(
        {"ISO_15118_20_WPT": {"SessionSetupRes": {}}},
        "secc",
        ["DIN_SPEC_70121", "ISO_15118_20_WPT"],
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


def test_shipped_iso20_dc_secc_baseline_passes_completeness():
    # ISO-20 DC is tree-backed for the SECC as of #98: the shipped baseline must
    # carry a complete ISO-20 DC subtree. Loading is the check.
    load_personality("iso20-dc-secc-baseline", "secc")


def test_incomplete_iso20_dc_subtree_fails_now_that_iso20_dc_is_tree_backed():
    # ISO-20 DC is tree-backed (#98): a present-but-incomplete DC subtree (a
    # SessionSetupRes missing the required, config-owned EVSEID) trips the gate.
    # ResponseCode is allowlisted and the header envelope is excluded, so EVSEID
    # is the leaf that must be present.
    with pytest.raises(
        ValidationError,
        match="ISO_15118_20_DC -> SessionSetupRes -> evse_id",
    ):
        SECCPersonality.model_validate(
            {
                "capabilities": {"supported_protocols": ["ISO_15118_20_DC"]},
                "message_field_tree": {"ISO_15118_20_DC": {"SessionSetupRes": {}}},
            }
        )


def test_iso20_header_envelope_is_excluded_from_completeness():
    # The ISO-20 message models carry a required `header` (SessionID + timestamp),
    # which stays compute-only/deferred (ADR-0006) — the tree is message-body
    # only. A DC subtree that supplies EVSEID but nothing under `header` must
    # still load: the header leaves are never demanded of the tree.
    SECCPersonality.model_validate(
        {
            "capabilities": {"supported_protocols": ["ISO_15118_20_DC"]},
            "message_field_tree": {
                "ISO_15118_20_DC": {"SessionSetupRes": {"EVSEID": "PcLoadLetter"}}
            },
        }
    )


def test_shipped_iso20_ac_secc_baseline_passes_completeness():
    # ISO-20 AC is tree-backed for the SECC as of #100: the shipped baseline must
    # carry a complete ISO-20 AC subtree. Loading is the check. The only mandatory
    # AC SECC leaf the tree must supply is the config-owned SessionSetupRes.EVSEID
    # (shared via the common anchor); every other required leaf is allowlisted
    # (runtime-produced) or Optional (the AC envelope the baseline pins).
    load_personality("iso20-ac-secc-baseline", "secc")


def test_incomplete_iso20_ac_subtree_fails_now_that_iso20_ac_is_tree_backed():
    # ISO-20 AC is tree-backed (#100): a present-but-incomplete AC subtree (a
    # SessionSetupRes missing the required, config-owned EVSEID) trips the gate.
    # ResponseCode is allowlisted and the header envelope is excluded, so EVSEID
    # is the leaf that must be present — exactly as on the DC side.
    with pytest.raises(
        ValidationError,
        match="ISO_15118_20_AC -> SessionSetupRes -> evse_id",
    ):
        SECCPersonality.model_validate(
            {
                "capabilities": {"supported_protocols": ["ISO_15118_20_AC"]},
                "message_field_tree": {"ISO_15118_20_AC": {"SessionSetupRes": {}}},
            }
        )


def test_iso20_ac_cpd_envelope_is_optional_not_completeness_required():
    # The AC-specific ACChargeParameterDiscoveryRes rides its envelope inside the
    # Optional `{bpt_,}ac_params` sub-models, so no envelope leaf is ever
    # completeness-required: a subtree that names the message and pins the EVSEID
    # elsewhere loads even though it supplies only a partial AC envelope. The tree
    # is message-present for ACChargeParameterDiscoveryRes here, exercising that
    # its only required leaf (`response_code`) is base-allowlisted.
    SECCPersonality.model_validate(
        {
            "capabilities": {"supported_protocols": ["ISO_15118_20_AC"]},
            "message_field_tree": {
                "ISO_15118_20_AC": {
                    "SessionSetupRes": {"EVSEID": "PcLoadLetter"},
                    "ACChargeParameterDiscoveryRes": {
                        "AC_CPDResEnergyTransferMode": {
                            "EVSEMaximumChargePower": {"Exponent": 1, "Value": 20000},
                        }
                    },
                }
            },
        }
    )


def test_shipped_iso20_dc_evcc_baseline_passes_completeness():
    # ISO-20 DC is tree-backed for the EVCC as of #99: the shipped baseline must
    # carry a complete ISO-20 DC subtree. Loading is the check. Every mandatory
    # EVCC-emitted DC body leaf is runtime-produced (allowlisted) or Optional (the
    # BPT requested envelope the baseline pins), so the baseline's single pinned
    # message loads clean.
    load_personality("iso20-dc-evcc-baseline", "evcc")


def test_incomplete_iso20_dc_evcc_subtree_fails_now_that_iso20_dc_evcc_is_tree_backed():
    # ISO-20 DC is tree-backed for the EVCC (#99). Unlike the SECC (whose
    # config-owned EVSEID trips the gate), every mandatory *common* EVCC leaf is
    # runtime-produced and allowlisted (EVCCID from the NIC MAC, the negotiated
    # auth service, session-scoped IDs, ready flags), so the gate-tripping target
    # is the PnC-only CertificateInstallationReq — its OEMProvisioningCertificate-
    # Chain leaves are mandatory and *not* allowlisted (no PnC baseline sources
    # them). A subtree that names that message but omits them trips the gate. (The
    # shipped EIM baseline never carries this message, so per-message-present keeps
    # it clean.)
    with pytest.raises(
        ValidationError,
        match=(
            "ISO_15118_20_DC -> CertificateInstallationReq -> "
            "oem_prov_cert_chain -> id"
        ),
    ):
        EVCCPersonality.model_validate(
            {
                "capabilities": {"supported_protocols": ["ISO_15118_20_DC"]},
                "message_field_tree": {
                    "ISO_15118_20_DC": {
                        "CertificateInstallationReq": {
                            "MaximumContractCertificateChains": 3
                        }
                    }
                },
            }
        )


def test_iso20_dc_evcc_header_envelope_is_excluded_from_completeness():
    # The EVCC-side ISO-20 mirror of the SECC header-exclusion test: a DC EVCC
    # subtree that pins the DC-BPT requested envelope but nothing under `header`
    # must still load — the header leaves are never demanded of the tree.
    EVCCPersonality.model_validate(
        {
            "capabilities": {"supported_protocols": ["ISO_15118_20_DC"]},
            "message_field_tree": {
                "ISO_15118_20_DC": {
                    "DCChargeParameterDiscoveryReq": {
                        "BPT_DC_CPDReqEnergyTransferMode": {
                            "EVMaximumChargePower": {"Exponent": 0, "Value": 18000},
                            "EVMinimumChargePower": {"Exponent": 0, "Value": 0},
                            "EVMaximumChargeCurrent": {"Exponent": 0, "Value": 60},
                            "EVMinimumChargeCurrent": {"Exponent": 0, "Value": 0},
                            "EVMaximumVoltage": {"Exponent": 0, "Value": 800},
                            "EVMinimumVoltage": {"Exponent": 0, "Value": 450},
                            "EVMaximumDischargePower": {"Exponent": 0, "Value": -20000},
                            "EVMinimumDischargePower": {"Exponent": 0, "Value": 0},
                            "EVMaximumDischargeCurrent": {"Exponent": 0, "Value": -60},
                            "EVMinimumDischargeCurrent": {"Exponent": 0, "Value": 0},
                        }
                    }
                }
            },
        }
    )


def test_shipped_iso20_ac_evcc_baseline_passes_completeness():
    # ISO-20 AC is tree-backed for the EVCC as of #101: the shipped baseline must
    # carry a complete ISO-20 AC subtree. Loading is the check. Every mandatory
    # EVCC-emitted AC body leaf is runtime-produced (allowlisted) or Optional (the
    # AC requested envelope the baseline pins), so the baseline's single pinned
    # message loads clean.
    load_personality("iso20-ac-evcc-baseline", "evcc")


def test_incomplete_iso20_ac_evcc_subtree_fails_now_that_iso20_ac_evcc_is_tree_backed():
    # ISO-20 AC is tree-backed for the EVCC (#101). As on the DC EVCC side, every
    # mandatory *common* EVCC leaf is runtime-produced and allowlisted (EVCCID from
    # the NIC MAC, the negotiated auth service, session-scoped IDs, ready flags),
    # so the gate-tripping target is the PnC-only CertificateInstallationReq — its
    # OEMProvisioningCertificateChain leaves are mandatory and *not* allowlisted
    # (no PnC baseline sources them). A subtree that names that message but omits
    # them trips the gate. (The shipped EIM baseline never carries this message, so
    # per-message-present keeps it clean.)
    with pytest.raises(
        ValidationError,
        match=(
            "ISO_15118_20_AC -> CertificateInstallationReq -> "
            "oem_prov_cert_chain -> id"
        ),
    ):
        EVCCPersonality.model_validate(
            {
                "capabilities": {"supported_protocols": ["ISO_15118_20_AC"]},
                "message_field_tree": {
                    "ISO_15118_20_AC": {
                        "CertificateInstallationReq": {
                            "MaximumContractCertificateChains": 3
                        }
                    }
                },
            }
        )


def test_iso20_ac_evcc_cpd_envelope_is_optional_not_completeness_required():
    # The AC-specific ACChargeParameterDiscoveryReq rides its requested envelope
    # inside the Optional `{bpt_,}ac_params` sub-models, so no envelope leaf is ever
    # completeness-required: an AC EVCC subtree that names the message but supplies
    # only a partial AC envelope loads (the mirror of the SECC-side
    # `test_iso20_ac_cpd_envelope_is_optional_not_completeness_required`). The tree
    # is message-present for ACChargeParameterDiscoveryReq here, exercising that it
    # has no non-allowlisted mandatory body leaf.
    EVCCPersonality.model_validate(
        {
            "capabilities": {"supported_protocols": ["ISO_15118_20_AC"]},
            "message_field_tree": {
                "ISO_15118_20_AC": {
                    "ACChargeParameterDiscoveryReq": {
                        "AC_CPDReqEnergyTransferMode": {
                            "EVMaximumChargePower": {"Exponent": 0, "Value": 12000},
                        }
                    }
                }
            },
        }
    )


def test_incomplete_iso2_evcc_subtree_fails_now_that_iso2_evcc_is_tree_backed():
    # ISO-2 is tree-backed for the EVCC (#97): a present-but-incomplete ISO-2
    # subtree (a CableCheckReq missing the required, config-only EVRESSSOC) trips
    # the completeness gate. EVReady / EVErrorCode are allowlisted (runtime-
    # produced), so dropping them would NOT fail — EVRESSSOC is the config leaf.
    with pytest.raises(
        ValidationError,
        match="ISO_15118_2 -> CableCheckReq -> dc_ev_status -> ev_ress_soc",
    ):
        EVCCPersonality.model_validate(
            {
                "capabilities": {"supported_protocols": ["ISO_15118_2"]},
                "message_field_tree": {
                    "ISO_15118_2": {
                        "CableCheckReq": {"DC_EVStatus": {"EVReady": True}}
                    }
                },
            }
        )
