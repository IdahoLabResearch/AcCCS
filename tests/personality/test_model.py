"""Personality + Runtime model behavior tests.

These tests target the contract spelled out in ADR-0001 and issue #6:

- Strict validation — unknown fields raise.
- Two-part shape (ADR-0006) — the wire values live in `message_field_tree`;
  the residual/negotiation config is `capabilities` + `meter` at the top level
  plus a `residual` section (network, slac, tls, certificates, charge_profile,
  charge_ramp, behavior). The pre-tree `identity`/`power` sections are retired
  (#102): every emitted field is tree-sourced and the EV DC ramp seeds moved to
  `residual.charge_ramp`.
- Personality fields are not CLI-overridable; runtime fields are.
- `personalities/default-*.yaml` is a complete materialised dump and must
  stay in sync with the model defaults (drift test).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.shared.personality.model import (
    EVCCPersonality,
    Runtime,
    SECCPersonality,
)


# ---------------------------------------------------------------------------
# Strict validation
# ---------------------------------------------------------------------------


def test_evcc_rejects_unknown_top_level_field():
    with pytest.raises(ValidationError):
        EVCCPersonality.model_validate({"meter": {"meter_id": "M-1"}, "bogus": 1})


def test_evcc_rejects_unknown_section_field():
    with pytest.raises(ValidationError):
        EVCCPersonality.model_validate(
            {"capabilities": {"made_up_field": 1}}
        )


def test_secc_rejects_unknown_top_level_field():
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate({"meter": {"meter_id": "M-1"}, "junk": True})


def test_retired_identity_and_power_sections_are_rejected():
    """The pre-tree `identity`/`power` structured wire sections are deleted
    (#102): every emitted field is tree-sourced. Strict validation now rejects
    both keys on either role."""
    for section in ("identity", "power"):
        with pytest.raises(ValidationError):
            EVCCPersonality.model_validate({section: {}})
        with pytest.raises(ValidationError):
            SECCPersonality.model_validate({section: {}})


# ---------------------------------------------------------------------------
# Defaults are wholly material — every section must instantiate from {}
# ---------------------------------------------------------------------------


def test_evcc_personality_constructs_from_empty_dict():
    """All fields have defaults so an empty YAML still validates."""
    p = EVCCPersonality.model_validate({})
    assert p.residual.charge_ramp.target_current_a > 0  # DC ramp seed default
    assert p.residual.network.interface  # interface has a default (ADR-0006)


def test_secc_personality_constructs_from_empty_dict():
    p = SECCPersonality.model_validate({})
    assert p.capabilities.supported_protocols  # negotiation input default
    assert p.residual.network.interface


# ---------------------------------------------------------------------------
# Residual section (ADR-0006): non-wire config, strict, never duplicated
# ---------------------------------------------------------------------------


def test_residual_holds_non_wire_sections():
    """The residual section is the home for everything with no wire form:
    tls / slac / certificates / network / charge_profile / behavior."""
    p = SECCPersonality.model_validate({})
    r = p.residual
    assert r.tls.enable_tls_1_3 is True
    assert r.slac.sound_timeout_ms == 1000
    assert r.certificates.pki_path
    assert r.network.interface == "acccs_secc"
    assert r.charge_profile.cycle == 10
    assert r.behavior.use_cpo_backend is False


def test_residual_loads_strictly():
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate({"residual": {"tls": {"bogus": 1}}})
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate({"residual": {"not_a_section": {}}})


def test_use_cpo_backend_moved_from_capabilities_to_residual_behavior():
    """`use_cpo_backend` is a code-path switch (non-wire), so ADR-0006 moves it
    out of capabilities into residual.behavior — and it is no longer accepted
    under capabilities."""
    assert (
        "use_cpo_backend"
        not in SECCPersonality.model_validate({}).capabilities.model_dump()
    )
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate({"capabilities": {"use_cpo_backend": True}})
    p = SECCPersonality.model_validate(
        {"residual": {"behavior": {"use_cpo_backend": True}}}
    )
    assert p.residual.behavior.use_cpo_backend is True


def test_non_wire_sections_rejected_at_top_level():
    """The old flat top-level tls/slac/network/certificates keys are gone —
    they must live under residual now (never duplicated)."""
    for section in ("tls", "slac", "network", "certificates", "charge_profile"):
        with pytest.raises(ValidationError):
            SECCPersonality.model_validate({section: {}})


# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------


def test_runtime_constructs_from_empty_dict():
    r = Runtime.model_validate({})
    assert r.log.console_level
    assert r.virtual is False  # the framework-wide default per ADR-0001


def test_runtime_rejects_unknown_field():
    with pytest.raises(ValidationError):
        Runtime.model_validate({"surprise": "yes"})


def test_rearm_is_a_runtime_field_not_a_personality_field():
    """Auto-rearm is a runtime knob, never a personality field (ADR-0005).

    It must validate on Runtime but be rejected on either personality, the
    same contract the stall/console knobs hold.
    """
    assert Runtime.model_validate({"rearm": {"auto": True}}).rearm.auto is True
    with pytest.raises(ValidationError):
        EVCCPersonality.model_validate({"rearm": {"auto": True}})
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate({"rearm": {"auto": True}})
