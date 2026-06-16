"""Personality + Runtime model behavior tests.

These tests target the contract spelled out in ADR-0001 and issue #6:

- Strict validation — unknown fields raise.
- Concern-first sections — identity, network, slac, tls, capabilities,
  power, charge_profile, certificates.
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
        EVCCPersonality.model_validate({"identity": {"evcc_id": "1FMVAA45B63C47DD58Y6"}, "bogus": 1})


def test_evcc_rejects_unknown_section_field():
    with pytest.raises(ValidationError):
        EVCCPersonality.model_validate(
            {"identity": {"evcc_id": "x", "made_up_field": 1}}
        )


def test_secc_rejects_unknown_top_level_field():
    with pytest.raises(ValidationError):
        SECCPersonality.model_validate({"identity": {"evse_id": "USFRDE8326"}, "junk": True})


# ---------------------------------------------------------------------------
# Defaults are wholly material — every section must instantiate from {}
# ---------------------------------------------------------------------------


def test_evcc_personality_constructs_from_empty_dict():
    """All fields have defaults so an empty YAML still validates."""
    p = EVCCPersonality.model_validate({})
    assert p.identity.evcc_id  # the EVCC id default is non-empty
    assert p.network.interface  # interface has a default


def test_secc_personality_constructs_from_empty_dict():
    p = SECCPersonality.model_validate({})
    assert p.identity.evse_id
    assert p.network.interface


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
