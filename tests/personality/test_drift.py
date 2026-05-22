"""Drift test: model defaults must match `personalities/default-*.yaml`.

Per ADR-0001:

> Defaults live in the Pydantic model (single source of truth);
> `default.yaml` is a generated/maintained mirror.

If this test fails, regenerate the YAML via
`python scripts/regen_personality_defaults.py` (do *not* hand-edit the YAML
to make the test pass — the model is the source of truth).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.shared.personality.model import EVCCPersonality, SECCPersonality

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "model_cls, yaml_name",
    [
        (EVCCPersonality, "default-evcc.yaml"),
        (SECCPersonality, "default-secc.yaml"),
    ],
)
def test_default_yaml_matches_model_defaults(model_cls, yaml_name):
    path = REPO_ROOT / "personalities" / yaml_name
    assert path.exists(), (
        f"{path} is missing. Run `python scripts/regen_personality_defaults.py`."
    )

    yaml_data = yaml.safe_load(path.read_text())
    yaml_model = model_cls.model_validate(yaml_data)
    default_model = model_cls()

    assert yaml_model.model_dump() == default_model.model_dump(), (
        f"{yaml_name} has drifted from model defaults — regenerate via "
        f"scripts/regen_personality_defaults.py"
    )
