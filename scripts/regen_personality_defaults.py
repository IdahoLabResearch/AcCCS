#!/usr/bin/env python3
"""Regenerate `personalities/default-{evcc,secc}.yaml` from model defaults.

Per ADR-0001 the YAML is the canonical artifact a user reads to discover
"what knobs exist?" but the model is the single source of truth for default
values. This script materialises the model defaults back into YAML so
authoring stays one-way (model → YAML) and the drift test catches mismatches.

Usage:

    python scripts/regen_personality_defaults.py
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402

from app.shared.personality.model import EVCCPersonality, SECCPersonality  # noqa: E402


HEADER = """\
# Stock {role} personality.
#
# This file is *generated* from the Pydantic defaults in
# `app/shared/personality/model.py` by
# `scripts/regen_personality_defaults.py`. Edit the model, then rerun the
# script. The drift test (tests/personality/test_drift.py) guards against
# this file falling out of sync.
#
# See ADR-0001 for the personality concept and section breakdown.
"""


def _dump(model_cls, role: str, path: Path) -> None:
    payload = model_cls().model_dump(mode="json")
    text = HEADER.format(role=role.upper())
    text += yaml.safe_dump(payload, sort_keys=False, indent=2)
    path.write_text(text)
    print(f"wrote {path}")


def main() -> int:
    out = REPO_ROOT / "personalities"
    out.mkdir(exist_ok=True)
    _dump(EVCCPersonality, "evcc", out / "default-evcc.yaml")
    _dump(SECCPersonality, "secc", out / "default-secc.yaml")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
