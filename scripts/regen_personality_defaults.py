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

from app.shared.personality.model import (  # noqa: E402
    EVCCPersonality,
    SECCPersonality,
    no_tls_personality,
)


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

NO_TLS_HEADER = """\
# Cert-free "smoke" {role} personality (issue #23).
#
# Identical to the stock `default-{role_lower}.yaml` except for two sections:
# `tls:` disables encryption, and `capabilities.supported_protocols` drops the
# ISO 15118-20 entries (they mandate TLS 1.3, so the loader refuses to start a
# -20 session without it). This lets a fresh clone run the virtual EVCC <->
# SECC demo without first generating PKI certs via `create_certs.sh`. The
# cert-enabled stock default remains the realistic-testing path.
#
# This file is *generated* from the Pydantic defaults plus the `NO_TLS`
# posture in `app/shared/personality/model.py` by
# `scripts/regen_personality_defaults.py`. Edit the model, then rerun the
# script. The drift test (tests/personality/test_drift.py) guards against
# this file falling out of sync.
#
# See ADR-0001 for the personality concept and section breakdown.
"""


def _dump(model, header: str, role: str, path: Path) -> None:
    payload = model.model_dump(mode="json")
    text = header.format(role=role.upper(), role_lower=role.lower())
    text += yaml.safe_dump(payload, sort_keys=False, indent=2)
    path.write_text(text)
    print(f"wrote {path}")


def main() -> int:
    out = REPO_ROOT / "personalities"
    out.mkdir(exist_ok=True)
    _dump(EVCCPersonality(), HEADER, "evcc", out / "default-evcc.yaml")
    _dump(SECCPersonality(), HEADER, "secc", out / "default-secc.yaml")
    _dump(
        no_tls_personality(EVCCPersonality),
        NO_TLS_HEADER,
        "evcc",
        out / "default-no-tls-evcc.yaml",
    )
    _dump(
        no_tls_personality(SECCPersonality),
        NO_TLS_HEADER,
        "secc",
        out / "default-no-tls-secc.yaml",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
