"""Personality + Runtime configuration.

See ADR-0001 (`docs/adr/0001-personality-yaml-config.md`) for the design
rationale. The public surface:

- `EVCCPersonality`, `SECCPersonality` — strict pydantic models describing
  *who* the emulated device is. Loaded from YAML. Not CLI-overridable.
- `Runtime` — operational per-invocation knobs (logging, NMAP toggles,
  virtual mode). Loaded from optional YAML, then overridden by CLI flags.
- `load_personality` / `load_runtime` — the three-tier YAML loader.
- `apply_runtime_overrides` — applies argparse `Namespace` overrides onto a
  Runtime instance.
"""

from app.shared.personality.loader import (
    PersonalityNotFoundError,
    add_runtime_cli_args,
    apply_runtime_overrides,
    load_personality,
    load_runtime,
)
from app.shared.personality.model import (
    EVCCPersonality,
    Personality,
    Role,
    Runtime,
    SECCPersonality,
)

__all__ = [
    "EVCCPersonality",
    "SECCPersonality",
    "Personality",
    "Role",
    "Runtime",
    "load_personality",
    "load_runtime",
    "apply_runtime_overrides",
    "add_runtime_cli_args",
    "PersonalityNotFoundError",
]
