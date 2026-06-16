"""YAML loader + CLI override merger for personalities and runtime.

Per ADR-0001 the personality search order is:

1. Explicit `--config <path>` (or `--runtime <path>`).
2. `personalities/<name>.yaml` in the repo (relative to CWD).
3. `~/.acccs/personalities/<name>.yaml` user-local.

That order lets proprietary device personalities live outside the repo
without forking AcCCS, while keeping the repo's bundled defaults the obvious
starting point.

For runtime: defaults (from the model) → optional `runtime.yaml` →
argparse-derived overrides. Personality fields are *not* CLI-overridable;
the CLI builder simply never constructs flags for them.
"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Type, TypeVar

import yaml

from app.shared.personality.model import (
    EVCCPersonality,
    Runtime,
    SECCPersonality,
    _PersonalityBase,
)

P = TypeVar("P", bound=_PersonalityBase)

REPO_PERSONALITIES = Path("personalities")
USER_PERSONALITIES = Path.home() / ".acccs" / "personalities"


@dataclass
class PersonalityInfo:
    """Metadata for one discovered personality file."""

    name: str
    path: Path
    source: str   # "repo" or "user-local"
    role: str     # "evcc", "secc", or "none"
    shadowed: bool  # True: user-local entry eclipsed by same-name repo entry


class PersonalityNotFoundError(FileNotFoundError):
    """Raised when no personality file is found under the search order."""


def _resolve(name_or_path: str) -> Path:
    """Apply the three-tier search to `name_or_path`.

    If `name_or_path` is an existing file path, return it as-is (tier 1).
    Otherwise treat it as a bare name and look it up under
    `personalities/` then `~/.acccs/personalities/`.
    """
    candidate = Path(name_or_path)
    if candidate.is_file():
        return candidate

    # Tier 2: repo-local personalities/<name>.yaml. Accept either a bare
    # name ("default-evcc") or a name with extension ("default-evcc.yaml")
    # so the CLI is forgiving.
    for suffix in ("", ".yaml", ".yml"):
        repo_path = REPO_PERSONALITIES / f"{name_or_path}{suffix}"
        if repo_path.is_file():
            return repo_path

    # Tier 3: user-local override.
    for suffix in ("", ".yaml", ".yml"):
        user_path = USER_PERSONALITIES / f"{name_or_path}{suffix}"
        if user_path.is_file():
            return user_path

    raise PersonalityNotFoundError(
        f"No personality file for {name_or_path!r}. Searched: "
        f"explicit path, {REPO_PERSONALITIES}/, {USER_PERSONALITIES}/."
    )


def _load_yaml(path: Path) -> dict:
    with path.open("r") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level YAML must be a mapping, got {type(data).__name__}")
    return data


def _peek_role(path: Path) -> str:
    """Return the `role` field from a personality YAML without full validation."""
    try:
        return str(_load_yaml(path).get("role") or "none")
    except Exception:
        return "none"


def list_available_personalities() -> List[PersonalityInfo]:
    """Return annotated metadata for every discoverable personality file.

    Scans `personalities/` (repo) then `~/.acccs/personalities/` (user-local).
    Both directories are searched regardless of which run script is calling.
    A user-local file whose stem matches a repo file is marked `shadowed=True`
    because `_resolve()` prefers the repo copy — the opposite of the usual
    user-local-overrides-repo convention.
    """
    entries: List[PersonalityInfo] = []

    repo_stems: set[str] = set()
    if REPO_PERSONALITIES.is_dir():
        for path in sorted(REPO_PERSONALITIES.iterdir()):
            if path.suffix in (".yaml", ".yml"):
                stem = path.stem
                repo_stems.add(stem)
                entries.append(PersonalityInfo(
                    name=stem,
                    path=path,
                    source="repo",
                    role=_peek_role(path),
                    shadowed=False,
                ))

    if USER_PERSONALITIES.is_dir():
        for path in sorted(USER_PERSONALITIES.iterdir()):
            if path.suffix in (".yaml", ".yml"):
                stem = path.stem
                entries.append(PersonalityInfo(
                    name=stem,
                    path=path,
                    source="user-local",
                    role=_peek_role(path),
                    shadowed=stem in repo_stems,
                ))

    return entries


def format_personality_listing(entries: List[PersonalityInfo]) -> str:
    """Format a `list_available_personalities()` result for terminal output."""
    if not entries:
        return "No personalities found."

    name_w = max(len(e.name) for e in entries)
    src_w = max(len(e.source) for e in entries)

    lines = ["Available personalities:", ""]
    for e in entries:
        note = "  [shadowed — repo copy loads]" if e.shadowed else ""
        lines.append(f"  {e.name:<{name_w}}  {e.source:<{src_w}}  {e.role}{note}")
    return "\n".join(lines)


def load_personality(name_or_path: str, role: str) -> _PersonalityBase:
    """Resolve + parse a personality YAML for the given role.

    `role` is the role of the run script invoking the loader (`"evcc"` or
    `"secc"`). The YAML may or may not include a `role:` field — if it
    does, it must match. This catches "loaded the SECC personality into the
    EVCC by accident" mistakes early.
    """
    path = _resolve(name_or_path)
    data = _load_yaml(path)

    yaml_role = data.get("role")
    if yaml_role is not None and yaml_role != role:
        raise ValueError(
            f"{path}: personality declares role={yaml_role!r} but this "
            f"process is the {role!r} side"
        )

    model_cls: Type[_PersonalityBase]
    if role == "evcc":
        model_cls = EVCCPersonality
    elif role == "secc":
        model_cls = SECCPersonality
    else:
        raise ValueError(f"unknown role {role!r}; expected 'evcc' or 'secc'")

    return model_cls.model_validate(data)


def load_runtime(path_or_none: Optional[str]) -> Runtime:
    """Load a runtime.yaml or return defaults.

    Unlike personalities, runtime is fully optional — passing `None` is the
    common case and just yields the model defaults.
    """
    if path_or_none is None:
        return Runtime()
    return Runtime.model_validate(_load_yaml(Path(path_or_none)))


# ---------------------------------------------------------------------------
# CLI override application
# ---------------------------------------------------------------------------


_CLI_FIELD_MAP = {
    # argparse dest -> dotted Runtime field path
    "virtual": "virtual",
    "log_level": "log.console_level",
    "file_log_level": "log.file_level",
    "nmap_enabled": "nmap.enabled",
    "nmap_args": "nmap.args",
    "nmap_ports": "nmap.ports",
    "source_port": "source_port",
    "modified_cordset": "modified_cordset",
    "message_log_json": "log.message_log_json",
    "message_log_exi": "log.message_log_exi",
    # Operator console + stall arming (ADR-0004).
    "stall_charge_loop": "stall.charge_loop",
    "stall_authorization": "stall.authorization",
    "console_mode": "console.mode",
    # Auto-rearm (ADR-0005).
    "auto_rearm": "rearm.auto",
}


def apply_runtime_overrides(runtime: Runtime, args: argparse.Namespace) -> Runtime:
    """Return a new Runtime with non-None argparse fields overlaid.

    Builds a dict from the runtime, walks `_CLI_FIELD_MAP`, and overlays any
    CLI value that the user actually supplied (i.e. not `None` — argparse
    leaves unprovided fields as None when default=None). Re-validates so
    the result is still strict-checked.
    """
    data = runtime.model_dump()
    for dest, dotted in _CLI_FIELD_MAP.items():
        value = getattr(args, dest, None)
        if value is None:
            continue
        cursor = data
        parts = dotted.split(".")
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[parts[-1]] = value
    return Runtime.model_validate(data)


def add_runtime_cli_args(parser: argparse.ArgumentParser) -> None:
    """Attach the runtime-overriding flags to a parser.

    Personality fields deliberately have no flags — ADR-0001 promises that
    personality is not CLI-overridable. Any historical EVCC/SECC flag that
    set a personality field (e.g. `--protocols`, `--useTLS`,
    `--slacSoundTimeout`) has been removed; authoring a custom personality
    file is the new path.
    """
    parser.add_argument(
        "--config",
        default="din_reference",
        help="Personality file (name or path); defaults to the DIN reference personality",
    )
    parser.add_argument(
        "--list-configs",
        dest="list_configs",
        action="store_true",
        default=False,
        help=(
            "Print all discoverable personalities (repo + user-local) with their "
            "source and declared role, then exit 0"
        ),
    )
    parser.add_argument("--runtime", default=None, help="Optional runtime.yaml path")

    parser.add_argument(
        "--log-level",
        dest="log_level",
        default=None,
        help="Console log level (overrides runtime.log.console_level)",
    )
    parser.add_argument(
        "--file-log-level",
        dest="file_log_level",
        default=None,
        help="File log level (overrides runtime.log.file_level)",
    )
    parser.add_argument(
        "--virtual",
        dest="virtual",
        action="store_true",
        default=None,
        help="Run in virtual mode (no SMBus / I2C relays)",
    )
    parser.add_argument(
        "--nmap",
        dest="nmap_enabled",
        action="store_true",
        default=None,
        help="Enable NMAP probing",
    )
    parser.add_argument(
        "--nmap-args",
        dest="nmap_args",
        default=None,
        help="NMAP argument string",
    )
    parser.add_argument(
        "--nmap-ports",
        dest="nmap_ports",
        default=None,
        help="NMAP port spec",
    )
    parser.add_argument(
        "--source-port",
        dest="source_port",
        type=int,
        default=None,
        help="Override TCP source port (operational)",
    )
    parser.add_argument(
        "--capture",
        dest="capture",
        default=None,
        help=(
            "Append EXI codec records to this JSONL path. Off by default. "
            "Use this (not env vars) when running under sudo, which strips "
            "ACCCS_EXI_CAPTURE on the dev box."
        ),
    )
    parser.add_argument(
        "--modified-cordset",
        dest="modified_cordset",
        action="store_true",
        default=None,
        help="SECC: enable modified-cordset behaviour for hardware testing",
    )

    # Operator console + stall arming (ADR-0004). These are runtime knobs, so
    # they get CLI flags; stall arming via CLI overrides runtime.yaml.
    parser.add_argument(
        "--stall-charge-loop",
        dest="stall_charge_loop",
        action="store_true",
        default=None,
        help=(
            "EVCC: arm the charge-loop stall — hold the ISO 15118-2 DC "
            "CurrentDemand loop open until released via the console [a]dvance"
        ),
    )
    parser.add_argument(
        "--stall-authorization",
        dest="stall_authorization",
        action="store_true",
        default=None,
        help=(
            "SECC: arm the authorization stall — hold the ISO 15118-2 "
            "Authorization gate (EVSEProcessing=ONGOING) until released via "
            "the console [a]dvance"
        ),
    )
    # Auto-rearm (ADR-0005). A runtime knob like the stall flags: off by
    # default, CLI-overridable, never a personality field. The live `r`
    # console key toggles it mid-run.
    parser.add_argument(
        "--auto-rearm",
        dest="auto_rearm",
        action="store_true",
        default=None,
        help=(
            "Re-arm automatically after each session cycle instead of waiting "
            "for the console [a]dvance; with both sides set, cycle sessions "
            "continuously until quit (the EVCC paces itself between cycles)"
        ),
    )
    # --console / --no-console both write console.mode. argparse keeps the last
    # one on the command line, so `--console --no-console` resolves to "off".
    parser.add_argument(
        "--console",
        dest="console_mode",
        action="store_const",
        const="on",
        default=None,
        help="Force the operator console on (warns + stays headless without a TTY)",
    )
    parser.add_argument(
        "--no-console",
        dest="console_mode",
        action="store_const",
        const="off",
        default=None,
        help="Suppress the operator console (run fully headless)",
    )
