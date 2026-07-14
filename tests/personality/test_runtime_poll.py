"""The ONGOING poll interval is a runtime knob, not a personality field (#88).

Pacing the EVCC's ONGOING re-send loops is a per-invocation operational
decision (how hard this run leans on the link), not part of *who the emulated
device is* — so per ADR-0001 it lives in `runtime.yaml` / a CLI flag and is
deliberately absent from the personality model.
"""

from __future__ import annotations

import argparse
import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.shared.personality import (
    EVCCPersonality,
    Runtime,
    add_runtime_cli_args,
    apply_runtime_overrides,
    load_runtime,
)


def _parse(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_runtime_cli_args(parser)
    return parser.parse_args(["--config", "default-evcc", *argv])


def test_default_interval_is_a_modest_positive_cadence():
    """A sane default: paced out of the box, no opt-in needed."""
    assert Runtime().poll.ongoing_interval_seconds == 1.0


def test_runtime_yaml_sets_the_interval(tmp_path: Path):
    path = tmp_path / "runtime.yaml"
    path.write_text(
        textwrap.dedent(
            """
            poll:
              ongoing_interval_seconds: 0.25
            """
        )
    )
    assert load_runtime(str(path)).poll.ongoing_interval_seconds == 0.25


def test_poll_interval_flag():
    args = _parse(["--poll-interval", "0.2"])
    assert apply_runtime_overrides(Runtime(), args).poll.ongoing_interval_seconds == 0.2


def test_absent_flag_leaves_runtime_yaml_untouched():
    runtime = Runtime(poll={"ongoing_interval_seconds": 0.25})
    args = _parse([])  # no --poll-interval
    assert apply_runtime_overrides(runtime, args).poll.ongoing_interval_seconds == 0.25


def test_zero_disables_pacing():
    """0 s is legal — it restores the un-paced hot re-send for red-team probing."""
    runtime = Runtime(poll={"ongoing_interval_seconds": 0})
    assert runtime.poll.ongoing_interval_seconds == 0


def test_negative_interval_is_rejected():
    with pytest.raises(ValidationError):
        Runtime(poll={"ongoing_interval_seconds": -1})


def test_not_a_personality_field():
    """ADR-0001: personality is never an operational knob (and is strict)."""
    with pytest.raises(ValidationError):
        EVCCPersonality.model_validate({"poll": {"ongoing_interval_seconds": 1.0}})
