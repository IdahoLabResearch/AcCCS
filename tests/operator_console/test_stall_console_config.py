"""Runtime config + CLI plumbing for stall arming and console mode (ADR-0004)."""

from __future__ import annotations

import argparse
import textwrap
from pathlib import Path

from app.shared.personality import (
    Runtime,
    add_runtime_cli_args,
    apply_runtime_overrides,
    load_runtime,
)


def _parse(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_runtime_cli_args(parser)
    return parser.parse_args(["--config", "default-evcc", *argv])


# -- model defaults / YAML --------------------------------------------------


def test_defaults():
    r = Runtime()
    assert r.stall.charge_loop is False
    assert r.stall.authorization is False
    assert r.console.mode == "auto"
    assert r.rearm.auto is False  # auto-rearm is opt-in (ADR-0005)


def test_runtime_yaml_arms_stall(tmp_path: Path):
    path = tmp_path / "runtime.yaml"
    path.write_text(
        textwrap.dedent(
            """
            stall:
              charge_loop: true
              authorization: true
            console:
              mode: off
            """
        )
    )
    r = load_runtime(str(path))
    assert r.stall.charge_loop is True
    assert r.stall.authorization is True
    assert r.console.mode == "off"


# -- CLI flags --------------------------------------------------------------


def test_stall_charge_loop_flag():
    args = _parse(["--stall-charge-loop"])
    assert args.stall_charge_loop is True
    overridden = apply_runtime_overrides(Runtime(), args)
    assert overridden.stall.charge_loop is True


def test_stall_authorization_flag():
    args = _parse(["--stall-authorization"])
    assert args.stall_authorization is True
    overridden = apply_runtime_overrides(Runtime(), args)
    assert overridden.stall.authorization is True


# -- auto-rearm (ADR-0005, issue #43) ---------------------------------------


def test_runtime_yaml_enables_auto_rearm(tmp_path: Path):
    path = tmp_path / "runtime.yaml"
    path.write_text(
        textwrap.dedent(
            """
            rearm:
              auto: true
            """
        )
    )
    assert load_runtime(str(path)).rearm.auto is True


def test_auto_rearm_flag():
    args = _parse(["--auto-rearm"])
    assert args.auto_rearm is True
    assert apply_runtime_overrides(Runtime(), args).rearm.auto is True


def test_cli_auto_rearm_overrides_runtime_yaml():
    """CLI --auto-rearm flips on a runtime that left it off."""
    args = _parse(["--auto-rearm"])
    assert apply_runtime_overrides(Runtime(), args).rearm.auto is True


def test_absent_auto_rearm_flag_leaves_runtime_untouched():
    """argparse defaults --auto-rearm to None, so a runtime.yaml value survives."""
    runtime = Runtime(rearm={"auto": True})
    args = _parse([])  # no --auto-rearm
    assert apply_runtime_overrides(runtime, args).rearm.auto is True


def test_no_console_flag():
    args = _parse(["--no-console"])
    assert args.console_mode == "off"
    assert apply_runtime_overrides(Runtime(), args).console.mode == "off"


def test_console_flag():
    args = _parse(["--console"])
    assert args.console_mode == "on"
    assert apply_runtime_overrides(Runtime(), args).console.mode == "on"


def test_cli_overrides_runtime_yaml_stall():
    """CLI --stall-charge-loop overrides a runtime.yaml that left it off."""
    runtime = Runtime()  # stall.charge_loop False
    args = _parse(["--stall-charge-loop"])
    assert apply_runtime_overrides(runtime, args).stall.charge_loop is True


def test_absent_flags_leave_runtime_untouched():
    runtime = Runtime(
        stall={"charge_loop": True, "authorization": True}, console={"mode": "on"}
    )
    args = _parse([])  # no console/stall flags
    overridden = apply_runtime_overrides(runtime, args)
    # argparse defaults the new flags to None, so the runtime values survive.
    assert overridden.stall.charge_loop is True
    assert overridden.stall.authorization is True
    assert overridden.console.mode == "on"
