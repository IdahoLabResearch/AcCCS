"""Loader + CLI-override behavior tests."""

from __future__ import annotations

import argparse
import textwrap
from pathlib import Path

import pytest

from app.shared.personality.loader import (
    PersonalityNotFoundError,
    REPO_PERSONALITIES,
    USER_PERSONALITIES,
    apply_runtime_overrides,
    load_personality,
    load_runtime,
)
from app.shared.personality.model import Runtime


# ---------------------------------------------------------------------------
# Three-tier search
# ---------------------------------------------------------------------------


def test_explicit_path_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "personalities").mkdir()
    (tmp_path / "personalities" / "marker.yaml").write_text(
        "identity:\n  evcc_id: from-repo\n"
    )

    explicit = tmp_path / "explicit.yaml"
    explicit.write_text("identity:\n  evcc_id: from-explicit\n")

    p = load_personality(str(explicit), role="evcc")
    assert p.identity.evcc_id == "from-explicit"


def test_repo_directory_searched_when_name_is_bare(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "personalities").mkdir()
    (tmp_path / "personalities" / "marker.yaml").write_text(
        "identity:\n  evcc_id: from-repo\n"
    )

    p = load_personality("marker", role="evcc")
    assert p.identity.evcc_id == "from-repo"


def test_user_local_searched_when_repo_misses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.chdir(tmp_path)
    fake_home = tmp_path / "home"
    user_dir = fake_home / ".acccs" / "personalities"
    user_dir.mkdir(parents=True)
    (user_dir / "private.yaml").write_text("identity:\n  evcc_id: from-user\n")

    # Patch the constants since they're captured at import. The loader uses
    # the module-level paths directly.
    monkeypatch.setattr(
        "app.shared.personality.loader.USER_PERSONALITIES", user_dir
    )

    p = load_personality("private", role="evcc")
    assert p.identity.evcc_id == "from-user"


def test_missing_personality_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "app.shared.personality.loader.USER_PERSONALITIES",
        tmp_path / "no-such-dir",
    )
    with pytest.raises(PersonalityNotFoundError):
        load_personality("does-not-exist", role="evcc")


# ---------------------------------------------------------------------------
# Role guard
# ---------------------------------------------------------------------------


def test_role_mismatch_raises(tmp_path: Path):
    path = tmp_path / "p.yaml"
    path.write_text("role: secc\nidentity:\n  evcc_id: x\n")
    with pytest.raises(ValueError, match="role"):
        load_personality(str(path), role="evcc")


# ---------------------------------------------------------------------------
# Runtime + CLI merge
# ---------------------------------------------------------------------------


def test_runtime_defaults_when_path_is_none():
    r = load_runtime(None)
    assert r.virtual is False
    assert r.log.console_level == "INFO"


def test_runtime_yaml_overrides_defaults(tmp_path: Path):
    path = tmp_path / "runtime.yaml"
    path.write_text(
        textwrap.dedent(
            """
            virtual: true
            log:
              console_level: DEBUG
            """
        )
    )
    r = load_runtime(str(path))
    assert r.virtual is True
    assert r.log.console_level == "DEBUG"
    # file_level must still come from the model default
    assert r.log.file_level == "DEBUG"


def test_cli_overrides_runtime():
    runtime = Runtime(virtual=False)
    args = argparse.Namespace(
        virtual=True,
        log_level="WARNING",
        file_log_level=None,
        nmap_enabled=None,
        nmap_args=None,
        nmap_ports=None,
        source_port=12345,
        modified_cordset=None,
        message_log_json=None,
        message_log_exi=None,
    )
    overridden = apply_runtime_overrides(runtime, args)
    assert overridden.virtual is True
    assert overridden.log.console_level == "WARNING"
    assert overridden.source_port == 12345
