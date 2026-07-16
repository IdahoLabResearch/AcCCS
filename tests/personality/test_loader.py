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
    format_personality_listing,
    list_available_personalities,
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
        "residual:\n  network:\n    interface: from-repo\n"
    )

    explicit = tmp_path / "explicit.yaml"
    explicit.write_text("residual:\n  network:\n    interface: from-explicit\n")

    p = load_personality(str(explicit), role="evcc")
    assert p.residual.network.interface == "from-explicit"


def test_repo_directory_searched_when_name_is_bare(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "personalities").mkdir()
    (tmp_path / "personalities" / "marker.yaml").write_text(
        "residual:\n  network:\n    interface: from-repo\n"
    )

    p = load_personality("marker", role="evcc")
    assert p.residual.network.interface == "from-repo"


def test_user_local_searched_when_repo_misses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.chdir(tmp_path)
    fake_home = tmp_path / "home"
    user_dir = fake_home / ".acccs" / "personalities"
    user_dir.mkdir(parents=True)
    (user_dir / "private.yaml").write_text(
        "residual:\n  network:\n    interface: from-user\n"
    )

    # Patch the constants since they're captured at import. The loader uses
    # the module-level paths directly.
    monkeypatch.setattr(
        "app.shared.personality.loader.USER_PERSONALITIES", user_dir
    )

    p = load_personality("private", role="evcc")
    assert p.residual.network.interface == "from-user"


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
    path.write_text("role: secc\nresidual:\n  network:\n    interface: x\n")
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


# ---------------------------------------------------------------------------
# list_available_personalities + format_personality_listing
# ---------------------------------------------------------------------------


def _setup_dirs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    repo_files: dict[str, str],
    user_files: dict[str, str],
) -> tuple[Path, Path]:
    """Create fake repo + user-local dirs, monkeypatch the module constants."""
    repo_dir = tmp_path / "personalities"
    user_dir = tmp_path / "user" / ".acccs" / "personalities"
    repo_dir.mkdir(parents=True)
    user_dir.mkdir(parents=True)
    for name, content in repo_files.items():
        (repo_dir / name).write_text(content)
    for name, content in user_files.items():
        (user_dir / name).write_text(content)
    monkeypatch.setattr("app.shared.personality.loader.REPO_PERSONALITIES", repo_dir)
    monkeypatch.setattr("app.shared.personality.loader.USER_PERSONALITIES", user_dir)
    return repo_dir, user_dir


def test_list_repo_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _setup_dirs(
        tmp_path,
        monkeypatch,
        repo_files={"evcc-a.yaml": "role: evcc\n", "secc-b.yaml": "role: secc\n"},
        user_files={},
    )
    entries = list_available_personalities()
    assert len(entries) == 2
    names = [e.name for e in entries]
    assert "evcc-a" in names
    assert "secc-b" in names
    by_name = {e.name: e for e in entries}
    assert by_name["evcc-a"].source == "repo"
    assert by_name["evcc-a"].role == "evcc"
    assert by_name["evcc-a"].shadowed is False
    assert by_name["secc-b"].role == "secc"


def test_list_user_local_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _setup_dirs(
        tmp_path,
        monkeypatch,
        repo_files={},
        user_files={"custom.yaml": "role: secc\n"},
    )
    entries = list_available_personalities()
    assert len(entries) == 1
    assert entries[0].name == "custom"
    assert entries[0].source == "user-local"
    assert entries[0].role == "secc"
    assert entries[0].shadowed is False


def test_list_no_role_field(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _setup_dirs(
        tmp_path,
        monkeypatch,
        repo_files={"no-role.yaml": "residual:\n  network:\n    interface: x\n"},
        user_files={},
    )
    entries = list_available_personalities()
    assert entries[0].role == "none"


def test_list_shadowing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A user-local file with the same stem as a repo file is marked shadowed."""
    _setup_dirs(
        tmp_path,
        monkeypatch,
        repo_files={"shared.yaml": "role: evcc\n"},
        user_files={
            "shared.yaml": "role: evcc\n",  # same name — shadows repo
            "unique.yaml": "role: secc\n",  # different name — not shadowed
        },
    )
    entries = list_available_personalities()
    by_source = {(e.name, e.source): e for e in entries}

    repo_entry = by_source[("shared", "repo")]
    assert repo_entry.shadowed is False

    user_shared = by_source[("shared", "user-local")]
    assert user_shared.shadowed is True

    user_unique = by_source[("unique", "user-local")]
    assert user_unique.shadowed is False


def test_list_empty_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _setup_dirs(tmp_path, monkeypatch, repo_files={}, user_files={})
    assert list_available_personalities() == []


def test_format_listing_includes_all_fields(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _setup_dirs(
        tmp_path,
        monkeypatch,
        repo_files={"my-evcc.yaml": "role: evcc\n"},
        user_files={"my-evcc.yaml": "role: evcc\n"},
    )
    output = format_personality_listing(list_available_personalities())
    assert "my-evcc" in output
    assert "repo" in output
    assert "user-local" in output
    assert "evcc" in output
    assert "shadowed" in output


def test_format_listing_no_personalities():
    assert format_personality_listing([]) == "No personalities found."


# ---------------------------------------------------------------------------
# Layered baseline + sparse device overrides (ADR-0006 `extends:`)
# ---------------------------------------------------------------------------


def _write_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, files: dict):
    monkeypatch.chdir(tmp_path)
    repo = tmp_path / "personalities"
    repo.mkdir(exist_ok=True)
    for name, text in files.items():
        (repo / name).write_text(textwrap.dedent(text))


def test_extends_deep_merges_baseline(tmp_path, monkeypatch):
    """A device file `extends:` a baseline; unspecified leaves come from the
    baseline, specified leaves win."""
    _write_repo(
        tmp_path,
        monkeypatch,
        {
            "base-secc.yaml": """
                role: secc
                residual:
                  metering:
                    starting_reading_wh: 1000
                  tls:
                    enable_tls_1_3: false
                capabilities:
                  supported_protocols:
                    - DIN_SPEC_70121
                """,
            "device-secc.yaml": """
                extends: base-secc
                role: secc
                residual:
                  metering:
                    starting_reading_wh: 99
                """,
        },
    )
    p = load_personality("device-secc", role="secc")
    assert p.residual.metering.starting_reading_wh == 99  # device override
    assert p.capabilities.supported_protocols == ["DIN_SPEC_70121"]  # from baseline
    assert p.residual.tls.enable_tls_1_3 is False  # from baseline


def test_extends_sparse_tree_override_equals_full_tree(tmp_path, monkeypatch):
    """AC #4: a baseline tree plus a sparse device leaf override produces the
    same effective message field tree as spelling the whole tree out."""
    _write_repo(
        tmp_path,
        monkeypatch,
        {
            "tree-base-secc.yaml": """
                role: secc
                message_field_tree:
                  DIN_SPEC_70121:
                    ServiceDiscoveryRes:
                      PaymentOptions:
                        PaymentOption:
                          - ExternalPayment
                      ChargeService:
                        ServiceTag:
                          ServiceID: 1
                          ServiceCategory: EVCharging
                        FreeService: false
                        EnergyTransferType: DC_extended
                    ChargeParameterDiscoveryRes:
                      DC_EVSEChargeParameter:
                        DC_EVSEStatus:
                          EVSEIsolationStatus: Valid
                """,
            # Overrides only the isolation leaf; the energy-transfer leaf is
            # inherited from the baseline.
            "tree-device-secc.yaml": """
                extends: tree-base-secc
                role: secc
                message_field_tree:
                  DIN_SPEC_70121:
                    ChargeParameterDiscoveryRes:
                      DC_EVSEChargeParameter:
                        DC_EVSEStatus:
                          EVSEIsolationStatus: Invalid
                """,
            # The same effective tree, spelled out in full.
            "tree-full-secc.yaml": """
                role: secc
                message_field_tree:
                  DIN_SPEC_70121:
                    ServiceDiscoveryRes:
                      PaymentOptions:
                        PaymentOption:
                          - ExternalPayment
                      ChargeService:
                        ServiceTag:
                          ServiceID: 1
                          ServiceCategory: EVCharging
                        FreeService: false
                        EnergyTransferType: DC_extended
                    ChargeParameterDiscoveryRes:
                      DC_EVSEChargeParameter:
                        DC_EVSEStatus:
                          EVSEIsolationStatus: Invalid
                """,
        },
    )
    layered = load_personality("tree-device-secc", role="secc")
    full = load_personality("tree-full-secc", role="secc")
    assert layered.message_field_tree == full.message_field_tree


def test_extends_key_is_stripped_not_a_model_field(tmp_path, monkeypatch):
    """`extends` is a loader directive, not a strict-model field: a device with
    only an `extends` line loads without an 'extra field' error."""
    _write_repo(
        tmp_path,
        monkeypatch,
        {
            "b.yaml": "role: evcc\nresidual:\n  network:\n    interface: FROMBASE\n",
            "d.yaml": "extends: b\nrole: evcc\n",
        },
    )
    p = load_personality("d", role="evcc")
    assert p.residual.network.interface == "FROMBASE"
    assert not hasattr(p, "extends")


def test_circular_extends_raises(tmp_path, monkeypatch):
    _write_repo(
        tmp_path,
        monkeypatch,
        {
            "a.yaml": "extends: b\nrole: evcc\n",
            "b.yaml": "extends: a\nrole: evcc\n",
        },
    )
    with pytest.raises(ValueError, match="circular"):
        load_personality("a", role="evcc")
