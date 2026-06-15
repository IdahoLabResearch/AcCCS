"""Regression tests for ``app/shared/pki/create_certs.sh``.

These guard the bug fixed in #48: the ISO 15118-20 branch of the script set
``EC_CURVE=prime521r1``, which is not a valid OpenSSL curve name (the NIST
P-521 curve is spelled ``secp521r1`` in OpenSSL). Because the script has no
``set -e``, every ``openssl ecparam -genkey`` step failed silently and the
``cat …Cert.pem > …Chain.pem`` lines produced *empty* chain files — leaving
the ISO-20 certs directory with no usable cert material, so ISO 15118-20 TLS
conformance scenarios skipped for lack of certificates.

The script also used to assume the caller's working directory was the PKI
directory (relative ``configs/`` / ``iso15118_*/`` paths), so the repo-root
invocation documented in CLAUDE.md failed. It now ``cd``s to its own
directory at startup.

Each test copies the script and its ``configs/`` into a throwaway directory
and invokes it **from an unrelated working directory via an absolute path**,
so a regression in either the curve name or the run-from-anywhere behaviour
turns this red. The copy keeps the test hermetic — it never touches the
repo's real ``iso15118_*/certs`` trees.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

PKI_DIR = Path(__file__).resolve().parents[2] / "app" / "shared" / "pki"

# (version flag, output folder, expected OpenSSL curve name on the leaf cert)
_VERSIONS = [
    ("iso-2", "iso15118_2", "prime256v1"),
    ("iso-20", "iso15118_20", "secp521r1"),
]

# Files the script concatenates from per-cert outputs; an empty one is the
# tell-tale sign that the upstream key/cert generation silently failed.
_CHAIN_ARTIFACTS = [
    "cpoCertChain.pem",
    "oemCertChain.pem",
    "contractLeafCert.pem",
    "moCertChain.p12",
    "cpsCertChain.p12",
]


@pytest.fixture
def openssl() -> str:
    exe = shutil.which("openssl")
    if exe is None:
        pytest.skip("openssl not on PATH — required to generate/inspect certs")
    return exe


@pytest.fixture
def staged_pki(tmp_path: Path) -> Path:
    """Copy the script + configs into a tmp dir and return the script path."""
    staged = tmp_path / "pki"
    staged.mkdir()
    shutil.copy(PKI_DIR / "create_certs.sh", staged / "create_certs.sh")
    shutil.copytree(PKI_DIR / "configs", staged / "configs")
    return staged / "create_certs.sh"


@pytest.mark.parametrize("version,folder,expected_curve", _VERSIONS)
def test_create_certs_generates_full_chain(
    staged_pki: Path,
    tmp_path: Path,
    openssl: str,
    version: str,
    folder: str,
    expected_curve: str,
):
    # Run from a working directory that is NOT the PKI dir, by absolute path,
    # to prove the script's `cd "$(dirname "$0")"` makes the documented
    # repo-root invocation work.
    foreign_cwd = tmp_path
    result = subprocess.run(
        ["bash", str(staged_pki), "-v", version],
        cwd=foreign_cwd,
        capture_output=True,
        text=True,
        timeout=180,
    )

    assert result.returncode == 0, (
        f"create_certs.sh -v {version} exited {result.returncode}\n"
        f"stderr tail:\n{result.stderr[-2000:]}"
    )
    # The exact failure mode of the #48 bug: an invalid curve name.
    assert "invalid curve" not in result.stderr, (
        f"OpenSSL rejected the EC curve for {version}:\n{result.stderr[-2000:]}"
    )

    certs = staged_pki.parent / folder / "certs"
    for name in _CHAIN_ARTIFACTS:
        artifact = certs / name
        assert artifact.exists(), f"{version}: expected artifact missing: {name}"
        assert artifact.stat().st_size > 0, (
            f"{version}: chain artifact {name} is empty — upstream cert "
            "generation silently failed (the #48 regression)"
        )

    # The leaf must be a real X.509 cert on the curve mandated for this version.
    leaf = certs / "contractLeafCert.pem"
    text = subprocess.run(
        [openssl, "x509", "-in", str(leaf), "-noout", "-text"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert expected_curve in text, (
        f"{version}: contract leaf not on expected curve {expected_curve!r}\n"
        f"{text}"
    )

    # The MO contract chain must be a valid, password-readable PKCS12 container.
    info = subprocess.run(
        [
            openssl, "pkcs12", "-info", "-nokeys",
            "-in", str(certs / "moCertChain.p12"),
            "-passin", "pass:12345",
        ],
        capture_output=True,
        text=True,
    )
    assert info.returncode == 0, (
        f"{version}: moCertChain.p12 is not a readable PKCS12 container\n"
        f"{info.stderr[-2000:]}"
    )
    assert "contract_leaf_cert" in info.stdout, (
        f"{version}: moCertChain.p12 missing the contract leaf entry\n{info.stdout}"
    )
