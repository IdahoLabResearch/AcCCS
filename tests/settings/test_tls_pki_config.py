"""Per-leg TLS/PKI config is task-local, not a shared process-global (#123).

The two personality-sourced TLS/PKI values (``pki_path`` and
``enable_tls_1_3``) were moved out of the mutable ``shared_settings`` dict into
a per-task ``ContextVar`` so that the two legs of a one-process MIM each read
*their own* personality's posture instead of clobbering each other. These tests
pin that contract: the single-role default is unchanged, ``init_shared_settings``
no longer routes the two keys through the global dict, and two concurrent async
legs keep independent configs (including the ``CertPath`` paths derived from
``pki_path``).
"""

from __future__ import annotations

import asyncio

import pytest

import app.shared.security as security
from app.shared.personality.model import Runtime, SECCPersonality
from app.shared.settings import (
    current_enable_tls_1_3,
    current_pki_path,
    init_shared_settings,
    set_tls_pki_config,
    shared_settings,
)


@pytest.fixture(autouse=True)
def _restore_tls_pki_config():
    """A sync test calling ``set_tls_pki_config``/``init_shared_settings`` sets
    the ``ContextVar`` in the test's own context, which persists into later
    sync tests in the same worker. Snapshot and restore it so order
    (``pytest-randomly``) can't leak one test's posture into another."""
    saved_path, saved_tls = current_pki_path(), current_enable_tls_1_3()
    try:
        yield
    finally:
        set_tls_pki_config(pki_path=saved_path, enable_tls_1_3=saved_tls)


def test_defaults_match_legacy_shared_settings():
    """An un-configured context sees exactly what the old global default gave:
    ``pki_path="app/shared/pki/"`` and TLS 1.3 on — so code paths that never
    call ``init_shared_settings`` (codec shim, fixture-less unit tests) are
    byte-identical."""
    assert current_pki_path() == "app/shared/pki/"
    assert current_enable_tls_1_3() is True
    assert (
        str(security.CertPath.OEM_ROOT_PEM)
        == "app/shared/pki/iso15118_2/certs/oemRootCACert.pem"
    )


def test_init_shared_settings_keeps_tls_pki_off_the_global_dict():
    """The two personality-sourced keys must not be reachable through the
    process-global ``shared_settings`` dict — that is the clobber vector #123
    closes. Only the runtime-sourced operational knobs remain there."""
    init_shared_settings(SECCPersonality(), Runtime())
    assert "PKI_PATH" not in shared_settings
    assert "ENABLE_TLS_1_3" not in shared_settings
    # The runtime-sourced keys are still shared, as intended.
    assert "ENABLE_NMAP" in shared_settings


def test_two_legs_do_not_clobber_each_other():
    """The regression guard: two concurrent legs set different postures and
    each keeps its own, including the ``CertPath`` derived from ``pki_path``."""

    async def leg(path: str, tls13: bool):
        set_tls_pki_config(pki_path=path, enable_tls_1_3=tls13)
        # Yield so the sibling leg runs and sets its own config in between.
        await asyncio.sleep(0)
        return (
            current_pki_path(),
            current_enable_tls_1_3(),
            str(security.CertPath.OEM_ROOT_PEM),
        )

    async def drive():
        return await asyncio.gather(
            leg("/legA/pki/", True),
            leg("/legB/pki/", False),
        )

    a, b = asyncio.run(drive())
    assert a == (
        "/legA/pki/",
        True,
        "/legA/pki/iso15118_2/certs/oemRootCACert.pem",
    )
    assert b == (
        "/legB/pki/",
        False,
        "/legB/pki/iso15118_2/certs/oemRootCACert.pem",
    )
