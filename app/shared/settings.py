"""
    Copyright 2025, Ford Motor Company
    Copyright 2022, Switch
"""

import contextvars
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.shared.personality.model import Runtime, _PersonalityBase


class SettingKey:
    MESSAGE_LOG_JSON = "MESSAGE_LOG_JSON"
    MESSAGE_LOG_EXI = "MESSAGE_LOG_EXI"
    ENABLE_NMAP = "ENABLE_NMAP"
    NMAP_ARGS = "NMAP_ARGS"
    NMAP_PORTS = "NMAP_PORTS"


# `shared_settings` holds only the genuinely *process-wide* operational knobs
# sourced from `runtime.yaml` (logging + NMAP). Those are meant to be shared by
# every leg in the process, so a plain module-global dict is correct for them.
#
# The two *personality-sourced* TLS/PKI values (`pki_path`, `enable_tls_1_3`)
# used to live here too, but a single mutable dict means the second leg's init
# clobbers the first — both legs of the MIM (#123) would collapse to one TLS
# posture. They now live in a per-task `ContextVar` (see `TlsPkiConfig` below),
# which each async leg sets from *its own* personality, so the two legs of a
# one-process MIM keep independent TLS/PKI configs. In the single-role case the
# process default (set once at `init_shared_settings`) is inherited by every
# task, so behaviour is unchanged.
shared_settings: dict = {}


@dataclass(frozen=True)
class TlsPkiConfig:
    """The per-leg TLS/PKI posture, sourced from a leg's personality.

    `pki_path` roots the ISO 15118-2 cert/key tree read by `CertPath` /
    `KeyPath` / `KeyPasswordPath`; `enable_tls_1_3` selects the TLS version
    posture in `get_ssl_context`.
    """

    pki_path: str
    enable_tls_1_3: bool


# Defaults match the personality-model defaults (`pki_path="app/shared/pki/"`,
# `enable_tls_1_3=True`) so code paths that never call `init_shared_settings`
# (e.g. the codec's `load_shared_settings` shim, unit tests that touch a
# `CertPath`) see exactly what the old `shared_settings` default gave them.
_tls_pki: "contextvars.ContextVar[TlsPkiConfig]" = contextvars.ContextVar(
    "tls_pki_config",
    default=TlsPkiConfig(pki_path="app/shared/pki/", enable_tls_1_3=True),
)


def set_tls_pki_config(
    pki_path: str, enable_tls_1_3: bool
) -> "contextvars.Token[TlsPkiConfig]":
    """Set the TLS/PKI config for the current task context.

    Called once at startup (via `init_shared_settings`) in the single-role
    case, and per-leg inside each leg's own task by the MIM so the two legs
    do not clobber each other. Returns the reset token for symmetry with the
    `ContextVar` API.
    """
    return _tls_pki.set(TlsPkiConfig(pki_path=pki_path, enable_tls_1_3=enable_tls_1_3))


def current_pki_path() -> str:
    """The PKI root for the current task's leg."""
    return _tls_pki.get().pki_path


def current_enable_tls_1_3() -> bool:
    """Whether the current task's leg negotiates TLS 1.3."""
    return _tls_pki.get().enable_tls_1_3


def init_shared_settings(personality: "_PersonalityBase", runtime: "Runtime") -> None:
    """Populate the shared-settings dict from a personality + runtime.

    Per ADR-0001 there are no env-var sources of truth any more — the
    personality YAML supplies persona fields and `runtime.yaml` / CLI flags
    supply operational ones. This function is the single seam where those
    typed models cross over into the legacy `shared_settings` dict that
    older code (codec, NMAP scanner) still reads.

    The personality-sourced TLS/PKI values do *not* go into the shared dict —
    they are set into the per-task `TlsPkiConfig` `ContextVar` so a second leg
    in the same process cannot clobber the first (see `TlsPkiConfig`).
    """
    set_tls_pki_config(
        pki_path=personality.residual.certificates.pki_path,
        enable_tls_1_3=personality.residual.tls.enable_tls_1_3,
    )
    shared_settings.update(
        {
            SettingKey.MESSAGE_LOG_JSON: runtime.log.message_log_json,
            SettingKey.MESSAGE_LOG_EXI: runtime.log.message_log_exi,
            SettingKey.ENABLE_NMAP: runtime.nmap.enabled,
            SettingKey.NMAP_ARGS: runtime.nmap.args,
            SettingKey.NMAP_PORTS: runtime.nmap.ports,
        }
    )


def load_shared_settings(*_args, **_kwargs) -> None:
    """Back-compat shim: tests and the codec call this with no args to get
    sane defaults. New code should call `init_shared_settings` with a real
    personality + runtime."""
    # Imported here to avoid a circular import at module load.
    from app.shared.personality.model import EVCCPersonality, Runtime

    if shared_settings:
        return
    init_shared_settings(EVCCPersonality(), Runtime())
