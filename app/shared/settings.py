"""
    Copyright 2025, Ford Motor Company
    Copyright 2022, Switch
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.shared.personality.model import Runtime, _PersonalityBase


class SettingKey:
    PKI_PATH = "PKI_PATH"
    MESSAGE_LOG_JSON = "MESSAGE_LOG_JSON"
    MESSAGE_LOG_EXI = "MESSAGE_LOG_EXI"
    ENABLE_TLS_1_3 = "ENABLE_TLS_1_3"
    ENABLE_NMAP = "ENABLE_NMAP"
    NMAP_ARGS = "NMAP_ARGS"
    NMAP_PORTS = "NMAP_PORTS"


shared_settings: dict = {}

def init_shared_settings(personality: "_PersonalityBase", runtime: "Runtime") -> None:
    """Populate the shared-settings dict from a personality + runtime.

    Per ADR-0001 there are no env-var sources of truth any more — the
    personality YAML supplies persona fields and `runtime.yaml` / CLI flags
    supply operational ones. This function is the single seam where those
    typed models cross over into the legacy `shared_settings` dict that
    older code (codec, NMAP scanner) still reads.
    """
    shared_settings.update(
        {
            SettingKey.PKI_PATH: personality.residual.certificates.pki_path,
            SettingKey.MESSAGE_LOG_JSON: runtime.log.message_log_json,
            SettingKey.MESSAGE_LOG_EXI: runtime.log.message_log_exi,
            SettingKey.ENABLE_TLS_1_3: personality.residual.tls.enable_tls_1_3,
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
