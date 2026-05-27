"""Opt-in capture tap for the EXI codec boundary.

When the ``ACCCS_EXI_CAPTURE`` environment variable is set to a writable
file path, every ``EXI().to_exi`` and ``EXI().from_exi`` call appends a
single JSONL record to that path. The records form the input corpus for
the replay layer (``tests/conformance/replay/``).

Each record has the following keys:

- ``ts``      — wall-clock float seconds (``time.time()``).
- ``dir``     — ``"encode"`` (Pydantic → bytes) or ``"decode"`` (bytes → Pydantic).
- ``ns``      — protocol namespace string (matches ``Namespace`` enum value).
- ``model``   — ``str(msg_element)`` at the encode site, or the decoded
                top-level message name at the decode site. Used by the
                replay harness to look up the Pydantic class for re-decode.
- ``root``    — ``"document"`` / ``"fragment"`` / ``"xmldsig"``. Picked by
                inspecting the in-flight object; the replay harness uses it
                to call the matching EXPy variant once Slice 5 lands.
- ``hex``     — the wire bytes, hex-encoded.

Capture is **off by default**. The codec calls :func:`record`
unconditionally; ``record`` short-circuits when neither the env var nor
the sentinel file is set. With capture off, the hot path costs one
``os.environ.get`` plus one failing ``open`` on the sentinel per codec
call.
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Literal, Optional

_ENV_VAR = "ACCCS_EXI_CAPTURE"
# Sentinel file: lets a non-root capture driver script point the
# privileged emulator subprocess at a capture path even when sudo strips
# the environment (the AcCCS dev box's NOPASSWD sudoers entry forbids
# preserving custom env vars). The capture script writes the file before
# launching the emulators; the file is read once per ``record`` call.
_SENTINEL_PATH = "/tmp/acccs_exi_capture_path"
_lock = threading.Lock()


def capture_path() -> Optional[str]:
    env_val = os.environ.get(_ENV_VAR)
    if env_val:
        return env_val
    try:
        with open(_SENTINEL_PATH, "r", encoding="utf-8") as fh:
            line = fh.readline().strip()
    except OSError:
        return None
    return line or None


def classify_root(msg_element_or_name) -> Literal["document", "fragment", "xmldsig"]:
    """Pick the EXI root kind for a Pydantic message.

    Accepts either an instance or a bare ``str(model)`` name — the encode
    side has the instance, the decode side has only the name from the
    decoded JSON envelope. Misclassification is preferable to crashing the
    session: anything we don't recognise falls back to ``"fragment"``.
    """
    name = (
        msg_element_or_name
        if isinstance(msg_element_or_name, str)
        else str(msg_element_or_name)
    )
    if name == "SignedInfo":
        return "xmldsig"

    # Late-imported to avoid bootstrapping the message graph for every call.
    if not isinstance(msg_element_or_name, str):
        from app.shared.messages.app_protocol import (
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
        )
        from app.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDIN
        from app.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
        from app.shared.messages.iso15118_20.common_types import (
            V2GMessage as V2GMessageV20,
        )

        if isinstance(
            msg_element_or_name,
            (
                V2GMessageDIN,
                V2GMessageV2,
                V2GMessageV20,
                SupportedAppProtocolReq,
                SupportedAppProtocolRes,
            ),
        ):
            return "document"
        return "fragment"

    # String-only path (decode side): the model name comes from the
    # decoded JSON envelope's outer key. V2G_Message / app protocol /
    # ISO-20 top-level messages all decode through ``from_exi`` and are
    # always full documents.
    if name in {
        "V2G_Message",
        "SupportedAppProtocolReq",
        "SupportedAppProtocolRes",
    }:
        return "document"
    # Any other top-level name in the decoder envelope is an ISO-20
    # full-message decode (no V2G_Message wrapper at that layer).
    return "document"


def record(
    *,
    direction: Literal["encode", "decode"],
    namespace: str,
    model: object,
    payload: bytes,
) -> None:
    """Append one record to the capture file if capture is enabled.

    ``model`` may be a Pydantic instance (encode) or a string (decode);
    the wire bytes are the raw EXI stream.
    """
    path = capture_path()
    if not path:
        return

    record_dict = {
        "ts": time.time(),
        "dir": direction,
        "ns": namespace,
        "model": (
            model if isinstance(model, str) else str(model)
        ),
        "root": classify_root(model),
        "hex": payload.hex(),
    }
    line = json.dumps(record_dict, separators=(",", ":"))
    with _lock:
        existed = os.path.exists(path)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        # The emulator typically runs as root via sudo while the capture
        # script that ingests these files runs as the unprivileged user.
        # Mark the file world-writable on first create so the user can
        # also rewrite or delete it without a sudo prompt.
        if not existed:
            try:
                os.chmod(path, 0o666)
            except OSError:
                pass
