"""Opt-in capture tap for the EXI codec boundary.

Capture is **off by default**. When enabled, every ``EXI().to_exi`` and
``EXI().from_exi`` call appends a single JSONL record to the capture
file. The records form the input corpus for the replay layer
(``tests/conformance/replay/``).

Enabling capture
----------------

Capture is enabled at process start, in exactly one of two ways:

1. **Environment variable.** ``ACCCS_EXI_CAPTURE=<path>`` set in the
   environment at module import time. Used by tests and ad-hoc local
   runs where the runner inherits a shell env.
2. **Explicit CLI flag.** ``run_secc.py --capture <path>`` /
   ``run_evcc.py --capture <path>`` calls :func:`enable_capture` before
   the codec is exercised. This is the production-suitable path because
   ``sudo`` strips ``ACCCS_EXI_CAPTURE`` on this project's dev box
   (NOPASSWD entry does not preserve custom env vars), and we do **not**
   want a sentinel file under ``/tmp`` that production code paths
   consult on every codec call.

The hot path when capture is off is a single ``if`` against a cached
module-level variable — **zero syscalls**. No env lookup, no ``open()``,
no ``stat()``. This is a hard requirement for Slice 5 where the codec is
on every CCS session's hot path.

Record schema
-------------

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

Cross-process append safety
---------------------------

The SECC and EVCC are independent root processes that may both append to
the same capture target during a veth session. POSIX ``O_APPEND`` is
only atomic up to ``PIPE_BUF`` (4096 bytes); a record carrying large hex
payloads (certs, signed sales tariffs in a hardware capture) can exceed
that and tear across writes. To make concurrent appends safe regardless
of payload size, :func:`record` takes an advisory ``fcntl.LOCK_EX`` on
the open file descriptor across the ``write()``. The
lock is per-file, held only while capture is active, and only matters
when two processes target the same path.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import threading
import time
from typing import Literal, Optional

logger = logging.getLogger(__name__)

_ENV_VAR = "ACCCS_EXI_CAPTURE"
_lock = threading.Lock()

# Resolved exactly once: at module import (env var) or at the first
# successful ``enable_capture()`` call. The off-path check is a single
# Python ``is None`` test — no syscalls.
_capture_path: Optional[str] = os.environ.get(_ENV_VAR) or None


def enable_capture(path: str) -> None:
    """Turn capture on, pointing at ``path``.

    Called from the runners' ``--capture`` flag handler. Idempotent on
    the same path; raises if a different path is already active (so a
    stray double-enable is surfaced rather than silently overwriting).
    """
    global _capture_path
    if not path:
        raise ValueError("enable_capture requires a non-empty path")
    if _capture_path is not None and _capture_path != path:
        raise RuntimeError(
            f"EXI capture already enabled for {_capture_path!r}; "
            f"refusing to switch to {path!r}"
        )
    _capture_path = path


def disable_capture() -> None:
    """Turn capture off. Intended for tests; restores zero-syscall hot path."""
    global _capture_path
    _capture_path = None


def capture_path() -> Optional[str]:
    """Return the active capture path, or ``None`` if capture is off."""
    return _capture_path


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
    path = _capture_path
    if path is None:
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
    line = json.dumps(record_dict, separators=(",", ":")) + "\n"
    data = line.encode("utf-8")
    with _lock:
        existed = os.path.exists(path)
        # Open with O_APPEND + flock for cross-process safety. O_APPEND
        # guarantees atomic seek-to-end per write call; flock serialises
        # the write() itself so payloads larger than PIPE_BUF (4096 B)
        # cannot tear across concurrent appenders.
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o666)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                os.write(fd, data)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        # The emulator typically runs as root via sudo while the capture
        # script that ingests these files runs as the unprivileged user.
        # Mark the file world-writable on first create so the user can
        # also rewrite or delete it without a sudo prompt.
        if not existed:
            try:
                os.chmod(path, 0o666)
            except OSError:
                pass
