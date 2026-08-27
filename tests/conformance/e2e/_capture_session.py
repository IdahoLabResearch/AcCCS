"""Shared helpers for the risk-based E2E tests (ADR-0003, issue #21).

The smoke E2E layer (`test_scenarios.py`) is declarative: a scenario YAML
names two personalities and the only oracle is clean session termination
observed on stdout. The three risk-based tests need more — they assert
*mid-session* wire behavior (ISO-20 envelope shape, PnC signed-message
artifacts, app-protocol negotiation outcome). ADR-0003 anticipated this:

> Risk-based augmentation [...] authored as Python E2E tests (declarative
> scenarios won't express fault injection cleanly).

These helpers drive a real two-subprocess session over the veth pair (the
same seam and oracle as the smoke layer) but additionally turn on the EXI
capture tap (`app/shared/exi_capture.py`) via the runners' ``--capture``
flag. After the session terminates cleanly, the captured JSONL is the
introspection surface the assertions read: every message that crossed the
codec boundary, in both directions, with its namespace, root kind, model
name, and raw wire bytes.

Reusing the capture tap rather than inventing a new wire-tap keeps these
tests honest — they observe exactly the bytes the production codec path
produced and consumed, decoded back through the same EXPy codec.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from app.shared.messages.enums import Namespace

# Same protocol-agnostic success markers the smoke runner watches. A clean
# SessionStopReq/Res exchange logs these via app/shared/comm_session.py.
EVCC_SUCCESS_MARKER = "SessionStopRes received"
SECC_SUCCESS_MARKER = "Sent SessionStopRes"

# Namespace of the SupportedAppProtocol (SAP) handshake — present in every
# session regardless of which V2G protocol is ultimately negotiated.
SAP_NS = Namespace.SAP.value


@dataclass(frozen=True)
class CaptureRecord:
    """One EXI capture JSONL line. See app/shared/exi_capture.py § Record schema."""

    direction: str  # "encode" | "decode"
    namespace: str
    model: str
    root: str  # "document" | "fragment" | "xmldsig"
    hex: str

    @property
    def payload(self) -> bytes:
        return bytes.fromhex(self.hex)


@dataclass
class SessionCapture:
    """Result of a driven session: the success oracle plus the capture corpus."""

    evcc_done: bool
    secc_done: bool
    records: list[CaptureRecord]

    @property
    def completed(self) -> bool:
        return self.evcc_done and self.secc_done

    def documents(self, *, namespace: Optional[str] = None) -> list[CaptureRecord]:
        out = [r for r in self.records if r.root == "document"]
        if namespace is not None:
            out = [r for r in out if r.namespace == namespace]
        return out

    def model_names(self, *, root: Optional[str] = None) -> set[str]:
        out = self.records
        if root is not None:
            out = [r for r in out if r.root == root]
        return {r.model for r in out}


def _wait_for_marker(
    proc: subprocess.Popen, marker: str, deadline: float
) -> bool:
    assert proc.stdout is not None
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                return False
            continue
        if marker in line.decode("utf-8", errors="replace"):
            return True
    return False


def drive_session(
    launch_emulator,
    *,
    evcc_personality: Path,
    secc_personality: Path,
    capture_path: Path,
    timeout_seconds: int = 90,
) -> SessionCapture:
    """Run a real SECC⇄EVCC session with the EXI capture tap on.

    Mirrors `test_scenarios.test_scenario`'s launch/oracle handling (SECC
    first, brief grace, then EVCC; watch each subprocess's stdout for its own
    SessionStop marker) but threads ``--capture <capture_path>`` into both
    subprocesses so the wire is recorded. Returns once both markers are seen
    or the deadline passes, then reads the capture file.
    """
    capture_arg = ["--capture", str(capture_path)]

    secc = launch_emulator("secc", secc_personality, capture_arg)
    # Tiny grace period so the SECC TCP listener is up before EVCC dials.
    time.sleep(0.5)
    evcc = launch_emulator("evcc", evcc_personality, capture_arg)

    deadline = time.monotonic() + timeout_seconds
    evcc_done = _wait_for_marker(evcc, EVCC_SUCCESS_MARKER, deadline)
    secc_done = (
        _wait_for_marker(secc, SECC_SUCCESS_MARKER, deadline) if evcc_done else False
    )

    # Both terminal SessionStop records are flushed by the time their markers
    # are logged (capture happens inside the codec call, before the send/recv
    # log line). Give the processes a brief beat to fully exit so no late
    # record is mid-write when we read.
    for proc in (evcc, secc):
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

    records = _read_capture(capture_path)
    return SessionCapture(evcc_done=evcc_done, secc_done=secc_done, records=records)


def _read_capture(path: Path) -> list[CaptureRecord]:
    if not path.exists():
        return []
    records: list[CaptureRecord] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        records.append(
            CaptureRecord(
                direction=d["dir"],
                namespace=d["ns"],
                model=d["model"],
                root=d["root"],
                hex=d["hex"],
            )
        )
    return records
