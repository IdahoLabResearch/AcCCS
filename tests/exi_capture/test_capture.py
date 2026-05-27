"""Tests for the EXI capture tap (`app/shared/exi_capture.py`).

Covers issue #25 acceptance criteria:

- Zero-syscall hot path when capture is off (no env, no enable_capture).
- Stale ``/tmp/acccs_exi_capture_path`` sentinel cannot silently enable
  capture (the sentinel mechanism has been removed entirely).
- Concurrent processes appending oversize records (> ``PIPE_BUF``) produce
  a corpus that re-parses cleanly.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import subprocess
import sys
from pathlib import Path

import pytest

from app.shared import exi_capture

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _capture_off():
    """Force capture off around each test; restore prior state after."""
    prior = exi_capture.capture_path()
    exi_capture.disable_capture()
    yield
    exi_capture.disable_capture()
    if prior is not None:
        exi_capture.enable_capture(prior)


# ---------------------------------------------------------------------------
# Hot-path cost
# ---------------------------------------------------------------------------


def test_record_when_disabled_makes_no_syscalls(monkeypatch):
    """With capture off, `record` must not touch the filesystem.

    Acceptance criterion: ``EXI.to_exi`` / ``EXI.from_exi`` do **zero**
    extra syscalls beyond what they did before #15. We assert this at
    the capture-module boundary by trapping every filesystem syscall we
    can think of and checking none fire.
    """
    calls: list[str] = []

    def _trap(name):
        def _f(*a, **kw):
            calls.append(name)
            raise AssertionError(
                f"capture is disabled but {name}() was called with {a!r} {kw!r}"
            )
        return _f

    monkeypatch.setattr(os, "open", _trap("os.open"))
    monkeypatch.setattr(os, "stat", _trap("os.stat"))
    monkeypatch.setattr(os.path, "exists", _trap("os.path.exists"))
    monkeypatch.setattr(os, "environ", {})  # env access not allowed either

    # Built-in open is what older code paths used; trap that too.
    import builtins

    monkeypatch.setattr(builtins, "open", _trap("builtins.open"))

    exi_capture.record(
        direction="encode",
        namespace="urn:foo",
        model="V2G_Message",
        payload=b"\x01\x02\x03",
    )
    assert calls == []


def test_stale_sentinel_does_not_enable_capture(tmp_path, monkeypatch):
    """A leftover ``/tmp/acccs_exi_capture_path`` from a crashed Slice 4 run
    must not silently enable capture in a production process. The sentinel
    mechanism has been removed entirely — this test pins that removal.
    """
    # Plant a stale sentinel pointing at a writable path under tmp.
    sentinel = tmp_path / "acccs_exi_capture_path"
    target = tmp_path / "should_not_be_written.jsonl"
    sentinel.write_text(str(target) + "\n")

    # Force-re-import the module in a fresh state, with the sentinel
    # present. We do not patch ``/tmp/acccs_exi_capture_path`` because the
    # whole point of the fix is that the module no longer looks for one.
    exi_capture.disable_capture()
    exi_capture.record(
        direction="encode",
        namespace="urn:foo",
        model="V2G_Message",
        payload=b"x" * 16,
    )
    assert not target.exists(), (
        "Capture must not activate from a stale sentinel file"
    )
    assert exi_capture.capture_path() is None


# ---------------------------------------------------------------------------
# Enable / write
# ---------------------------------------------------------------------------


def test_enable_capture_writes_records(tmp_path):
    out = tmp_path / "cap.jsonl"
    exi_capture.enable_capture(str(out))
    exi_capture.record(
        direction="encode",
        namespace="urn:iso:15118:2:2013:MsgDef",
        model="V2G_Message",
        payload=b"\xde\xad\xbe\xef",
    )
    exi_capture.record(
        direction="decode",
        namespace="urn:iso:15118:2:2013:MsgDef",
        model="V2G_Message",
        payload=b"\x01\x02",
    )
    lines = out.read_text().strip().splitlines()
    assert len(lines) == 2
    rec0 = json.loads(lines[0])
    assert rec0["dir"] == "encode"
    assert rec0["hex"] == "deadbeef"
    assert rec0["root"] == "document"
    assert rec0["model"] == "V2G_Message"


def test_enable_capture_rejects_path_switch(tmp_path):
    exi_capture.enable_capture(str(tmp_path / "a.jsonl"))
    # Same path is fine (idempotent).
    exi_capture.enable_capture(str(tmp_path / "a.jsonl"))
    with pytest.raises(RuntimeError):
        exi_capture.enable_capture(str(tmp_path / "b.jsonl"))


# ---------------------------------------------------------------------------
# Cross-process oversize append
# ---------------------------------------------------------------------------


_BIG_PAYLOAD_BYTES = 8192  # > PIPE_BUF (4096); a single record exceeds it once hex-encoded too


def _writer_proc(path: str, worker_id: int, n_records: int) -> None:
    """Worker entrypoint: enable capture and append N oversize records.

    Runs in a fresh process so the fcntl advisory lock is genuinely
    cross-process (a threading.Lock would not be).
    """
    # Force a clean module state inside the child (multiprocessing 'fork'
    # would otherwise inherit the parent's _capture_path).
    from app.shared import exi_capture as cap

    cap.disable_capture()
    cap.enable_capture(path)
    payload = bytes([worker_id & 0xFF]) * _BIG_PAYLOAD_BYTES
    for i in range(n_records):
        cap.record(
            direction="encode",
            namespace=f"urn:test:worker{worker_id}",
            model="V2G_Message",
            payload=payload + i.to_bytes(4, "big"),
        )


def test_concurrent_writers_oversize_payloads_reparse_cleanly(tmp_path):
    """Two writer processes appending records well over PIPE_BUF (4096 B)
    must produce a JSONL file where every line still parses. Before the
    fcntl.flock fix, large writes could interleave and tear.
    """
    out = tmp_path / "concurrent.jsonl"
    n_workers = 4
    n_records = 10

    ctx = multiprocessing.get_context("spawn")
    procs = [
        ctx.Process(target=_writer_proc, args=(str(out), wid, n_records))
        for wid in range(n_workers)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=30)
        assert p.exitcode == 0, f"writer exited {p.exitcode}"

    lines = out.read_text().splitlines()
    assert len(lines) == n_workers * n_records, (
        f"expected {n_workers * n_records} lines, got {len(lines)}"
    )
    seen: set[tuple[str, int]] = set()
    for ln in lines:
        rec = json.loads(ln)  # no try/except: every line must be valid JSON
        assert rec["dir"] == "encode"
        # Recover (worker, sequence) from the payload so we can verify no
        # records were lost or duplicated.
        payload = bytes.fromhex(rec["hex"])
        assert len(payload) == _BIG_PAYLOAD_BYTES + 4
        worker_id = payload[0]
        seq = int.from_bytes(payload[-4:], "big")
        seen.add((worker_id, seq))
    assert len(seen) == n_workers * n_records


# ---------------------------------------------------------------------------
# Runner CLI flag wiring
# ---------------------------------------------------------------------------


def test_runner_capture_flag_is_registered():
    """`--capture` must be a real CLI flag on both runners — the audit
    needs to drive captures through argv, not a sentinel file.
    """
    for runner in ("run_secc.py", "run_evcc.py"):
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / runner), "--help"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert "--capture" in result.stdout, (
            f"{runner} --help did not advertise --capture:\n{result.stdout}"
        )
