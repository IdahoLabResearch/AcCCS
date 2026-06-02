"""Pane redraws are coalesced to the render tick, not run per log record (#35).

`on_emit` used to rebuild the entire pane text (`"\n".join` over the up-to-2000
line deque) and `set_document` it on *every* log record. ADR-0004 measures the
virtual ISO-2 DC CurrentDemand loop at ~2000 log lines/s, so that was millions
of joined characters per second on the asyncio loop — the same hot-path
pressure that sank `patch_stdout`.

The fix coalesces the expensive rebuild off the per-record path: `on_emit` only
marks the pane dirty, and the full-text rebuild + `set_document` runs at most
once per render frame (`Application.before_render`, driven by the existing
`refresh_interval=0.5`). These tests pin that contract:

- a burst of records is cheap and triggers no rebuild on its own,
- a render tick rebuilds at most once and only when something changed, and
- after a flush the pane buffer holds exactly the deque's lines, tailing to the
  newest — identical to the old per-record output.
"""

from __future__ import annotations

import logging
import time
from unittest import mock

from app.shared.console import _build_application
from app.shared.live_control import LiveControl


def _build():
    """A headless console (no TTY, no running loop — `_build_application` is cheap)."""
    console = _build_application(LiveControl(), "EVCC")
    console.handler.setFormatter(logging.Formatter("%(message)s"))
    return console


def _emit(console, msg: str) -> None:
    console.handler.emit(logging.makeLogRecord({"levelname": "INFO", "msg": msg}))


def test_burst_of_records_triggers_no_full_text_rebuild():
    """Emitting records only appends + marks dirty; no `set_document` per record."""
    console = _build()
    with mock.patch.object(
        console.log_buffer, "set_document", wraps=console.log_buffer.set_document
    ) as set_doc:
        for i in range(5000):
            _emit(console, f"line {i}")
        # The whole point of #35: the rebuild does NOT scale with the record rate.
        assert set_doc.call_count == 0


def test_burst_of_records_is_cheap():
    """5000 records through the pane handler complete well under a modest budget.

    The old per-record `"\\n".join` over a 2000-line deque was ~10M joined chars
    for this burst; the coalesced path is plain deque appends. A generous 2 s
    budget cleanly separates the two without being flaky under CI load.
    """
    console = _build()
    start = time.monotonic()
    for i in range(5000):
        _emit(console, f"line {i}")
    assert time.monotonic() - start < 2.0


def test_render_tick_rebuilds_once_per_tick_not_per_record():
    """`set_document` is bounded by the number of render ticks, not record count."""
    console = _build()
    with mock.patch.object(
        console.log_buffer, "set_document", wraps=console.log_buffer.set_document
    ) as set_doc:
        for i in range(1000):
            _emit(console, f"a{i}")
        console.flush_pane()  # one render tick
        assert set_doc.call_count == 1

        # A tick with nothing new is a no-op — the dirty flag was cleared.
        console.flush_pane()
        assert set_doc.call_count == 1

        for i in range(1000):
            _emit(console, f"b{i}")
        console.flush_pane()  # second tick, one more rebuild
        assert set_doc.call_count == 2


def test_flushed_pane_matches_deque_and_tails_to_newest():
    """After a flush the buffer holds exactly the deque's lines, cursor at end."""
    console = _build()
    for i in range(10):
        _emit(console, f"line {i}")
    console.flush_pane()

    expected = "\n".join(f"line {i}" for i in range(10))
    assert console.log_buffer.text == expected
    # Cursor parked at the end so the Window tails to the newest line.
    assert console.log_buffer.cursor_position == len(expected)
