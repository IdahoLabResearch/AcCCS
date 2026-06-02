"""Logs route into the console pane while the console runs (ADR-0004, issue #28).

The full-screen console owns the terminal, so the root logger's stdout
`StreamHandler` must be swapped for a pane handler for the console's lifetime
and restored afterwards — otherwise log writes would corrupt the frame (and, on
the headless path, behaviour would change). These exercise that routing without
a real TTY: the helpers directly, and the full `run_with_console` lifecycle
with a stubbed prompt_toolkit Application.
"""

from __future__ import annotations

import asyncio
import collections
import io
import logging
import threading

import pytest

from app.shared import console
from app.shared.console import (
    _LogPaneHandler,
    _restore_logging,
    _route_logging_to_pane,
    run_with_console,
)
from app.shared.live_control import LiveControl


@pytest.fixture
def root_with_handlers():
    """Root with a stdout StreamHandler (bound to sys.stdout) + a file-ish one."""
    import sys

    root = logging.getLogger()
    saved = root.handlers[:]
    saved_level = root.level
    root.setLevel(logging.DEBUG)  # _init_logger sets root to DEBUG; mirror it

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    stdout_handler.setLevel(logging.INFO)
    file_stream = io.StringIO()
    file_handler = logging.StreamHandler(file_stream)  # different stream — must survive

    root.handlers = [stdout_handler, file_handler]
    try:
        yield root, stdout_handler, file_handler, file_stream
    finally:
        root.handlers = saved
        root.setLevel(saved_level)


def test_pane_handler_formats_records_into_line_buffer():
    lines: "collections.deque[str]" = collections.deque(maxlen=100)
    calls = []
    handler = _LogPaneHandler(lines, lambda: calls.append(1))
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    handler.emit(logging.makeLogRecord({"levelname": "INFO", "msg": "hello"}))
    # A multi-line message (e.g. a traceback) splits into separate pane lines.
    handler.emit(logging.makeLogRecord({"levelname": "ERROR", "msg": "a\nb"}))

    assert list(lines) == ["INFO: hello", "ERROR: a", "b"]
    assert calls == [1, 1]  # on_emit fired once per record


def test_route_swaps_only_the_stdout_handler_and_restores(root_with_handlers):
    root, stdout_handler, file_handler, _file_stream = root_with_handlers
    pane = _LogPaneHandler(collections.deque(), lambda: None)

    removed = _route_logging_to_pane(pane)

    # The stdout handler is removed and the pane handler installed; the
    # different-stream (file) handler is left in place.
    assert stdout_handler not in root.handlers
    assert pane in root.handlers
    assert file_handler in root.handlers
    assert removed == [stdout_handler]
    # Formatter + level are copied so the on-screen text matches headless.
    assert pane.formatter is stdout_handler.formatter
    assert pane.level == logging.INFO

    _restore_logging(pane, removed)
    assert pane not in root.handlers
    assert stdout_handler in root.handlers


class _FakeApp:
    """Stand-in for the prompt_toolkit Application (no TTY needed)."""

    def __init__(self):
        self.is_running = False
        self._stop = asyncio.Event()

    async def run_async(self):
        self.is_running = True
        await self._stop.wait()
        self.is_running = False

    def exit(self):
        self._stop.set()

    def invalidate(self):
        pass


def test_run_with_console_routes_logs_in_flight_then_restores(
    monkeypatch, root_with_handlers
):
    root, stdout_handler, _file_handler, _file_stream = root_with_handlers

    lines: "collections.deque[str]" = collections.deque(maxlen=100)
    fake_handler = _LogPaneHandler(lines, lambda: None)
    fake = console._Console(_FakeApp(), object(), fake_handler)
    monkeypatch.setattr(console, "_build_application", lambda lc, source: fake)

    captured = {}

    async def main():
        # While in flight, the stdout handler is gone and the pane handler is
        # live: a log call lands in the pane's line buffer, not on stdout.
        logging.getLogger().info("mid-session line")
        captured["handlers"] = logging.getLogger().handlers[:]
        captured["lines"] = list(lines)

    asyncio.run(run_with_console(LiveControl(), main(), source="EVCC"))

    assert stdout_handler not in captured["handlers"]
    assert fake_handler in captured["handlers"]
    assert captured["lines"] == ["INFO: mid-session line"]
    # Restored once the session completes.
    assert stdout_handler in logging.getLogger().handlers
    assert fake_handler not in logging.getLogger().handlers


def test_off_loop_logging_is_marshalled_onto_the_ui_thread(
    monkeypatch, root_with_handlers
):
    """A log emitted off the UI loop touches prompt_toolkit only on the UI thread.

    Regression for issue #33: the scapy SLAC sniffer thread and any
    `run_in_executor` worker can log while the console's event loop runs on the
    asyncio thread. The pane handler must marshal the buffer-mutation/invalidate
    refresh onto the UI loop rather than running it on the calling thread.
    """
    lines: "collections.deque[str]" = collections.deque(maxlen=100)
    refresh_threads: list[int] = []

    fake_app = _FakeApp()

    def on_emit() -> None:
        # Stands in for the real on_emit: this is where set_document/invalidate
        # (the prompt_toolkit interaction) would run. Record which thread it's on.
        refresh_threads.append(threading.get_ident())
        if fake_app.is_running:
            fake_app.invalidate()

    handler = _LogPaneHandler(lines, on_emit)
    fake = console._Console(fake_app, object(), handler)
    monkeypatch.setattr(console, "_build_application", lambda lc, source: fake)

    ui_thread: dict[str, int] = {}
    worker_errors: list[BaseException] = []

    async def main():
        ui_thread["ident"] = threading.get_ident()
        done = threading.Event()

        def worker():
            try:
                for i in range(50):
                    logging.getLogger().info("from-thread %d", i)
            except BaseException as exc:  # noqa: BLE001 - capture for assertion
                worker_errors.append(exc)
            finally:
                done.set()

        t = threading.Thread(target=worker)
        t.start()
        # Pump the loop so the marshalled call_soon_threadsafe callbacks run.
        while not done.is_set():
            await asyncio.sleep(0.001)
        t.join()
        await asyncio.sleep(0.01)  # drain any final scheduled refresh

    asyncio.run(run_with_console(LiveControl(), main(), source="EVCC"))

    # The off-loop logging never raised.
    assert worker_errors == []
    # The refresh fired and every refresh ran on the UI loop thread, never the
    # worker thread that emitted the records.
    assert refresh_threads, "on_emit refresh never fired"
    assert all(tid == ui_thread["ident"] for tid in refresh_threads)
    # All 50 lines arrived intact and in order in the pane's line buffer. The
    # pane handler inherits the routed stdout handler's "%(levelname)s: ..."
    # formatter (see `_route_logging_to_pane`), so each line is prefixed.
    assert list(lines) == [f"INFO: from-thread {i}" for i in range(50)]
