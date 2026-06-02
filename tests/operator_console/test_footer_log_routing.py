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
