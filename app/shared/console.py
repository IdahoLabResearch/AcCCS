"""The operator console: an opt-out, TTY-detected terminal footer.

Per ADR-0004 (`docs/adr/0004-operator-console-live-control.md`) the console is
a `prompt_toolkit` footer pinned to the bottom of the terminal with the
session's log lines scrolling in a pane above it. It is the single delivery
surface for the project's live, mid-session capabilities — currently just the
EVCC charge-loop [[stall]] (issue #28).

Activation is opt-out with TTY auto-detection:

- ``runtime.console.mode == "off"`` (CLI ``--no-console``) → never active.
- stdout is a TTY → active.
- no TTY + ``mode == "on"`` (CLI ``--console``) → a console was explicitly
  requested but cannot run; log a warning and stay headless.
- no TTY + ``mode == "auto"`` (the default) → silently headless.

The silent-headless path is what keeps the conformance E2E layer (which spawns
the runners as ``stdout=PIPE`` subprocesses — see ADR-0003) and all CI/replay
paths untouched: no footer, no TUI, today's plain stdout logging behaviour.

**Why a full-screen TUI, not ``patch_stdout()``.** ADR-0004 originally chose
``patch_stdout()`` (print logs above a floating footer). That was measured to
fail acceptance criterion #1: the virtual ISO-2 DC CurrentDemand loop emits
~2000 log lines/s, while ``patch_stdout`` only repaints the footer a few times
a second, so the footer's row is overwritten hundreds of times between redraws
and is visible <2% of the time. A full-screen layout instead routes log records
into a scrolling pane and repaints the *whole* frame (logs **and** footer)
atomically, so the footer is present in essentially every frame regardless of
log rate. The TUI only ever runs on a real TTY, so the E2E/CI stdout-marker
path — the reason ADR-0004 first rejected a TUI — is never on this codepath.
See ADR-0004 for the recorded reversal and the measured evidence.
"""

from __future__ import annotations

import collections
import logging
import sys
from typing import Awaitable

from app.shared.live_control import LiveControl

logger = logging.getLogger(__name__)

# How many recent log lines the scrolling pane retains. Bounded so a long
# stalled session (the CurrentDemand loop runs indefinitely) can't grow the
# pane's backing text without limit.
_LOG_PANE_LINES = 2000


def resolve_console_enabled(mode: str) -> bool:
    """Decide whether the operator console should run for this invocation.

    `mode` is `runtime.console.mode` — one of ``"auto"``, ``"on"``, ``"off"``.
    See the module docstring for the full truth table.
    """
    if mode == "off":
        return False

    if sys.stdout.isatty():
        return True

    # No TTY: only warn when a console was *explicitly* requested ("on");
    # the default ("auto") stays silently headless so piped/CI runs are quiet.
    if mode == "on":
        logger.warning(
            "Operator console requested (--console / console.mode=on) but "
            "stdout is not a TTY; running headless."
        )
    return False


class _LogPaneHandler(logging.Handler):
    """Routes formatted log records into the console's scrolling pane.

    While the operator console is active the root logger's stdout
    `StreamHandler` is replaced by one of these (see `_route_logging_to_pane`),
    so log output flows into the prompt_toolkit log pane instead of writing
    straight to the terminal and corrupting the full-screen frame. The original
    formatter and level are copied over, so the on-screen log text is identical
    to the headless path's.
    """

    def __init__(self, lines: "collections.deque[str]", on_emit) -> None:
        super().__init__()
        self._lines = lines
        self._on_emit = on_emit

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:  # noqa: BLE001 - mirror logging.Handler.emit's contract
            self.handleError(record)
            return
        # A record may format to multiple physical lines (e.g. tracebacks).
        for line in msg.split("\n"):
            self._lines.append(line)
        self._on_emit()


class _Console:
    """A built, not-yet-running operator console: the app plus its log pane.

    Bundled so `run_with_console` can drive the prompt_toolkit Application and
    feed the log pane from one place, while `_build_application` stays cheap to
    construct in tests (no TTY, no event loop).
    """

    def __init__(self, app, log_buffer, handler: _LogPaneHandler) -> None:
        self.app = app
        self.log_buffer = log_buffer
        self.handler = handler


def _build_application(live_control: LiveControl, source: str) -> _Console:
    """Build the full-screen console: a scrolling log pane above a 1-line footer.

    Kept importing `prompt_toolkit` lazily — it is only needed when a console is
    actually active, never on the headless E2E/CI path.
    """
    from prompt_toolkit.application import Application
    from prompt_toolkit.buffer import Buffer
    from prompt_toolkit.document import Document
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.layout import Layout
    from prompt_toolkit.layout.containers import HSplit, Window
    from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
    from prompt_toolkit.styles import Style

    lines: "collections.deque[str]" = collections.deque(maxlen=_LOG_PANE_LINES)
    # read_only so the pane is display-only; we mutate it via bypass_readonly.
    log_buffer = Buffer(read_only=True)

    kb = KeyBindings()

    @kb.add("s")
    def _toggle_stall(event) -> None:
        live_control.toggle_charge_loop_stall()
        event.app.invalidate()

    @kb.add("a")
    def _advance(event) -> None:
        live_control.release_charge_loop()
        event.app.invalidate()

    def render_footer():
        state = "ARMED" if live_control.stall_charge_loop else "off"
        return [
            ("class:footer", f" AcCCS {source} "),
            ("class:footer", f"│ charge-loop stall: {state} "),
            ("class:footer", "│ [s] toggle stall  [a] advance "),
        ]

    log_window = Window(
        content=BufferControl(buffer=log_buffer, focusable=False),
        wrap_lines=True,
    )
    footer = Window(
        content=FormattedTextControl(render_footer),
        height=1,
        style="class:footer",
    )

    app = Application(
        layout=Layout(HSplit([log_window, footer])),
        key_bindings=kb,
        style=Style.from_dict({"footer": "reverse"}),
        full_screen=True,
        refresh_interval=0.5,
    )

    def on_emit() -> None:
        # Rebuild the pane text from the (bounded) line buffer and keep the
        # cursor at the end so the Window tails to the newest line. The footer
        # is a separate control repainted every frame, so its visibility never
        # depends on this; invalidate just nudges the log pane to refresh.
        text = "\n".join(lines)
        log_buffer.set_document(
            Document(text, cursor_position=len(text)), bypass_readonly=True
        )
        if app.is_running:
            app.invalidate()

    handler = _LogPaneHandler(lines, on_emit)
    return _Console(app, log_buffer, handler)


def _route_logging_to_pane(handler: _LogPaneHandler):
    """Swap the root logger's stdout StreamHandler for the pane `handler`.

    The stdout console handler (`logging.conf` → ``StreamHandler(sys.stdout)``,
    built in `_init_logger`) writes straight to the terminal, which would
    corrupt the full-screen frame. We remove it for the console's lifetime and
    route logs into the pane instead, copying its formatter and level so the
    on-screen text matches the headless path. A `FileHandler` is a
    `StreamHandler` subclass but its stream is the log file (never the terminal
    stdout), so matching on stream *identity* leaves file logging untouched.

    Returns the removed handlers so the caller can restore them on exit.
    """
    root = logging.getLogger()
    terminal_stdout = sys.stdout
    removed = []
    for existing in list(root.handlers):
        if (
            isinstance(existing, logging.StreamHandler)
            and existing.stream is terminal_stdout
        ):
            handler.setFormatter(existing.formatter)
            handler.setLevel(existing.level)
            root.removeHandler(existing)
            removed.append(existing)
    root.addHandler(handler)
    return removed


def _restore_logging(handler: _LogPaneHandler, removed) -> None:
    """Undo `_route_logging_to_pane`: drop the pane handler, restore the originals."""
    root = logging.getLogger()
    root.removeHandler(handler)
    for existing in removed:
        root.addHandler(existing)


async def run_with_console(
    live_control: LiveControl,
    main_coro: Awaitable[None],
    *,
    source: str,
) -> None:
    """Run `main_coro` under the full-screen operator console.

    The session's log lines scroll in a pane above a pinned 1-line footer; the
    whole frame is repainted atomically, so the footer stays visible at any log
    rate (see the module docstring for why this replaced ``patch_stdout()``).
    The console is torn down — and stdout logging restored — when `main_coro`
    completes or raises: the session, not the footer, owns the lifetime.
    """
    import asyncio

    console = _build_application(live_control, source)
    removed = _route_logging_to_pane(console.handler)

    main_task = asyncio.ensure_future(main_coro)
    ui_task = asyncio.ensure_future(console.app.run_async())
    try:
        await main_task
    finally:
        if console.app.is_running:
            console.app.exit()
        # Drain the UI task; never let a footer teardown error mask the
        # session's own result/exception.
        try:
            await ui_task
        except Exception:  # noqa: BLE001 - footer teardown is best-effort
            logger.debug(
                "Operator console UI task ended with an exception", exc_info=True
            )
        # Restore stdout logging so anything outside this context (and the
        # headless path) is unaffected by the console's handler swap.
        _restore_logging(console.handler, removed)
