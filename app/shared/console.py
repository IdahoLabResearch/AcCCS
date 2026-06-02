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

import asyncio
import collections
import logging
import sys
from dataclasses import dataclass
from typing import Awaitable, Optional

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

    `emit` runs on whatever thread emitted the record — the scapy SLAC sniffer
    thread and any `loop.run_in_executor` worker do **not** run on the asyncio/UI
    thread. The bounded line deque is appended on the calling thread (a `deque`
    append is atomic enough), but the `on_emit` refresh touches prompt_toolkit
    (`Buffer.set_document` / `Application.invalidate`), which is not thread-safe.
    So once the UI loop is bound (`bind_loop`), off-loop refreshes are marshalled
    onto it via `call_soon_threadsafe`; on-loop and not-yet-running refreshes run
    inline (issue #33).
    """

    def __init__(self, lines: "collections.deque[str]", on_emit) -> None:
        super().__init__()
        self._lines = lines
        self._on_emit = on_emit
        # The UI event loop, captured by `bind_loop` once the console is running.
        # `None` means no loop is live (before start / after teardown / in unit
        # tests using the handler standalone).
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Capture the UI event loop so off-loop refreshes can be marshalled onto it."""
        self._loop = loop

    def unbind_loop(self) -> None:
        """Drop the loop reference at teardown so no refresh is scheduled onto a closing loop."""
        self._loop = None

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:  # noqa: BLE001 - mirror logging.Handler.emit's contract
            self.handleError(record)
            return
        # A record may format to multiple physical lines (e.g. tracebacks).
        # The deque append stays on the calling thread; only the prompt_toolkit
        # refresh below is thread-sensitive.
        for line in msg.split("\n"):
            self._lines.append(line)
        self._dispatch_refresh()

    def _dispatch_refresh(self) -> None:
        """Run the pane refresh on the UI loop thread, marshalling if need be.

        - No loop bound → run inline. The console is not running its loop, so
          there is no concurrent UI thread to corrupt; `on_emit` no-ops its
          `invalidate` when the app is not running.
        - Already on the UI loop thread → run inline (avoids deferring the
          common case, where the asyncio session logs from its own loop).
        - Off the UI loop thread → `call_soon_threadsafe`, so the buffer
          mutation and `invalidate` happen on the UI thread.
        """
        loop = self._loop
        if loop is None:
            self._on_emit()
            return
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            self._on_emit()
        else:
            loop.call_soon_threadsafe(self._on_emit)


@dataclass
class _EntryState:
    """Operator value-entry state for the override footer (issue #29).

    `mode` is None when not entering a value, else "current"/"voltage"; `text`
    accumulates the typed digits; `message` is transient footer feedback (last
    commit result or a parse error). A small dataclass rather than a dict so the
    field names are typo-checked instead of failing only at runtime.
    """

    mode: Optional[str] = None
    text: str = ""
    message: str = ""


def _apply_override(live_control: LiveControl, field: str, text: str) -> str:
    """Parse operator-typed text and apply it as a live override (issue #29).

    `field` is ``"current"`` or ``"voltage"``. Returns a short status string for
    the footer's transient feedback line. Values are **unchecked** — anything
    that parses as a number is stored verbatim (no clamping to the personality
    envelope); a value the EXI codec can't ultimately encode surfaces as a codec
    error downstream, which is acceptable per ADR-0004. Non-numeric input is
    rejected here (it could never be encoded) and leaves the override untouched.
    """
    raw = text.strip()
    try:
        value = float(raw)
    except ValueError:
        return f"invalid {field}: {raw!r}"
    if field == "current":
        live_control.set_override_current(value)
        return f"override current = {value} A"
    live_control.set_override_voltage(value)
    return f"override voltage = {value} V"


class _Console:
    """A built, not-yet-running operator console: the app plus its log pane.

    Bundled so `run_with_console` can drive the prompt_toolkit Application and
    feed the log pane from one place, while `_build_application` stays cheap to
    construct in tests (no TTY, no event loop). `_build_application` also attaches
    the override-entry hooks (`entry`, `commit`) as attributes so tests can drive
    a value commit without a real keyboard.
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
    from prompt_toolkit.filters import Condition
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.layout import Layout
    from prompt_toolkit.layout.containers import HSplit, Window
    from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
    from prompt_toolkit.styles import Style

    lines: "collections.deque[str]" = collections.deque(maxlen=_LOG_PANE_LINES)
    # read_only so the pane is display-only; we mutate it via bypass_readonly.
    log_buffer = Buffer(read_only=True)

    # Override-entry state (issue #29). The single `_EntryState` instance is
    # shared by every key handler via closure (one mutable cell).
    #
    # We capture digits with our own key bindings into `text` rather than focusing
    # a prompt_toolkit input buffer: the value line is only ever a handful of
    # characters, and app-level key bindings fire regardless of focus, so this
    # sidesteps the focus/visibility juggling a hidden BufferControl would need.
    entry = _EntryState()
    in_entry = Condition(lambda: entry.mode is not None)
    not_entry = ~in_entry

    kb = KeyBindings()

    # Action keys are gated off while entering a value, so a stray 's'/'c'/etc.
    # can't fire an action mid-number (it is simply ignored — only the value
    # keys below are live in entry mode).
    @kb.add("s", filter=not_entry)
    def _toggle_stall(event) -> None:
        live_control.toggle_charge_loop_stall()
        event.app.invalidate()

    @kb.add("a", filter=not_entry)
    def _advance(event) -> None:
        live_control.release_charge_loop()
        event.app.invalidate()

    @kb.add("c", filter=not_entry)
    def _set_current(event) -> None:
        _enter_mode("current")
        event.app.invalidate()

    @kb.add("v", filter=not_entry)
    def _set_voltage(event) -> None:
        _enter_mode("voltage")
        event.app.invalidate()

    @kb.add("x", filter=not_entry)
    def _clear_overrides(event) -> None:
        live_control.clear_overrides()
        entry.message = "overrides cleared"
        event.app.invalidate()

    # Value-entry keys, live only while a value is being typed.
    for _ch in "0123456789.-":

        @kb.add(_ch, filter=in_entry)
        def _append(event, ch=_ch) -> None:
            entry.text += ch
            event.app.invalidate()

    @kb.add("backspace", filter=in_entry)
    def _backspace(event) -> None:
        entry.text = entry.text[:-1]
        event.app.invalidate()

    @kb.add("enter", filter=in_entry)
    def _commit(event) -> None:
        entry.message = _apply_override(live_control, entry.mode, entry.text)
        _exit_mode()
        event.app.invalidate()

    @kb.add("escape", filter=in_entry)
    def _cancel_entry(event) -> None:
        _exit_mode()
        entry.message = "entry cancelled"
        event.app.invalidate()

    def _enter_mode(mode: str) -> None:
        entry.mode = mode
        entry.text = ""
        entry.message = ""

    def _exit_mode() -> None:
        entry.mode = None
        entry.text = ""

    def _fmt(value, unit):
        return f"{value:g} {unit}" if value is not None else "auto"

    def render_footer():
        state = "ARMED" if live_control.stall_charge_loop else "off"
        cur = _fmt(live_control.override_current_a, "A")
        volt = _fmt(live_control.override_voltage_v, "V")
        if entry.mode:
            label = "current (A)" if entry.mode == "current" else "voltage (V)"
            return [
                ("class:footer", f" AcCCS {source} │ set {label}: "),
                ("class:footer", entry.text or "_"),
                ("class:footer", "  [enter] commit  [esc] cancel "),
            ]
        parts = [
            ("class:footer", f" AcCCS {source} "),
            ("class:footer", f"│ charge-loop stall: {state} "),
            ("class:footer", f"│ override I:{cur} V:{volt} "),
            ("class:footer", "│ [s] stall  [a] advance  [c] set-I  [v] set-V  [x] clear "),
        ]
        if entry.message:
            parts.append(("class:footer", f"│ {entry.message} "))
        return parts

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
    console = _Console(app, log_buffer, handler)
    # Override-entry hooks, exposed for tests to drive a commit headlessly.
    console.entry = entry
    console.commit = _commit
    return console


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
    console = _build_application(live_control, source)
    # Capture the UI loop and arm the handler *before* routing logs into it, so
    # any record the pane handler receives can be marshalled onto this loop
    # rather than touching prompt_toolkit from an off-loop thread (issue #33).
    console.handler.bind_loop(asyncio.get_running_loop())
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
        # Stop marshalling onto a loop that's about to close, then restore stdout
        # logging so anything outside this context (and the headless path) is
        # unaffected by the console's handler swap.
        console.handler.unbind_loop()
        _restore_logging(console.handler, removed)
