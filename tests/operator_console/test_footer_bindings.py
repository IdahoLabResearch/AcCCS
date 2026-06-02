"""The footer's [s]/[a] key bindings drive LiveControl (ADR-0004, issue #28).

These exercise the live-toggle path without needing a real TTY: build the
prompt_toolkit Application and invoke its bound handlers directly, asserting
they mutate the shared LiveControl. (Actual rendering + physical keypresses
are the one piece that requires a human terminal.)
"""

from __future__ import annotations

import types

from app.shared.console import _build_application
from app.shared.live_control import LiveControl


class _FakeEvent:
    """Minimal stand-in for a prompt_toolkit key-press event."""

    def __init__(self):
        self.app = types.SimpleNamespace(invalidate=lambda: None)


def _handler_for(app, key: str):
    for binding in app.key_bindings.bindings:
        if any(str(k) == key for k in binding.keys):
            return binding.handler
    raise AssertionError(f"no key binding registered for {key!r}")


def test_s_toggles_charge_loop_stall():
    lc = LiveControl()
    app = _build_application(lc, "EVCC").app
    handler = _handler_for(app, "s")

    handler(_FakeEvent())
    assert lc.stall_charge_loop is True
    handler(_FakeEvent())
    assert lc.stall_charge_loop is False


def test_a_releases_charge_loop_gate():
    lc = LiveControl(stall_charge_loop=True)
    app = _build_application(lc, "EVCC").app
    handler = _handler_for(app, "a")

    handler(_FakeEvent())
    # The advance handler set the one-shot release.
    assert lc.take_charge_loop_release() is True
