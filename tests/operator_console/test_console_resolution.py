"""Tests for operator-console TTY auto-detection (ADR-0004, issue #28)."""

from __future__ import annotations

import logging
import sys

import pytest

from app.shared.console import resolve_console_enabled


@pytest.fixture
def tty(monkeypatch: pytest.MonkeyPatch):
    # pytest's capture plugin owns sys.stdout, so patch isatty() on the live
    # object rather than swapping the whole stream out.
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)


@pytest.fixture
def no_tty(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)


def test_off_never_runs_even_on_tty(tty):
    assert resolve_console_enabled("off") is False


def test_auto_runs_on_tty(tty):
    assert resolve_console_enabled("auto") is True


def test_on_runs_on_tty(tty):
    assert resolve_console_enabled("on") is True


def test_auto_silently_headless_without_tty(no_tty, caplog):
    with caplog.at_level(logging.WARNING):
        assert resolve_console_enabled("auto") is False
    # The default path stays quiet — no warning spam for piped/CI runs.
    assert caplog.records == []


def test_on_warns_when_no_tty(no_tty, caplog):
    with caplog.at_level(logging.WARNING):
        assert resolve_console_enabled("on") is False
    assert any("not a TTY" in r.message for r in caplog.records)


def test_off_silent_without_tty(no_tty, caplog):
    with caplog.at_level(logging.WARNING):
        assert resolve_console_enabled("off") is False
    assert caplog.records == []
