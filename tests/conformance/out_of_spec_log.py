"""Assertions over the out-of-spec warning the message models emit (issue #124).

Every tolerant validator logs through ``app.shared.messages.out_of_spec``;
tests in the codec and state-machine layers assert on that one logger here.
"""

from __future__ import annotations

import logging

OUT_OF_SPEC_LOGGER = "app.shared.messages.out_of_spec"


def out_of_spec_records(caplog) -> list[logging.LogRecord]:
    return [
        rec
        for rec in caplog.records
        if rec.name == OUT_OF_SPEC_LOGGER and rec.levelno == logging.WARNING
    ]


def assert_single_out_of_spec_warning(caplog, *needles: object) -> None:
    """Exactly one warning was logged, and it names every needle."""
    records = out_of_spec_records(caplog)
    assert len(records) == 1, [rec.getMessage() for rec in records]
    text = records[0].getMessage()
    for needle in needles:
        assert str(needle) in text, f"{needle!r} missing from out-of-spec line: {text}"
