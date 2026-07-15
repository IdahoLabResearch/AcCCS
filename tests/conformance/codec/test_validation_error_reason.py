"""``V2GMessageValidationError`` carries its reason into ``str(exc)``.

Regression for a diagnostic-cost bug surfaced while investigating #93. When a
decoded V2G message fails Pydantic validation, ``EXI._validation_error`` builds
a rich reason that names the offending field and the constraint it violated
(e.g. ``evse_id`` / ``String should have at most 64 characters``) and stores it
on ``.reason``. But ``V2GMessageValidationError.__init__`` used to call
``Exception.__init__(self)`` with *no* arguments, so ``str(exc)`` was the empty
string. The generic teardown handler in ``comm_session`` interpolates ``{exc}``
when composing the stop reason, so the one piece of information identifying the
cause rendered as nothing::

    Reason: V2GMessageValidationError occurred while processing message  in state SessionSetup : .

Passing ``reason`` through to the base class makes ``str(exc)`` correct at every
site that logs this exception, including the teardown line.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.shared.exceptions import V2GMessageValidationError
from app.shared.exi_codec import EXI
from app.shared.messages.din_spec.body import SessionSetupRes
from app.shared.messages.din_spec.datatypes import ResponseCode as ResponseCodeDIN
from app.shared.messages.enums import Namespace


def test_str_returns_reason():
    """``str(exc)`` is the reason, not the empty string (the whole bug)."""
    reason = "Validation error: evse_id too long. Decoded dict: {...}"
    exc = V2GMessageValidationError(
        reason, ResponseCodeDIN.FAILED, SessionSetupRes
    )

    assert str(exc) == reason


def test_attributes_survive_for_existing_callers():
    """``.reason``, ``.response_code``, ``.message`` remain available."""
    reason = "some reason"
    exc = V2GMessageValidationError(
        reason, ResponseCodeDIN.FAILED, SessionSetupRes
    )

    assert exc.reason == reason
    assert exc.response_code == ResponseCodeDIN.FAILED
    assert exc.message is SessionSetupRes


def test_codec_built_error_names_the_offending_field():
    """The real ``_validation_error`` path renders the field in ``str(exc)``.

    This is the teardown-log path: a genuine Pydantic ``ValidationError`` is
    turned into a ``V2GMessageValidationError`` whose string form must name the
    field so the stop reason is actionable rather than ``: .``.
    """
    try:
        # An EVSEID one byte past DIN's 32-byte schema maximum: guaranteed to
        # raise, and the Pydantic error names the field and its length bound.
        SessionSetupRes(response_code="OK", evse_id="AB" * 33)
    except ValidationError as pydantic_exc:
        exc = EXI()._validation_error(
            pydantic_exc,
            {"Body": {"SessionSetupRes": {}}},
            Namespace.DIN_MSG_DEF,
            SessionSetupRes,
        )
    else:  # pragma: no cover - the model must reject an over-length EVSEID
        pytest.fail("an EVSEID past the schema maximum should fail validation")

    rendered = str(exc)
    assert rendered, "str(exc) must not be the empty string"
    assert rendered == exc.reason
    # The identifying detail that used to be thrown away one attribute short of
    # the log line: the field name and the constraint it violated.
    assert "evse_id" in rendered
    assert "at most" in rendered
