"""DIN fixture-pair tests for the Pydantic↔EVerest translation module.

For every DIN ``CodecFixture`` registered in ``tests/conformance/codec/fixtures.py``:

- ``pydantic_to_everest`` produces an EVerest dict, EXPy encodes it, and the
  resulting bytes equal the Exificient-generated golden (see ADR-0002 Slice 5
  for the rebaselining plan).
- EXPy decodes the same golden bytes, ``everest_to_pydantic`` rebuilds the
  Pydantic model, and the round-tripped instance matches the original.

This module verifies the translation walker only — the production EXI wrapper
is still wired to Exificient (Slice 5 swaps it).
"""
from __future__ import annotations

import pytest

from app.shared.everest_shape import everest_to_pydantic, pydantic_to_everest
from tests.conformance.codec.fixtures import FIXTURES, CodecFixture

_DIN_FIXTURES = [f for f in FIXTURES if f.protocol == "din70121"]


def _expy_processor():
    from expy import EXIProcessor, Namespace

    return EXIProcessor(Namespace.DIN)


@pytest.mark.parametrize("fixture", _DIN_FIXTURES, ids=lambda f: f.id)
def test_din_translate_encode_matches_golden(fixture: CodecFixture):
    if not fixture.golden_path.exists():
        pytest.fail(
            f"Missing golden bytes for fixture {fixture.id!r}. "
            f"Regenerate via scripts/regen_codec_goldens.py."
        )
    message = fixture.build()
    everest = pydantic_to_everest(message, fixture.namespace)
    encoded = _expy_processor().encode(everest)
    expected = fixture.golden_path.read_bytes()
    assert encoded == expected, (
        f"EXPy encode drift for {fixture.id}: got {encoded.hex()} "
        f"vs golden {expected.hex()}"
    )


@pytest.mark.parametrize("fixture", _DIN_FIXTURES, ids=lambda f: f.id)
def test_din_translate_decode_round_trips(fixture: CodecFixture):
    if not fixture.golden_path.exists():
        pytest.fail(
            f"Missing golden bytes for fixture {fixture.id!r}. "
            f"Regenerate via scripts/regen_codec_goldens.py."
        )
    expected_bytes = fixture.golden_path.read_bytes()
    decoded_dict = _expy_processor().decode(expected_bytes)
    original = fixture.build()
    rebuilt = everest_to_pydantic(decoded_dict, type(original), fixture.namespace)
    # Compare via model_dump — Pydantic model identity differs but field
    # values are the oracle (ADR-0003 codec-layer convention).
    assert rebuilt.model_dump(by_alias=True, exclude_none=True) == original.model_dump(
        by_alias=True, exclude_none=True
    ), f"EXPy decode drift for {fixture.id}"
