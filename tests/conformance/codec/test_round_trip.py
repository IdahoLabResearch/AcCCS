"""Codec-layer round-trip oracle.

For every fixture in `fixtures.FIXTURES`:

- encode the pydantic model and assert it equals the golden byte sequence,
- decode the golden byte sequence and assert it round-trips back to an
  equivalent pydantic model.

This is the oracle described by ADR-0003's codec layer:

> byte-for-byte equality on encode; decoded-Pydantic equality on decode.

Per ADR-0003 the corpus is bootstrapped from the current Exificient codec
during ADR-0002 Slices 1–3 and rebaselined against EXPy at Slice 5.
"""

from __future__ import annotations

import pytest

from tests.conformance.codec.fixtures import FIXTURES, CodecFixture

# The legacy ``EXI()`` wrapper only handles full ``V2GMessage`` documents on
# decode (it unwraps a ``V2G_Message`` key). Fragment / XmldsigFragment
# payloads added in ADR-0002 Slice 2+ are exercised by the dedicated EXPy
# tests under ``tests/expy/`` instead.
_DOCUMENT_FIXTURES = [f for f in FIXTURES if f.root_kind == "document"]


@pytest.mark.parametrize("fixture", _DOCUMENT_FIXTURES, ids=lambda f: f.id)
def test_codec_round_trip(fixture: CodecFixture, exi_codec):
    from app.shared.exi_codec import EXI

    if not fixture.golden_path.exists():
        pytest.fail(
            f"Missing golden bytes for fixture {fixture.id!r} at "
            f"{fixture.golden_path}. Regenerate via "
            f"`scripts/regen_codec_goldens.py` (see ADR-0003)."
        )

    expected_bytes = fixture.golden_path.read_bytes()
    message = fixture.build()

    encoded = EXI().to_exi(message, fixture.namespace)
    assert encoded == expected_bytes, (
        f"encode drift for {fixture.id}: codec produced {encoded.hex()} but "
        f"golden was {expected_bytes.hex()}"
    )

    decoded = EXI().from_exi(expected_bytes, fixture.namespace)
    # Pydantic-level equality. `model_dump` strips Python identity but keeps
    # field values, which is exactly the oracle ADR-0003 specifies.
    assert decoded.model_dump(by_alias=True, exclude_none=True) == message.model_dump(
        by_alias=True, exclude_none=True
    ), f"decode drift for {fixture.id}"
