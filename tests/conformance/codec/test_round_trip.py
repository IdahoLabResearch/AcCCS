"""Codec-layer round-trip oracle.

For every fixture in :data:`fixtures.FIXTURES`:

- encode the pydantic model and assert it equals the golden byte sequence;
- decode the golden byte sequence and assert it round-trips back to an
  equivalent pydantic model.

This is the oracle described by ADR-0003's codec layer:

> byte-for-byte equality on encode; decoded-Pydantic equality on decode.

Per ADR-0002 the corpus is rebaselined against EXPy at Slice 5 (#16). The
``expy_authoritative`` flag is now redundant — every golden is produced by
the EXPy codec via the unified :class:`~app.shared.exi_codec.EXI` wrapper.
"""

from __future__ import annotations

import pytest

from tests.conformance.codec.fixtures import FIXTURES, CodecFixture


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda f: f.id)
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

    if fixture.root_kind == "document":
        encoded = EXI().to_exi_document(message, fixture.namespace)
    elif fixture.root_kind == "fragment":
        encoded = EXI().to_exi_fragment(
            message, fixture.namespace, root_name=fixture.root_name
        )
    elif fixture.root_kind == "xmldsig":
        encoded = EXI().to_exi_xmldsig(
            message, fixture.namespace, root_name=fixture.root_name
        )
    else:
        pytest.fail(f"unknown root_kind {fixture.root_kind!r} for {fixture.id}")

    assert encoded == expected_bytes, (
        f"encode drift for {fixture.id}: codec produced {encoded.hex()} but "
        f"golden was {expected_bytes.hex()}"
    )

    model_cls = fixture.decode_model_cls
    if fixture.root_kind == "document":
        decoded = EXI().from_exi_document(
            expected_bytes, fixture.namespace, model_cls=model_cls
        )
    elif fixture.root_kind == "fragment":
        decoded = EXI().from_exi_fragment(
            expected_bytes,
            model_cls,
            fixture.namespace,
            root_name=fixture.root_name,
        )
    else:
        decoded = EXI().from_exi_xmldsig(
            expected_bytes,
            model_cls,
            fixture.namespace,
            root_name=fixture.root_name,
        )

    # Pydantic-level equality. ``model_dump`` strips Python identity but keeps
    # field values, which is exactly the oracle ADR-0003 specifies.
    assert decoded.model_dump(by_alias=True, exclude_none=True) == message.model_dump(
        by_alias=True, exclude_none=True
    ), f"decode drift for {fixture.id}"
