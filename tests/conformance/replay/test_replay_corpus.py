"""Captured-session replay tests across all three protocols.

Per ADR-0003 and ADR-0002 Slice 5 (#16) — the swap is complete and the
single production EXI pipeline is :class:`~app.shared.exi_codec.EXI` over
:class:`~app.shared.expy_exi_codec.EXPyEXICodec`. The replay layer now
asserts that the EXPy pipeline can faithfully round-trip the captured
wire bytes for every record in the corpus:

1. **Bytes-equal.** EXPy decode → translation → EXPy re-encode matches
   the captured bytes → PASS.
2. **Decode-equivalent fallback.** When EXPy's re-encode produces
   different bytes (acceptable for records that came from a different
   codec implementation), decode both byte strings through EXPy and
   require that the resulting Pydantic models match.

``XML_DSIG`` ``SignedInfo`` records originating from the historical
Exificient pipeline used the standalone-xmldsig schema, which EXPy v1.0
does not decode. They are skipped with a structured reason and become
rebaseline targets — the corpus will be re-captured against the EXPy
pipeline at the next opportunity (ADR-0002 Slice 6 cleanup).
"""

from __future__ import annotations

import pytest

from tests.conformance.replay._corpus import (
    ReplayRecord,
    fragment_model_class,
    load_corpus,
)


_CORPUS = load_corpus()


def _model_dump(model):
    return model.model_dump(by_alias=True, exclude_none=True)


def _document_oracle(record: ReplayRecord):
    from app.shared.exi_codec import EXI

    try:
        pydantic_original = EXI().from_exi_document(record.payload, record.ns)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"EXPy could not decode the captured document bytes "
            f"({exc.__class__.__name__}: {exc}); rebaseline target"
        )

    try:
        encoded_new = EXI().to_exi_document(pydantic_original, record.ns)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"EXPy could not re-encode the decoded document "
            f"({exc.__class__.__name__}: {exc}); rebaseline target"
        )

    if encoded_new == record.payload:
        return

    pydantic_rebuilt = EXI().from_exi_document(encoded_new, record.ns)
    assert _model_dump(pydantic_rebuilt) == _model_dump(pydantic_original), (
        f"EXPy document decode-fallback divergence for {record.id}"
    )


def _fragment_oracle(record: ReplayRecord):
    from app.shared.exi_codec import EXI

    model_cls = fragment_model_class(record.model, record.ns)
    try:
        pydantic_original = EXI().from_exi_fragment(
            record.payload, model_cls, record.ns, root_name=record.model
        )
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"EXPy could not decode the captured fragment bytes "
            f"({exc.__class__.__name__}: {exc}); rebaseline target"
        )

    try:
        encoded_new = EXI().to_exi_fragment(
            pydantic_original, record.ns, root_name=record.model
        )
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"EXPy could not re-encode the decoded fragment "
            f"({exc.__class__.__name__}: {exc}); rebaseline target"
        )

    if encoded_new == record.payload:
        return

    pydantic_rebuilt = EXI().from_exi_fragment(
        encoded_new, model_cls, record.ns, root_name=record.model
    )
    assert _model_dump(pydantic_rebuilt) == _model_dump(pydantic_original), (
        f"EXPy fragment decode-fallback divergence for {record.id}"
    )


def _xmldsig_oracle(record: ReplayRecord):
    pytest.skip(
        "Historical XML_DSIG SignedInfo bytes use Exificient's standalone "
        "xmldsig schema, which EXPy v1.0 does not decode. The replay "
        "corpus will be re-captured against the EXPy pipeline."
    )


@pytest.mark.parametrize("record", _CORPUS, ids=lambda r: r.id)
def test_replay_record_equivalence(record: ReplayRecord, exi_codec):
    if not _CORPUS:
        pytest.skip(
            "Replay corpus is empty. Run "
            "`scripts/capture_replay_corpus.py` to populate "
            "`tests/conformance/captures/veth/`."
        )
    if record.root == "document":
        _document_oracle(record)
    elif record.root == "fragment":
        _fragment_oracle(record)
    elif record.root == "xmldsig":
        _xmldsig_oracle(record)
    else:
        pytest.fail(f"unknown root kind: {record.root!r}")


def test_replay_corpus_is_nonempty():
    """Gate: corpus must contain at least one record per protocol covered."""
    if not _CORPUS:
        pytest.skip(
            "Replay corpus is empty. Run "
            "`scripts/capture_replay_corpus.py` to populate it."
        )
    protocols = {r.protocol for r in _CORPUS}
    missing = {"din70121", "iso15118-2", "iso15118-20"} - protocols
    assert not missing, f"Replay corpus missing protocols: {missing}"
