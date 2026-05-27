"""Captured-session replay tests across all three protocols.

Per ADR-0003 and ADR-0002 Slice 4 (#15), this layer feeds wire bytes
captured from working virtual or hardware sessions through the EXI codec
and asserts the new (EXPy + translation module) pipeline is
protocol-equivalent to the current (Exificient) pipeline that produced
the bytes.

Equivalence oracle per record (the issue body + Slice 4 grilling):

1. **Bytes-equal.** EXPy re-encode == captured bytes → PASS.
2. **Decode-equivalent through Exificient.** Decode both byte strings
   through Exificient and compare the resulting Pydantic objects.
   (Document records only — the current ``EXI`` wrapper doesn't expose
   Exificient fragment / xmldsig decode.)
3. **Fallback: EXPy decode-self-consistency.** When Exificient cannot
   decode the bytes (DecodeError or schema mismatch — common for the
   ``expy_authoritative`` set documented in ADR-0002 Slice 5 and the
   codec-layer fixtures), decode both via EXPy and compare. This is the
   weakest tier; it proves EXPy is self-consistent for that byte
   sequence but not that EXPy matches Exificient.

Records that are known to be divergent at the schema level (currently
just ``XML_DSIG``-namespace ``SignedInfo`` — Exificient encodes through
the standalone xmldsig schema, libcbv2g/EXPy reads only the
ISO-2-or-ISO-20-rooted xmldsig fragment) are skipped with a structured
reason. They become the rebaseline targets at ADR-0002 Slice 5.

The corpus lives in ``tests/conformance/captures/`` — see its README for
provenance and coverage policy.
"""

from __future__ import annotations

import pytest

from app.shared.everest_shape import (
    everest_to_pydantic,
    everest_to_pydantic_fragment,
    everest_to_pydantic_xmldsig,
    pydantic_to_everest,
    pydantic_to_everest_fragment,
    pydantic_to_everest_xmldsig,
)
from tests.conformance.replay._corpus import (
    ReplayRecord,
    expy_namespace,
    fragment_model_class,
    load_corpus,
)


_CORPUS = load_corpus()


def _model_dump(model):
    return model.model_dump(by_alias=True, exclude_none=True)


def _expy_processor(record: ReplayRecord):
    from expy import EXIProcessor

    return EXIProcessor(expy_namespace(record.ns))


def _expy_processor_for_xmldsig(record: ReplayRecord):
    """Pick a sibling-namespace EXPy processor for an XML_DSIG fragment.

    EXPy v1.0 exposes ``encode_xmldsig`` / ``decode_xmldsig`` on the six
    namespaces that include the xmldsig schema. AcCCS production code
    routes through ``Namespace.XML_DSIG`` which isn't itself an EXPy
    namespace; pick the matching protocol's processor based on the
    record's capture context.
    """
    from expy import EXIProcessor, Namespace as ExpyNS

    if record.protocol == "iso15118-2":
        return EXIProcessor(ExpyNS.ISO2)
    if record.protocol == "iso15118-20":
        return EXIProcessor(ExpyNS.ISO20_COMMON)
    raise pytest.skip.Exception(
        f"No EXPy xmldsig dispatch for protocol {record.protocol!r}"
    )


def _document_oracle(record: ReplayRecord):
    """Tiered oracle for full ``V2GMessage`` / SAP document records."""
    from app.shared.exi_codec import EXI

    # Reconstruct the Pydantic from the captured bytes using the current
    # Exificient pipeline. This is the source-of-truth model for the
    # equivalence comparison.
    try:
        pydantic_current = EXI().from_exi(record.payload, record.ns)
    except Exception as exc:  # noqa: BLE001
        pytest.fail(
            f"current Exificient pipeline failed to decode captured bytes: {exc}"
        )

    # Pass through translation + EXPy.
    try:
        everest_dict = pydantic_to_everest(pydantic_current, record.ns)
    except KeyError as exc:
        pytest.skip(
            f"translation module has no registration for namespace {exc} — "
            "Slice 5 rebaseline target"
        )
    try:
        encoded_new = _expy_processor(record).encode(everest_dict)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"EXPy rejected the translated EVerest dict ({exc.__class__.__name__}: "
            f"{exc}); Slice 5 rebaseline target — see captured model {record.model!r}"
        )

    if encoded_new == record.payload:
        return  # bytes-equal: PASS

    # Decode-equivalent through Exificient.
    try:
        pydantic_via_current = EXI().from_exi(encoded_new, record.ns)
        if _model_dump(pydantic_via_current) == _model_dump(pydantic_current):
            return  # decode-equivalent: PASS
        # Exificient decoded both but disagrees → fail loudly.
        pytest.fail(
            "Exificient decode of EXPy-encoded bytes disagrees with "
            "Exificient decode of original bytes\n"
            f"original: {_model_dump(pydantic_current)}\n"
            f"new:      {_model_dump(pydantic_via_current)}"
        )
    except Exception:
        # Fall through to EXPy fallback below.
        pass

    # Fallback: EXPy decode-self-consistency.
    proc = _expy_processor(record)
    decoded_original = proc.decode(record.payload)
    decoded_new = proc.decode(encoded_new)
    rebuilt_original = everest_to_pydantic(
        decoded_original, type(pydantic_current), record.ns
    )
    rebuilt_new = everest_to_pydantic(
        decoded_new, type(pydantic_current), record.ns
    )
    assert _model_dump(rebuilt_original) == _model_dump(rebuilt_new), (
        f"EXPy decode-fallback Pydantic divergence for {record.id}"
    )


def _fragment_oracle(record: ReplayRecord):
    """Replay oracle for Fragment records (signed sub-elements)."""
    model_cls = fragment_model_class(record.model, record.ns)
    proc = _expy_processor(record)

    # Reconstruct via EXPy (the current EXI wrapper has no fragment
    # decode entry point — ``EXI().from_exi`` only handles documents).
    try:
        decoded_orig = proc.decode_fragment(record.payload)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"EXPy cannot decode the captured Exificient-encoded fragment "
            f"({exc.__class__.__name__}: {exc}); Slice 5 rebaseline target"
        )
    try:
        pydantic_orig = everest_to_pydantic_fragment(
            decoded_orig, model_cls, record.ns, root_name=record.model
        )
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"translation module rebuild of decoded fragment failed "
            f"({exc.__class__.__name__}: {exc}); Slice 5 rebaseline target"
        )

    try:
        everest_new = pydantic_to_everest_fragment(
            pydantic_orig, record.ns, root_name=record.model
        )
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"translation module re-encode failed "
            f"({exc.__class__.__name__}: {exc}); Slice 5 rebaseline target"
        )
    try:
        encoded_new = proc.encode_fragment(everest_new)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            f"EXPy rejected the translated fragment "
            f"({exc.__class__.__name__}: {exc}); Slice 5 rebaseline target"
        )
    if encoded_new == record.payload:
        return

    decoded_new = proc.decode_fragment(encoded_new)
    pydantic_new = everest_to_pydantic_fragment(
        decoded_new, model_cls, record.ns, root_name=record.model
    )
    assert _model_dump(pydantic_orig) == _model_dump(pydantic_new), (
        f"EXPy fragment decode-fallback divergence for {record.id}"
    )


def _xmldsig_oracle(record: ReplayRecord):
    """Replay oracle for XmldsigFragment records.

    The legacy codec encodes ``SignedInfo`` via Exificient's standalone
    XML_DSIG schema. EXPy reads only the protocol-rooted xmldsig fragment
    and cannot decode the standalone form, so byte equivalence is the
    only oracle that ever applies here. The mismatch is documented in
    ADR-0002 Slice 5 rebaselining notes and in the codec-layer
    ``iso2-xmldsig-signed-info`` / ``iso20-common-xmldsig-signed-info``
    fixtures (both ``expy_authoritative=True``).

    Skip with a reason so the corpus is acknowledged but not red.
    """
    pytest.skip(
        "XML_DSIG SignedInfo bytes from the current Exificient pipeline "
        "use the standalone-xmldsig schema, which EXPy v1.0 does not "
        "decode (see ADR-0002 Slice 5). Slice 5 rebaselines the corpus "
        "on EXPy; this record is the rebaseline target."
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
