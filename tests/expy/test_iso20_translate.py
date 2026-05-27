"""ISO 15118-20 fixture-pair tests for the Pydantic↔EVerest translation module.

Covers all five ISO-20 sub-namespaces and the root types EXPy v1.0 exposes:

- **Document** — every sub-namespace (``ISO20_COMMON``, ``ISO20_AC``,
  ``ISO20_DC``, ``ISO20_WPT``, ``ISO20_ACDP``) through ``encode`` / ``decode``.
  Energy services AC, AC-BPT, DC, DC-BPT, WPT, and ACDP each get a fixture.
- **Fragment** — ``PnC_AReqAuthorizationMode`` (the signed PnC auth params,
  see ``app/evcc/states/iso15118_20_states.py`` once Slice 5 lands).
- **XmldsigFragment** — ``SignedInfo`` rooted in ISO-20 common.

ISO-20 fragment / xmldsig only attach to the three signed-element processors
(``ISO20_COMMON``, ``ISO20_AC``, ``ISO20_DC``) per EXPy v1.0; WPT and ACDP
expose Document only.

Every ISO-20 fixture is :attr:`~CodecFixture.expy_authoritative` because
Exificient and EXPy diverge on ISO-20 today (signed-info canonicalisation,
optional-key encoding) — see ADR-0002 Slice 5.
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
from app.shared.messages.enums import Namespace
from tests.conformance.codec.fixtures import FIXTURES, CodecFixture

_ISO20_FIXTURES = [f for f in FIXTURES if f.protocol == "iso15118-20"]
_DOC = [f for f in _ISO20_FIXTURES if f.root_kind == "document"]
_FRAG = [f for f in _ISO20_FIXTURES if f.root_kind == "fragment"]
_XMLDSIG = [f for f in _ISO20_FIXTURES if f.root_kind == "xmldsig"]


_NAMESPACE_TO_EXPY = {
    Namespace.ISO_V20_COMMON_MSG: "ISO20_COMMON",
    Namespace.ISO_V20_AC: "ISO20_AC",
    Namespace.ISO_V20_DC: "ISO20_DC",
    Namespace.ISO_V20_WPT: "ISO20_WPT",
    Namespace.ISO_V20_ACDP: "ISO20_ACDP",
}


def _expy_processor(namespace: str):
    from expy import EXIProcessor, Namespace as ExpyNamespace

    return EXIProcessor(getattr(ExpyNamespace, _NAMESPACE_TO_EXPY[namespace]))


def _require_golden(fixture: CodecFixture) -> bytes:
    if not fixture.golden_path.exists():
        pytest.fail(
            f"Missing golden bytes for fixture {fixture.id!r}. "
            f"Regenerate via scripts/regen_codec_goldens.py."
        )
    return fixture.golden_path.read_bytes()


def _model_equal(left, right) -> bool:
    return left.model_dump(by_alias=True, exclude_none=True) == right.model_dump(
        by_alias=True, exclude_none=True
    )


@pytest.mark.parametrize("fixture", _DOC, ids=lambda f: f.id)
def test_iso20_document_encode_matches_golden(fixture: CodecFixture):
    expected = _require_golden(fixture)
    message = fixture.build()
    everest = pydantic_to_everest(message, fixture.namespace)
    encoded = _expy_processor(fixture.namespace).encode(everest)
    assert encoded == expected, (
        f"EXPy document encode drift for {fixture.id}: got {encoded.hex()} "
        f"vs golden {expected.hex()}"
    )


@pytest.mark.parametrize("fixture", _DOC, ids=lambda f: f.id)
def test_iso20_document_decode_round_trips(fixture: CodecFixture):
    expected = _require_golden(fixture)
    decoded = _expy_processor(fixture.namespace).decode(expected)
    original = fixture.build()
    rebuilt = everest_to_pydantic(decoded, type(original), fixture.namespace)
    assert _model_equal(rebuilt, original), (
        f"EXPy document decode drift for {fixture.id}"
    )


@pytest.mark.parametrize("fixture", _FRAG, ids=lambda f: f.id)
def test_iso20_fragment_encode_matches_golden(fixture: CodecFixture):
    expected = _require_golden(fixture)
    message = fixture.build()
    everest = pydantic_to_everest_fragment(
        message, fixture.namespace, root_name=fixture.root_name
    )
    encoded = _expy_processor(fixture.namespace).encode_fragment(everest)
    assert encoded == expected, (
        f"EXPy fragment encode drift for {fixture.id}: got {encoded.hex()} "
        f"vs golden {expected.hex()}"
    )


@pytest.mark.parametrize("fixture", _FRAG, ids=lambda f: f.id)
def test_iso20_fragment_decode_round_trips(fixture: CodecFixture):
    expected = _require_golden(fixture)
    decoded = _expy_processor(fixture.namespace).decode_fragment(expected)
    original = fixture.build()
    rebuilt = everest_to_pydantic_fragment(
        decoded,
        fixture.decode_model_cls,
        fixture.namespace,
        root_name=fixture.root_name,
    )
    assert _model_equal(rebuilt, original), (
        f"EXPy fragment decode drift for {fixture.id}"
    )


@pytest.mark.parametrize("fixture", _XMLDSIG, ids=lambda f: f.id)
def test_iso20_xmldsig_encode_matches_golden(fixture: CodecFixture):
    expected = _require_golden(fixture)
    message = fixture.build()
    everest = pydantic_to_everest_xmldsig(
        message, fixture.namespace, root_name=fixture.root_name
    )
    encoded = _expy_processor(fixture.namespace).encode_xmldsig(everest)
    assert encoded == expected, (
        f"EXPy xmldsig encode drift for {fixture.id}: got {encoded.hex()} "
        f"vs golden {expected.hex()}"
    )


@pytest.mark.parametrize("fixture", _XMLDSIG, ids=lambda f: f.id)
def test_iso20_xmldsig_decode_round_trips(fixture: CodecFixture):
    expected = _require_golden(fixture)
    decoded = _expy_processor(fixture.namespace).decode_xmldsig(expected)
    original = fixture.build()
    rebuilt = everest_to_pydantic_xmldsig(
        decoded,
        fixture.decode_model_cls,
        fixture.namespace,
        root_name=fixture.root_name,
    )
    assert _model_equal(rebuilt, original), (
        f"EXPy xmldsig decode drift for {fixture.id}"
    )
