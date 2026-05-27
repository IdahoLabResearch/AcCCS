"""ISO 15118-2 fixture-pair tests for the Pydantic↔EVerest translation module.

Covers all three EXPy root types for ISO-2:

- **Document** — ``V2GMessage`` end-to-end through ``encode`` / ``decode``.
- **Fragment** — signed-element payloads from
  ``app/evcc/states/iso15118_2_states.py`` and
  ``app/secc/controller/simulator.py`` (``AuthorizationReq``,
  ``CertificateInstallationReq``, ``MeteringReceiptReq``,
  ``ContractSignatureCertChain``, ``ContractSignatureEncryptedPrivateKey``,
  ``DHpublickey``, ``eMAID``) through ``encode_fragment`` /
  ``decode_fragment``.
- **XmldsigFragment** — ``SignedInfo`` (the payload signed by
  ``app/shared/security.py:create_signature``) through ``encode_xmldsig`` /
  ``decode_xmldsig``.

Each test confirms ``pydantic_to_everest_*`` produces an EVerest dict whose
EXPy encoding equals the checked-in golden, and that decoding the golden via
EXPy + ``everest_to_pydantic_*`` rebuilds the same Pydantic instance. Slice 5
will rebaseline the golden corpus against EXPy (ADR-0002); until then a few
fragment fixtures are flagged ``expy_authoritative=True`` because the legacy
Exificient codec produces undecodable output for them.
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
from tests.conformance.codec.fixtures import FIXTURES, CodecFixture

_ISO2_FIXTURES = [f for f in FIXTURES if f.protocol == "iso15118-2"]
_DOC = [f for f in _ISO2_FIXTURES if f.root_kind == "document"]
_FRAG = [f for f in _ISO2_FIXTURES if f.root_kind == "fragment"]
_XMLDSIG = [f for f in _ISO2_FIXTURES if f.root_kind == "xmldsig"]


def _expy_processor():
    from expy import EXIProcessor, Namespace

    return EXIProcessor(Namespace.ISO2)


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
def test_iso2_document_encode_matches_golden(fixture: CodecFixture):
    expected = _require_golden(fixture)
    message = fixture.build()
    everest = pydantic_to_everest(message, fixture.namespace)
    encoded = _expy_processor().encode(everest)
    assert encoded == expected, (
        f"EXPy document encode drift for {fixture.id}: got {encoded.hex()} "
        f"vs golden {expected.hex()}"
    )


@pytest.mark.parametrize("fixture", _DOC, ids=lambda f: f.id)
def test_iso2_document_decode_round_trips(fixture: CodecFixture):
    expected = _require_golden(fixture)
    decoded = _expy_processor().decode(expected)
    original = fixture.build()
    rebuilt = everest_to_pydantic(decoded, type(original), fixture.namespace)
    assert _model_equal(rebuilt, original), f"EXPy document decode drift for {fixture.id}"


@pytest.mark.parametrize("fixture", _FRAG, ids=lambda f: f.id)
def test_iso2_fragment_encode_matches_golden(fixture: CodecFixture):
    expected = _require_golden(fixture)
    message = fixture.build()
    everest = pydantic_to_everest_fragment(
        message, fixture.namespace, root_name=fixture.root_name
    )
    encoded = _expy_processor().encode_fragment(everest)
    assert encoded == expected, (
        f"EXPy fragment encode drift for {fixture.id}: got {encoded.hex()} "
        f"vs golden {expected.hex()}"
    )


@pytest.mark.parametrize("fixture", _FRAG, ids=lambda f: f.id)
def test_iso2_fragment_decode_round_trips(fixture: CodecFixture):
    expected = _require_golden(fixture)
    decoded = _expy_processor().decode_fragment(expected)
    original = fixture.build()
    rebuilt = everest_to_pydantic_fragment(
        decoded,
        fixture.decode_model_cls,
        fixture.namespace,
        root_name=fixture.root_name,
    )
    assert _model_equal(rebuilt, original), f"EXPy fragment decode drift for {fixture.id}"


@pytest.mark.parametrize("fixture", _XMLDSIG, ids=lambda f: f.id)
def test_iso2_xmldsig_encode_matches_golden(fixture: CodecFixture):
    expected = _require_golden(fixture)
    message = fixture.build()
    everest = pydantic_to_everest_xmldsig(
        message, fixture.namespace, root_name=fixture.root_name
    )
    encoded = _expy_processor().encode_xmldsig(everest)
    assert encoded == expected, (
        f"EXPy xmldsig encode drift for {fixture.id}: got {encoded.hex()} "
        f"vs golden {expected.hex()}"
    )


@pytest.mark.parametrize("fixture", _XMLDSIG, ids=lambda f: f.id)
def test_iso2_xmldsig_decode_round_trips(fixture: CodecFixture):
    expected = _require_golden(fixture)
    decoded = _expy_processor().decode_xmldsig(expected)
    original = fixture.build()
    rebuilt = everest_to_pydantic_xmldsig(
        decoded,
        fixture.decode_model_cls,
        fixture.namespace,
        root_name=fixture.root_name,
    )
    assert _model_equal(rebuilt, original), f"EXPy xmldsig decode drift for {fixture.id}"
