"""Risk-based E2E test 1/3: ISO 15118-20 ``V2GMessage`` envelope strip/synthesize.

ADR-0002 calls out an asymmetry that lives in exactly one place — the
per-namespace envelope adapter in ``app/shared/everest_shape.py``:

> AcCCS Pydantic models for ISO-20 retain their ``V2GMessage`` wrapper. The
> translation module strips it on encode and synthesizes it on decode for
> ISO-20 namespaces only.

DIN and ISO 15118-2 are identity (their Pydantic shape already matches
EVerest's ``V2G_Message(Header, Body)`` top level); ISO-20's libcbv2g schema
expects no wrapper at all — each message is ``{"<MessageName>": {Header,
…body…}}`` with the per-message ``Header`` inline. Get the adapter wrong and
either encode hands EXPy a shape it rejects (session never starts) or decode
hands the state machine a model missing its header.

This test drives a full ISO-20 DC session over veth with the EXI capture tap
on, then asserts both directions of the asymmetry against the bytes that
actually crossed the wire:

* **Strip (encode).** Every ISO-20 document captured on the wire, decoded
  back through the *raw* EXPy codec, is envelope-free: a single top-level key
  that is the message name (never ``V2G_Message``), no ``Body`` key, and the
  ``Header`` carried inside the message body. That shape can only be present
  if AcCCS stripped the ``V2GMessage`` wrapper before encoding.
* **Synthesize (decode).** The same wire bytes, fed through AcCCS's
  ``EXI.from_exi_document`` (the production decode path), come back as a
  ``V2GMessage`` subclass with its ``header`` populated — i.e. the wrapper the
  raw bytes do *not* carry has been synthesized back on.

A mutation that breaks the strip/synthesize asymmetry fails this test (and,
because EXPy would reject a wrongly-shaped encode, would usually fail the
session-completion oracle too).
"""

from __future__ import annotations

from pathlib import Path

from app.shared.exi_codec import EXI, _ISO20_MSG_CLASSES
from app.shared.messages.enums import Namespace
from app.shared.messages.iso15118_20.common_types import V2GMessage as V2GMessageV20

from tests.conformance.e2e._capture_session import drive_session

PERSONALITIES_DIR = Path(__file__).resolve().parents[1] / "personalities"
ISO20_PREFIX = Namespace.ISO_V20_BASE.value


def test_iso20_envelope_strip_and_synthesize(launch_emulator, exi_codec, tmp_path):
    capture_path = tmp_path / "iso20_envelope.jsonl"
    result = drive_session(
        launch_emulator,
        evcc_personality=PERSONALITIES_DIR / "iso20-eim-evcc.yaml",
        secc_personality=PERSONALITIES_DIR / "iso20-eim-secc.yaml",
        capture_path=capture_path,
        timeout_seconds=120,
    )

    assert result.completed, (
        "ISO-20 session did not complete cleanly: "
        f"evcc_done={result.evcc_done}, secc_done={result.secc_done}"
    )

    iso20_docs = [
        r for r in result.documents() if r.namespace.startswith(ISO20_PREFIX)
    ]
    assert iso20_docs, "no ISO-20 document records captured on the wire"

    codec = EXI().get_exi_codec()

    # ---- Strip (encode side): wire bytes carry no V2GMessage envelope ----
    for rec in iso20_docs:
        decoded = codec.decode_document(rec.payload, rec.namespace)

        assert len(decoded) == 1, (
            f"ISO-20 wire document for {rec.model!r} ({rec.direction}) should "
            f"have exactly one top-level key, got {list(decoded)}"
        )
        (envelope_key,) = decoded.keys()
        assert envelope_key != "V2G_Message", (
            f"ISO-20 wire document for {rec.model!r} still carries the "
            "DIN/ISO-2 'V2G_Message' envelope — strip did not run"
        )
        assert envelope_key in _ISO20_MSG_CLASSES, (
            f"ISO-20 wire top-level key {envelope_key!r} is not a known "
            "ISO-20 message name"
        )
        assert "Body" not in decoded, (
            f"ISO-20 wire document for {rec.model!r} carries a 'Body' "
            "envelope key — that is the ISO-2 identity shape, not ISO-20"
        )
        body = decoded[envelope_key]
        assert isinstance(body, dict) and "Header" in body, (
            f"ISO-20 message {envelope_key!r} should carry its Header inline "
            f"in the message body, got keys {list(body) if isinstance(body, dict) else type(body)}"
        )

    # ---- Synthesize (decode side): AcCCS re-wraps into a V2GMessage ----
    # Use a request the EVCC always sends so a representative record is present.
    session_setup = next(
        (r for r in iso20_docs if r.model == "SessionSetupReq"), iso20_docs[0]
    )
    model = EXI().from_exi_document(session_setup.payload, session_setup.namespace)
    assert isinstance(model, V2GMessageV20), (
        f"decoded ISO-20 message should be a V2GMessage subclass, got {type(model)}"
    )
    assert getattr(model, "header", None) is not None, (
        "ISO-20 decode did not synthesize the V2GMessage header back onto the "
        "Pydantic model"
    )
