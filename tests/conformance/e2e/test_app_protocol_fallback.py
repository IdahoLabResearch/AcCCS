"""Risk-based E2E test 3/3: SupportedAppProtocol fallback negotiation.

The SAP handshake is where the EVCC's prioritised protocol offer meets the
SECC's supported set. The SECC walks the EVCC's offer in priority order and
selects the first protocol it also supports (``app/secc/states/sap_states.py``);
the EVCC then maps the returned ``schema_id`` back to a protocol and switches
its state graph accordingly (``app/evcc/states/sap_states.py``). The fragile
case is *fallback*: the highest-priority offers are unsupported by the peer and
the negotiation must walk past them to a lower one — here, all the way to DIN.

Both directions of the asymmetry are exercised:

* **SECC-constrained.** The EVCC offers ISO 15118-20 > ISO 15118-2 > DIN; the
  SECC supports DIN only. The SECC must skip the two higher offers.
* **EVCC-constrained (mirror).** The EVCC offers DIN only; the SECC supports
  ISO 15118-2 > DIN. The negotiation still lands on DIN even though the SECC
  would have preferred ISO-2 — the limiting side is now the EVCC.

For each, with the EXI capture tap on, the test asserts:

* the SAP exchange happened and returned a positive response code;
* the ``schema_id`` the SECC selected maps back, in the EVCC's own offer, to
  the DIN namespace — i.e. DIN was the negotiated protocol;
* the session body ran entirely under DIN (no ISO-2 / ISO-20 document crossed
  the wire);
* the session terminated cleanly (a DIN ``SessionStop``).

A regression that mis-walks the priority ladder (e.g. selecting the first
*offered* rather than the first *mutually-supported* protocol) fails the
schema-mapping and body-namespace assertions; one that breaks DIN fallback
entirely fails the completion oracle.

TLS is off in all four personalities. This is deliberate and unavoidable: DIN
mandates no transport-layer security and the EVCC's SAP builder strips DIN from
a TLS offer ([V2G-DC-618]), while ISO-20 mandates TLS 1.3 — so an EVCC can only
offer ISO-20 *and* DIN in one request with TLS off. See the personality files
for the full rationale.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.shared.exi_codec import EXI
from app.shared.messages.app_protocol import ResponseCodeSAP
from app.shared.messages.enums import Namespace

from tests.conformance.e2e._capture_session import SAP_NS, drive_session

PERSONALITIES_DIR = Path(__file__).resolve().parents[1] / "personalities"
DIN_NS = Namespace.DIN_MSG_DEF.value


@pytest.mark.parametrize(
    "evcc_personality, secc_personality, constrained_side",
    [
        ("fallback-evcc-multi", "fallback-secc-din-only", "secc"),
        ("fallback-evcc-din-only", "fallback-secc-multi", "evcc"),
    ],
    ids=["secc-constrained", "evcc-constrained-mirror"],
)
def test_app_protocol_falls_back_to_din(
    launch_emulator,
    exi_codec,
    tmp_path,
    evcc_personality,
    secc_personality,
    constrained_side,
):
    capture_path = tmp_path / f"fallback_{constrained_side}.jsonl"
    result = drive_session(
        launch_emulator,
        evcc_personality=PERSONALITIES_DIR / f"{evcc_personality}.yaml",
        secc_personality=PERSONALITIES_DIR / f"{secc_personality}.yaml",
        capture_path=capture_path,
        timeout_seconds=90,
    )

    assert result.completed, (
        f"{constrained_side}-constrained fallback session did not complete: "
        f"evcc_done={result.evcc_done}, secc_done={result.secc_done}"
    )

    # ---- SAP negotiation landed on DIN ----
    sap_req_rec = _first_sap(result, "supportedAppProtocolReq")
    sap_res_rec = _first_sap(result, "supportedAppProtocolRes")
    sap_req = EXI().from_exi_document(sap_req_rec.payload, SAP_NS)
    sap_res = EXI().from_exi_document(sap_res_rec.payload, SAP_NS)

    assert sap_res.response_code in (
        ResponseCodeSAP.NEGOTIATION_OK,
        ResponseCodeSAP.MINOR_DEVIATION,
    ), f"SAP negotiation did not succeed: {sap_res.response_code}"

    selected_ns = {
        proto.protocol_ns
        for proto in sap_req.app_protocol
        if proto.schema_id == sap_res.schema_id
    }
    assert selected_ns == {DIN_NS}, (
        f"SECC selected schema_id {sap_res.schema_id}, which maps to "
        f"{selected_ns or 'no offered protocol'} in the EVCC's offer, not DIN"
    )

    # ---- The session body ran entirely under DIN ----
    body_namespaces = {
        r.namespace for r in result.documents() if r.namespace != SAP_NS
    }
    assert body_namespaces == {DIN_NS}, (
        f"expected the session body to run under DIN only, saw {body_namespaces}"
    )


def _first_sap(result, model_name):
    for rec in result.documents(namespace=SAP_NS):
        if rec.model == model_name:
            return rec
    raise AssertionError(
        f"no {model_name} captured — the SAP handshake did not run as expected"
    )
