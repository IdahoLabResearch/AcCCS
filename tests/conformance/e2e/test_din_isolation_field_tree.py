"""Risk-based E2E test: DIN message field tree reaches the wire (issue #71).

The tracer bullet for ADR-0006 wires exactly one field —
``ChargeParameterDiscoveryRes -> DC_EVSEChargeParameter -> DC_EVSEStatus ->
EVSEIsolationStatus`` — from a DIN SECC personality's [[message field tree]]
through construction-time substitution onto the bytes the SECC emits. The
simulator otherwise hardcodes this field to ``Valid``.

This drives a full DIN session over veth with the EXI capture tap on, using a
SECC personality that sets the tree leaf to ``Invalid``, then decodes the
``ChargeParameterDiscoveryRes`` the SECC actually put on the wire and asserts
the value is ``Invalid`` — the acceptance criterion "setting it to Invalid
causes the SECC to emit EVSEIsolationStatus = Invalid, observed in the virtual
two-session demo". The companion ``din-happy`` smoke scenario guards the unset
fallback (a clean session with the stock ``Valid``).
"""

from __future__ import annotations

from pathlib import Path

from app.shared.exi_codec import EXI
from app.shared.messages.enums import IsolationLevel, Namespace

from tests.conformance.e2e._capture_session import drive_session

PERSONALITIES_DIR = Path(__file__).resolve().parents[1] / "personalities"
DIN_NS = Namespace.DIN_MSG_DEF.value


def test_din_isolation_status_from_message_field_tree(
    launch_emulator, exi_codec, tmp_path
):
    capture_path = tmp_path / "din_isolation.jsonl"
    result = drive_session(
        launch_emulator,
        evcc_personality=PERSONALITIES_DIR / "din-evcc.yaml",
        secc_personality=PERSONALITIES_DIR / "din-isolation-invalid-secc.yaml",
        capture_path=capture_path,
        timeout_seconds=60,
    )

    assert result.completed, (
        "DIN session did not complete cleanly: "
        f"evcc_done={result.evcc_done}, secc_done={result.secc_done}"
    )

    # The SECC encodes the ChargeParameterDiscoveryRes; decode every DIN
    # document the SECC emitted and pull the one carrying the CPD response.
    isolation_values = []
    for rec in result.documents(namespace=DIN_NS):
        if rec.direction != "encode":
            continue
        msg = EXI().from_exi_document(rec.payload, rec.namespace)
        cpd_res = msg.body.charge_parameter_discovery_res
        if cpd_res is None or cpd_res.dc_charge_parameter is None:
            continue
        isolation_values.append(
            cpd_res.dc_charge_parameter.dc_evse_status.evse_isolation_status
        )

    assert isolation_values, "no ChargeParameterDiscoveryRes captured on the wire"
    assert all(v is IsolationLevel.INVALID for v in isolation_values), (
        "message field tree override did not reach the wire: "
        f"EVSEIsolationStatus values emitted = {isolation_values}"
    )
