"""E2E acceptance for issue #144 (conformance review SC-001 / SC-066): on the
wire, the EV's stop-side requests carry EVReady false, and the State-B settle
delay separates the stop request from the first WeldingDetectionReq.

Drives a real two-subprocess session over the veth pair with the shipped demo
personalities and the EXI capture tap on. The enable hook writes State B after
PowerDeliveryRes(Stop) and then sleeps `CP_STATE_B_SETTLE_S` before the
WeldingDetectionReq is built, so the gap between the EV's last
PowerDeliveryReq and its first WeldingDetectionReq (both EVCC encodes, the
response round-trip in between) is at least that constant.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.evcc.controller.simulator import CP_STATE_B_SETTLE_S
from app.shared.exi_codec import EXI
from app.shared.messages.enums import Namespace
from tests.conformance.e2e._capture_session import drive_session

REPO_PERSONALITIES_DIR = Path(__file__).resolve().parents[3] / "personalities"

# personality, stop-request model, welding-request model, EVReady on the wire
CASES = {
    "din": ("din_dc_extended", "PowerDeliveryReq", "WeldingDetectionReq", True),
    "iso2": ("iso2_eim_dc", "PowerDeliveryReq", "WeldingDetectionReq", True),
    # ISO-20 carries no EVReady; only the settle is checked.
    "iso20": ("iso20_dc", "PowerDeliveryReq", "DC_WeldingDetectionReq", False),
}
EV_READY_NAMESPACES = {Namespace.DIN_MSG_DEF.value, Namespace.ISO_V2_MSG_DEF.value}


def _dc_ev_status(body, name):
    if name == "power_delivery_req":
        return body.power_delivery_req.dc_ev_power_delivery_parameter.dc_ev_status
    return getattr(body, name).dc_ev_status


@pytest.mark.parametrize("case", sorted(CASES), ids=sorted(CASES))
def test_stop_side_ev_ready_and_state_b_settle_on_the_wire(
    case, launch_emulator, exi_codec, tmp_path
):
    personality, stop_model, welding_model, has_ev_ready = CASES[case]

    result = drive_session(
        launch_emulator,
        evcc_personality=REPO_PERSONALITIES_DIR / f"{personality}-evcc.yaml",
        secc_personality=REPO_PERSONALITIES_DIR / f"{personality}-secc.yaml",
        capture_path=tmp_path / f"{case}.jsonl",
        timeout_seconds=60,
    )
    assert result.completed, (
        f"{case} session did not complete cleanly: "
        f"evcc_done={result.evcc_done}, secc_done={result.secc_done}"
    )

    # Requests are EVCC encodes; the SECC never encodes a *Req.
    encodes = [r for r in result.documents() if r.direction == "encode"]
    stop_req = [r for r in encodes if r.model == stop_model][-1]
    first_welding = next(r for r in encodes if r.model == welding_model)
    assert first_welding.ts - stop_req.ts >= CP_STATE_B_SETTLE_S

    if not has_ev_ready:
        return
    power_deliveries, weldings = [], []
    for rec in encodes:
        if rec.namespace not in EV_READY_NAMESPACES:
            continue
        body = EXI().from_exi_document(rec.payload, rec.namespace).body
        if body.power_delivery_req is not None:
            power_deliveries.append(_dc_ev_status(body, "power_delivery_req"))
        elif body.welding_detection_req is not None:
            weldings.append(_dc_ev_status(body, "welding_detection_req"))

    start, stop = power_deliveries[0], power_deliveries[-1]
    assert start.ev_ready is True
    assert stop.ev_ready is False
    assert weldings and all(s.ev_ready is False for s in weldings)
