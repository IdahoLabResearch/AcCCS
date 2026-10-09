"""E2E acceptance for issue #138 (conformance review SC-003): on the wire,
PowerDeliveryReq Start carries ChargingComplete FALSE, the final Stop carries
TRUE because the simulated state of charge reached 100, and the charge loop
sends exactly ``charge_loop_cycle`` CurrentDemandReq, on DIN and ISO-2.

Drives a real two-subprocess session over the veth pair with the shipped demo
personalities (``charge_profile.cycle`` 10) and the EXI capture tap on, then
decodes every EVCC request the capture holds.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.shared.exi_codec import EXI
from app.shared.messages.enums import Namespace
from app.shared.messages.iso15118_2.datatypes import ChargeProgress
from app.evcc.evcc_config import EVCCConfig
from app.shared.personality import load_personality
from tests.conformance.e2e._capture_session import drive_session

REPO_PERSONALITIES_DIR = Path(__file__).resolve().parents[3] / "personalities"

CASES = {
    "din": ("din_dc_extended", Namespace.DIN_MSG_DEF.value),
    "iso2": ("iso2_eim_dc", Namespace.ISO_V2_MSG_DEF.value),
}


def _is_start(power_delivery_req) -> bool:
    progress = getattr(power_delivery_req, "charge_progress", None)
    if progress is not None:  # ISO-2
        return progress == ChargeProgress.START
    return power_delivery_req.ready_to_charge  # DIN


@pytest.mark.parametrize("case", sorted(CASES), ids=sorted(CASES))
def test_charging_complete_and_loop_count_on_the_wire(
    case, launch_emulator, exi_codec, tmp_path
):
    personality, namespace = CASES[case]
    evcc_personality = REPO_PERSONALITIES_DIR / f"{personality}-evcc.yaml"
    expected_cycles = EVCCConfig.from_personality(
        load_personality(str(evcc_personality), "evcc")
    ).charge_loop_cycle

    result = drive_session(
        launch_emulator,
        evcc_personality=evcc_personality,
        secc_personality=REPO_PERSONALITIES_DIR / f"{personality}-secc.yaml",
        capture_path=tmp_path / f"{case}.jsonl",
        timeout_seconds=60,
    )
    assert result.completed, (
        f"{case} session did not complete cleanly: "
        f"evcc_done={result.evcc_done}, secc_done={result.secc_done}"
    )

    # The shared capture holds each EVCC request twice (the EVCC's encode and
    # the SECC's decode of the same bytes); count the encode side only.
    power_delivery_reqs = []
    current_demand_reqs = 0
    for rec in result.documents(namespace=namespace):
        if rec.direction != "encode":
            continue
        body = EXI().from_exi_document(rec.payload, rec.namespace).body
        if body.power_delivery_req is not None:
            power_delivery_reqs.append(body.power_delivery_req)
        if body.current_demand_req is not None:
            current_demand_reqs += 1

    assert len(power_delivery_reqs) == 2, power_delivery_reqs
    start, stop = power_delivery_reqs
    assert _is_start(start) and not _is_start(stop)
    assert start.dc_ev_power_delivery_parameter.charging_complete is False
    assert stop.dc_ev_power_delivery_parameter.charging_complete is True
    assert current_demand_reqs == expected_cycles
