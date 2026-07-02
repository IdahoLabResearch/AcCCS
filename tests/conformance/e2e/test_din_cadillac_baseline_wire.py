"""E2E acceptance: the Cadillac Lyriq EVCC baseline reaches the wire (issue #74).

Drives a real two-subprocess DIN session over the veth pair with the shipped
DIN defaults — `din_dc_extended-evcc` (the Cadillac Lyriq, which `extends:` the
`din-evcc-baseline` message field tree) against `din_dc_extended-secc` (the ABB
charger) — with the EXI capture tap on. After the session terminates cleanly it
decodes the `ChargeParameterDiscoveryReq` and `CurrentDemandReq` the EVCC
actually put on the wire and asserts the Cadillac baseline fields from
`ABB_Cadillac_Lyric.pcapng`, proving the EVCC-side message field tree reaches
the wire through the production codec path (acceptance criteria #2 and #3).
"""

from __future__ import annotations

from pathlib import Path

from app.shared.exi_codec import EXI
from app.shared.messages.enums import Namespace

from tests.conformance.e2e._capture_session import drive_session

# The shipped repo personalities (not the conformance test personalities): these
# are the DIN defaults run_evcc.py / run_secc.py boot with.
REPO_PERSONALITIES_DIR = Path(__file__).resolve().parents[3] / "personalities"
DIN_NS = Namespace.DIN_MSG_DEF.value


def test_din_cadillac_baseline_reaches_the_wire(launch_emulator, exi_codec, tmp_path):
    capture_path = tmp_path / "din_cadillac.jsonl"
    result = drive_session(
        launch_emulator,
        evcc_personality=REPO_PERSONALITIES_DIR / "din_dc_extended-evcc.yaml",
        secc_personality=REPO_PERSONALITIES_DIR / "din_dc_extended-secc.yaml",
        capture_path=capture_path,
        timeout_seconds=60,
    )

    assert result.completed, (
        "DIN session did not complete cleanly: "
        f"evcc_done={result.evcc_done}, secc_done={result.secc_done}"
    )

    # Decode every DIN document; keep the EVCC-emitted requests (they appear in
    # the shared capture as the EVCC's encode and the SECC's decode of the same
    # bytes — either copy carries the same wire values).
    cpd_reqs = []
    current_demand_reqs = []
    for rec in result.documents(namespace=DIN_NS):
        msg = EXI().from_exi_document(rec.payload, rec.namespace)
        body = msg.body
        if body.charge_parameter_discovery_req is not None:
            cpd_reqs.append(body.charge_parameter_discovery_req)
        if body.current_demand_req is not None:
            current_demand_reqs.append(body.current_demand_req)

    assert cpd_reqs, "no ChargeParameterDiscoveryReq captured on the wire"
    dcp = cpd_reqs[0].dc_ev_charge_parameter
    assert dcp.dc_ev_status.ev_ress_soc == 88
    assert dcp.ev_maximum_current_limit.get_decimal_value() == 500
    assert dcp.ev_maximum_voltage_limit.get_decimal_value() == 410
    assert dcp.full_soc == 100
    assert dcp.bulk_soc == 80
    assert dcp.ev_maximum_power_limit is None  # Cadillac omits it here

    assert current_demand_reqs, "no CurrentDemandReq captured on the wire"
    cdr = current_demand_reqs[0]
    assert cdr.dc_ev_status.ev_ress_soc == 88
    assert cdr.ev_max_voltage_limit.get_decimal_value() == 410
    assert cdr.ev_max_current_limit.get_decimal_value() == 500
    assert cdr.bulk_charging_complete is True
    assert cdr.remaining_time_to_full_soc.get_decimal_value() == 2111
    assert cdr.remaining_time_to_bulk_soc.get_decimal_value() == 0
    assert cdr.ev_max_power_limit is None  # Cadillac omits it from CurrentDemandReq
