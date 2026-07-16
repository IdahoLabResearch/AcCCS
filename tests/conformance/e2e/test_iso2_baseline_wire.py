"""Risk-based E2E test: the ISO-2 SECC message field tree reaches the wire (#96).

Every ISO-15118-2 SECC-emitted message is sourced from the [[message field
tree]] as of #96, with the shipped ``iso2-secc-baseline`` replicating
``HAL+TCP_ISO_2_DC_Example.pcap``. This drives a full ISO-2 DC/EIM session over
veth with the EXI capture tap on, using a SECC personality tree-backed by that
baseline, then decodes the messages the SECC actually put on the wire and
asserts the baseline values reached it:

* the ``ChargeParameterDiscoveryRes`` isolation status is ``Invalid`` and its DC
  envelope is the baseline 200000 W max power (the retired structured read would
  have emitted the 80000 W model default);
* the ``CableCheckRes`` isolation progression is ``Invalid`` while ONGOING and
  flips to ``Valid`` on the completing FINISHED frame — the ``skip_fields`` seam
  that the per-message tree cannot script.

The companion ``iso2-eim-dc`` smoke scenario guards clean session completion.
"""

from __future__ import annotations

from pathlib import Path

from app.shared.exi_codec import EXI
from app.shared.messages.enums import IsolationLevel, Namespace

from tests.conformance.e2e._capture_session import drive_session

PERSONALITIES_DIR = Path(__file__).resolve().parents[1] / "personalities"
ISO2_NS = Namespace.ISO_V2_MSG_DEF.value


def test_iso2_baseline_values_from_message_field_tree(
    launch_emulator, exi_codec, tmp_path
):
    capture_path = tmp_path / "iso2_baseline.jsonl"
    result = drive_session(
        launch_emulator,
        evcc_personality=PERSONALITIES_DIR / "iso2-eim-variant-evcc.yaml",
        secc_personality=PERSONALITIES_DIR / "iso2-baseline-secc.yaml",
        capture_path=capture_path,
        timeout_seconds=60,
    )

    assert result.completed, (
        "ISO-2 session did not complete cleanly: "
        f"evcc_done={result.evcc_done}, secc_done={result.secc_done}"
    )

    cpd_isolation = []
    cpd_max_power_w = []
    cablecheck_isolation = []
    for rec in result.documents(namespace=ISO2_NS):
        if rec.direction != "encode":
            continue
        msg = EXI().from_exi_document(rec.payload, rec.namespace)
        cpd_res = msg.body.charge_parameter_discovery_res
        if cpd_res is not None and cpd_res.dc_charge_parameter is not None:
            dc = cpd_res.dc_charge_parameter
            cpd_isolation.append(dc.dc_evse_status.evse_isolation_status)
            mp = dc.evse_maximum_power_limit
            cpd_max_power_w.append(mp.value * (10 ** mp.multiplier))
        cc_res = msg.body.cable_check_res
        if cc_res is not None and cc_res.dc_evse_status is not None:
            cablecheck_isolation.append(cc_res.dc_evse_status.evse_isolation_status)

    # ChargeParameterDiscoveryRes: baseline isolation + DC envelope on the wire.
    assert cpd_isolation, "no ChargeParameterDiscoveryRes captured on the wire"
    assert all(v is IsolationLevel.INVALID for v in cpd_isolation), (
        "baseline isolation status did not reach the wire: "
        f"CPDRes EVSEIsolationStatus values = {cpd_isolation}"
    )
    assert all(p == 200000 for p in cpd_max_power_w), (
        "baseline DC envelope did not reach the wire (retired structured read "
        f"would emit the 80000 W model default): CPDRes maxPower values = {cpd_max_power_w}"
    )

    # CableCheckRes: Invalid while ONGOING, Valid on the completing FINISHED frame.
    assert cablecheck_isolation, "no CableCheckRes captured on the wire"
    assert IsolationLevel.INVALID in cablecheck_isolation, (
        "baseline ONGOING isolation (Invalid) not observed on any CableCheckRes: "
        f"{cablecheck_isolation}"
    )
    assert cablecheck_isolation[-1] is IsolationLevel.VALID, (
        "CableCheck skip_fields seam did not flip the completing frame to Valid: "
        f"final CableCheckRes EVSEIsolationStatus = {cablecheck_isolation[-1]}"
    )
