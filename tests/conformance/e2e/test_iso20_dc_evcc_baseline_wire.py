"""Risk-based E2E test: the ISO-20 DC EVCC message field tree reaches the wire (#99).

Every ISO-15118-20 DC EVCC-emitted message is sourced from the [[message field
tree]] as of #99, with the shipped ``iso20-dc-evcc-baseline`` replicating the
DC-BPT / Dynamic / EIM vehicle in ``iso20.pcap``. This drives a full ISO-20
DC-BPT session over veth (TLS 1.3) with the EXI capture tap on, using an EVCC
personality tree-backed by that baseline, then decodes the messages the EVCC
actually put on the wire and asserts the baseline value reached it:

* the DC-specific ``DCChargeParameterDiscoveryReq`` BPT charge-power maximum is
  the baseline 18000 W — the retired ``power.ev_dc_v20`` read would have emitted
  the 300000 W ``EVDCLimitsV20`` model default, so a non-baseline value here
  would mean the tree did not reach the DC requested envelope.

Pairs with the SECC-side ``test_iso20_dc_baseline_wire.py`` (which asserts the
SECC's tree reaches the wire). The EVCC's config-owned identity is EVCCID, but it
is the NIC MAC (runtime/allowlisted), not a tree value, so unlike the SECC test
there is no common-message identity assertion — the DC-BPT requested envelope is
the vehicle side's tree-sourced red-team surface.
"""

from __future__ import annotations

from pathlib import Path

from app.shared.exi_codec import EXI
from app.shared.messages.enums import Namespace

from tests.conformance.e2e._capture_session import drive_session

PERSONALITIES_DIR = Path(__file__).resolve().parents[1] / "personalities"
ISO20_PREFIX = Namespace.ISO_V20_BASE.value


def test_iso20_dc_evcc_baseline_values_from_message_field_tree(
    launch_emulator, exi_codec, tmp_path
):
    capture_path = tmp_path / "iso20_dc_evcc_baseline.jsonl"
    result = drive_session(
        launch_emulator,
        evcc_personality=PERSONALITIES_DIR / "iso20-dc-baseline-evcc.yaml",
        secc_personality=PERSONALITIES_DIR / "iso20-dc-baseline-secc.yaml",
        capture_path=capture_path,
        timeout_seconds=120,
    )

    assert result.completed, (
        "ISO-20 DC-BPT session did not complete cleanly: "
        f"evcc_done={result.evcc_done}, secc_done={result.secc_done}"
    )

    cpd_bpt_max_charge_power_w = []
    for rec in result.documents():
        if not rec.namespace.startswith(ISO20_PREFIX):
            continue
        if rec.direction != "encode":
            continue
        msg = EXI().from_exi_document(rec.payload, rec.namespace)
        # The EXI capture records ISO-20 messages by their wire model name, which
        # for the DC variant carries an underscore (`DC_ChargeParameterDiscoveryReq`).
        if rec.model == "DC_ChargeParameterDiscoveryReq" and msg.bpt_dc_params:
            mp = msg.bpt_dc_params.ev_max_charge_power
            cpd_bpt_max_charge_power_w.append(mp.get_decimal_value())

    # DCChargeParameterDiscoveryReq: the tree-sourced BPT requested envelope
    # reaches the wire (retired ev_dc_v20 read would emit the 300000 W model
    # default).
    assert cpd_bpt_max_charge_power_w, (
        "no DCChargeParameterDiscoveryReq with BPT params captured on the wire"
    )
    assert all(p == 18000 for p in cpd_bpt_max_charge_power_w), (
        "baseline DC-BPT requested envelope did not reach the wire (retired "
        "structured read would emit the 300000 W model default): CPDReq BPT "
        f"maxChargePower values = {cpd_bpt_max_charge_power_w}"
    )
