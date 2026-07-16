"""Risk-based E2E test: the ISO-20 DC SECC message field tree reaches the wire (#98).

Every ISO-15118-20 DC SECC-emitted message is sourced from the [[message field
tree]] as of #98, with the shipped ``iso20-dc-secc-baseline`` replicating the
real DC-BPT / Dynamic / EIM session in ``iso20.pcap``. This drives a full ISO-20
DC-BPT session over veth (TLS 1.3) with the EXI capture tap on, using a SECC
personality tree-backed by that baseline, then decodes the messages the SECC
actually put on the wire and asserts the baseline values reached it:

* the common ``SessionSetupRes.EVSEID`` is the baseline-pinned ``PcLoadLetter``
  (proving the tree is applied to the shared common messages, keyed by the
  session's negotiated ``ISO_15118_20_DC`` protocol);
* the DC-specific ``DCChargeParameterDiscoveryRes`` BPT charge-power maximum is
  the baseline 44000 W — the retired ``power.evse_dc_v20`` read would have
  emitted the 1000 W ``EVSEDCLimitsV20`` model default, so a non-baseline value
  here would mean the tree did not reach the DC envelope.

The companion ``iso20-eim-dc`` smoke scenario guards clean session completion on
the plain-DC path.
"""

from __future__ import annotations

from pathlib import Path

from app.shared.exi_codec import EXI
from app.shared.messages.enums import Namespace

from tests.conformance.e2e._capture_session import drive_session

PERSONALITIES_DIR = Path(__file__).resolve().parents[1] / "personalities"
ISO20_PREFIX = Namespace.ISO_V20_BASE.value


def test_iso20_dc_baseline_values_from_message_field_tree(
    launch_emulator, exi_codec, tmp_path
):
    capture_path = tmp_path / "iso20_dc_baseline.jsonl"
    result = drive_session(
        launch_emulator,
        evcc_personality=PERSONALITIES_DIR / "iso20-dc-bpt-evcc.yaml",
        secc_personality=PERSONALITIES_DIR / "iso20-dc-baseline-secc.yaml",
        capture_path=capture_path,
        timeout_seconds=120,
    )

    assert result.completed, (
        "ISO-20 DC-BPT session did not complete cleanly: "
        f"evcc_done={result.evcc_done}, secc_done={result.secc_done}"
    )

    session_setup_evse_ids = []
    cpd_bpt_max_charge_power_w = []
    for rec in result.documents():
        if not rec.namespace.startswith(ISO20_PREFIX):
            continue
        if rec.direction != "encode":
            continue
        msg = EXI().from_exi_document(rec.payload, rec.namespace)
        if rec.model == "SessionSetupRes":
            session_setup_evse_ids.append(msg.evse_id)
        # The EXI capture records ISO-20 messages by their wire model name, which
        # for the DC variant carries an underscore (`DC_ChargeParameterDiscoveryRes`).
        if rec.model == "DC_ChargeParameterDiscoveryRes" and msg.bpt_dc_params:
            mp = msg.bpt_dc_params.evse_max_charge_power
            cpd_bpt_max_charge_power_w.append(mp.get_decimal_value())

    # SessionSetupRes.EVSEID: the baseline identity reaches the wire (common
    # message, tree-sourced under the negotiated ISO_15118_20_DC key).
    assert session_setup_evse_ids, "no SessionSetupRes captured on the wire"
    assert all(v == "PcLoadLetter" for v in session_setup_evse_ids), (
        "baseline EVSEID did not reach the wire: "
        f"SessionSetupRes.EVSEID values = {session_setup_evse_ids}"
    )

    # DCChargeParameterDiscoveryRes: the tree-sourced BPT envelope reaches the
    # wire (retired evse_dc_v20 read would emit the 1000 W model default).
    assert cpd_bpt_max_charge_power_w, (
        "no DCChargeParameterDiscoveryRes with BPT params captured on the wire"
    )
    assert all(p == 44000 for p in cpd_bpt_max_charge_power_w), (
        "baseline DC-BPT envelope did not reach the wire (retired structured "
        "read would emit the 1000 W model default): CPDRes BPT maxChargePower "
        f"values = {cpd_bpt_max_charge_power_w}"
    )
