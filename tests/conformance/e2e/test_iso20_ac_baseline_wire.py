"""Risk-based E2E test: the ISO-20 AC SECC message field tree reaches the wire (#100).

Every ISO-15118-20 AC SECC-emitted message is sourced from the [[message field
tree]] as of #100, with the shipped ``iso20-ac-secc-baseline`` replicating the
real plain-AC / Dynamic / EIM session in ``HAL+TCP_ISO_20_AC_Example.pcap``. This
drives a full ISO-20 AC session over veth (TLS 1.3) with the EXI capture tap on,
using a SECC personality tree-backed by that baseline, then decodes the messages
the SECC actually put on the wire and asserts the baseline values reached it:

* the common ``SessionSetupRes.EVSEID`` is the baseline-pinned ``PcLoadLetter``
  (proving the tree is applied to the shared common messages, keyed by the
  session's negotiated ``ISO_15118_20_AC`` protocol — the same anchor identity the
  DC SECC baseline pins, shared not re-decoded);
* the AC-specific ``ACChargeParameterDiscoveryRes`` charge-power maximum is the
  baseline 200000 W — the retired ``power.evse_ac_v20`` read would have emitted the
  30000 W ``EVSEACLimitsV20`` model default, so a non-baseline value here would
  mean the tree did not reach the AC envelope.

The companion ``iso20-eim-ac`` smoke scenario guards clean session completion on
the plain-AC path.
"""

from __future__ import annotations

from pathlib import Path

from app.shared.exi_codec import EXI
from app.shared.messages.enums import Namespace

from tests.conformance.e2e._capture_session import drive_session

PERSONALITIES_DIR = Path(__file__).resolve().parents[1] / "personalities"
ISO20_PREFIX = Namespace.ISO_V20_BASE.value


def test_iso20_ac_baseline_values_from_message_field_tree(
    launch_emulator, exi_codec, tmp_path
):
    capture_path = tmp_path / "iso20_ac_baseline.jsonl"
    result = drive_session(
        launch_emulator,
        evcc_personality=PERSONALITIES_DIR / "iso20-eim-ac-evcc.yaml",
        secc_personality=PERSONALITIES_DIR / "iso20-ac-baseline-secc.yaml",
        capture_path=capture_path,
        timeout_seconds=120,
    )

    assert result.completed, (
        "ISO-20 AC session did not complete cleanly: "
        f"evcc_done={result.evcc_done}, secc_done={result.secc_done}"
    )

    session_setup_evse_ids = []
    cpd_max_charge_power_w = []
    for rec in result.documents():
        if not rec.namespace.startswith(ISO20_PREFIX):
            continue
        if rec.direction != "encode":
            continue
        msg = EXI().from_exi_document(rec.payload, rec.namespace)
        if rec.model == "SessionSetupRes":
            session_setup_evse_ids.append(msg.evse_id)
        # The EXI capture records ISO-20 messages by their wire model name, which
        # for the AC variant carries an underscore (`AC_ChargeParameterDiscoveryRes`).
        if rec.model == "AC_ChargeParameterDiscoveryRes" and msg.ac_params:
            mp = msg.ac_params.evse_max_charge_power
            cpd_max_charge_power_w.append(mp.get_decimal_value())

    # SessionSetupRes.EVSEID: the baseline identity reaches the wire (common
    # message, tree-sourced under the negotiated ISO_15118_20_AC key).
    assert session_setup_evse_ids, "no SessionSetupRes captured on the wire"
    assert all(v == "PcLoadLetter" for v in session_setup_evse_ids), (
        "baseline EVSEID did not reach the wire: "
        f"SessionSetupRes.EVSEID values = {session_setup_evse_ids}"
    )

    # ACChargeParameterDiscoveryRes: the tree-sourced AC envelope reaches the
    # wire (retired evse_ac_v20 read would emit the 30000 W model default).
    assert cpd_max_charge_power_w, (
        "no ACChargeParameterDiscoveryRes with AC params captured on the wire"
    )
    assert all(p == 200000 for p in cpd_max_charge_power_w), (
        "baseline AC envelope did not reach the wire (retired structured read "
        "would emit the 30000 W model default): CPDRes maxChargePower "
        f"values = {cpd_max_charge_power_w}"
    )
