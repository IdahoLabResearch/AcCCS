"""Risk-based E2E test: the ISO-20 AC EVCC message field tree reaches the wire (#101).

Every ISO-15118-20 AC EVCC-emitted message is sourced from the [[message field
tree]] as of #101, with the shipped ``iso20-ac-evcc-baseline`` replicating the
plain-AC / Dynamic / EIM vehicle in ``HAL+TCP_ISO_20_AC_Example.pcap``. This
drives a full ISO-20 AC session over veth (TLS 1.3) with the EXI capture tap on,
using an EVCC personality tree-backed by that baseline, then decodes the messages
the EVCC actually put on the wire and asserts the baseline value reached it:

* the AC-specific ``ACChargeParameterDiscoveryReq`` charge-power maximum is the
  baseline 12000 W — the retired ``power.ev_ac_v20`` read would have emitted the
  11000 W ``EVACLimitsV20`` model default, so a non-baseline value here would mean
  the tree did not reach the AC requested envelope.

Pairs with the SECC-side ``test_iso20_ac_baseline_wire.py`` (which asserts the
SECC's tree reaches the wire) and mirrors the DC EVCC
``test_iso20_dc_evcc_baseline_wire.py``. The EVCC's config-owned identity is
EVCCID, but it is the NIC MAC (runtime/allowlisted), not a tree value, so unlike
the SECC test there is no common-message identity assertion — the AC requested
envelope is the vehicle side's tree-sourced red-team surface.
"""

from __future__ import annotations

from pathlib import Path

from app.shared.exi_codec import EXI
from app.shared.messages.enums import Namespace

from tests.conformance.e2e._capture_session import drive_session

PERSONALITIES_DIR = Path(__file__).resolve().parents[1] / "personalities"
ISO20_PREFIX = Namespace.ISO_V20_BASE.value


def test_iso20_ac_evcc_baseline_values_from_message_field_tree(
    launch_emulator, exi_codec, tmp_path
):
    capture_path = tmp_path / "iso20_ac_evcc_baseline.jsonl"
    result = drive_session(
        launch_emulator,
        evcc_personality=PERSONALITIES_DIR / "iso20-ac-baseline-evcc.yaml",
        secc_personality=PERSONALITIES_DIR / "iso20-ac-baseline-secc.yaml",
        capture_path=capture_path,
        timeout_seconds=120,
    )

    assert result.completed, (
        "ISO-20 AC session did not complete cleanly: "
        f"evcc_done={result.evcc_done}, secc_done={result.secc_done}"
    )

    cpd_max_charge_power_w = []
    for rec in result.documents():
        if not rec.namespace.startswith(ISO20_PREFIX):
            continue
        if rec.direction != "encode":
            continue
        msg = EXI().from_exi_document(rec.payload, rec.namespace)
        # The EXI capture records ISO-20 messages by their wire model name, which
        # for the AC variant carries an underscore (`AC_ChargeParameterDiscoveryReq`).
        if rec.model == "AC_ChargeParameterDiscoveryReq" and msg.ac_params:
            mp = msg.ac_params.ev_max_charge_power
            cpd_max_charge_power_w.append(mp.get_decimal_value())

    # ACChargeParameterDiscoveryReq: the tree-sourced AC requested envelope
    # reaches the wire (retired ev_ac_v20 read would emit the 11000 W model
    # default).
    assert cpd_max_charge_power_w, (
        "no ACChargeParameterDiscoveryReq with AC params captured on the wire"
    )
    assert all(p == 12000 for p in cpd_max_charge_power_w), (
        "baseline AC requested envelope did not reach the wire (retired "
        "structured read would emit the 11000 W model default): CPDReq "
        f"maxChargePower values = {cpd_max_charge_power_w}"
    )
