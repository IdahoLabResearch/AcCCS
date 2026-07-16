"""Risk-based E2E test: the ISO-2 EVCC message field tree reaches the wire (#97).

Every ISO-15118-2 EVCC-emitted message is sourced from the [[message field
tree]] as of #97, with the shipped ``iso2-evcc-baseline`` replicating the Ford
Mach-E ``Mach-E-ISO.pcapng`` field-for-field. This drives a full ISO-2 DC/EIM
session over veth with the EXI capture tap on, using an EVCC personality
tree-backed by that baseline (against the tree-backed HAL SECC baseline), then
decodes the ``*Req`` messages the EVCC actually put on the wire and asserts the
baseline values reached it:

* the ``ChargeParameterDiscoveryReq`` DC envelope is the Mach-E 500 A / 422 V /
  211000 W (the retired structured read would have emitted the model defaults),
  and the Mach-E-omitted Optional fields (EVEnergyRequest / FullSOC / BulkSOC)
  are absent;
* every ``CurrentDemandReq`` resends that same envelope and omits the
  RemainingTime* / BulkChargingComplete Optional fields;
* the pinned 24 % EVRESSSOC reaches the wire.

The vehicle-side mirror of ``test_iso2_baseline_wire.py`` (the SECC #96 test).
"""

from __future__ import annotations

from pathlib import Path

from app.shared.exi_codec import EXI
from app.shared.messages.enums import Namespace

from tests.conformance.e2e._capture_session import drive_session

PERSONALITIES_DIR = Path(__file__).resolve().parents[1] / "personalities"
ISO2_NS = Namespace.ISO_V2_MSG_DEF.value


def test_iso2_evcc_baseline_values_from_message_field_tree(
    launch_emulator, exi_codec, tmp_path
):
    capture_path = tmp_path / "iso2_evcc_baseline.jsonl"
    result = drive_session(
        launch_emulator,
        evcc_personality=PERSONALITIES_DIR / "iso2-baseline-evcc.yaml",
        secc_personality=PERSONALITIES_DIR / "iso2-baseline-secc.yaml",
        capture_path=capture_path,
        timeout_seconds=60,
    )

    assert result.completed, (
        "ISO-2 session did not complete cleanly: "
        f"evcc_done={result.evcc_done}, secc_done={result.secc_done}"
    )

    cpd_envelope = []  # (current_a, voltage_v, power_w) from ChargeParameterDiscoveryReq
    cpd_soc = []
    cpd_omitted = []  # (energy_request, full_soc, bulk_soc) — must all be None
    cd_envelope = []  # (current_a, voltage_v, power_w) from CurrentDemandReq
    cd_omitted = []  # (remaining_full, remaining_bulk, bulk_complete) — all None
    for rec in result.documents(namespace=ISO2_NS):
        msg = EXI().from_exi_document(rec.payload, rec.namespace)
        cpd_req = msg.body.charge_parameter_discovery_req
        if cpd_req is not None and cpd_req.dc_ev_charge_parameter is not None:
            dc = cpd_req.dc_ev_charge_parameter
            cpd_envelope.append(
                (
                    dc.ev_maximum_current_limit.get_decimal_value(),
                    dc.ev_maximum_voltage_limit.get_decimal_value(),
                    dc.ev_maximum_power_limit.get_decimal_value(),
                )
            )
            cpd_soc.append(dc.dc_ev_status.ev_ress_soc)
            cpd_omitted.append(
                (dc.ev_energy_request, dc.full_soc, dc.bulk_soc)
            )
        cd_req = msg.body.current_demand_req
        if cd_req is not None:
            cd_envelope.append(
                (
                    cd_req.ev_max_current_limit.get_decimal_value(),
                    cd_req.ev_max_voltage_limit.get_decimal_value(),
                    cd_req.ev_max_power_limit.get_decimal_value(),
                )
            )
            cd_omitted.append(
                (
                    cd_req.remaining_time_to_full_soc,
                    cd_req.remaining_time_to_bulk_soc,
                    cd_req.bulk_charging_complete,
                )
            )

    # ChargeParameterDiscoveryReq: the Mach-E DC envelope on the wire.
    assert cpd_envelope, "no ChargeParameterDiscoveryReq captured on the wire"
    assert all(e == (500, 422, 211000) for e in cpd_envelope), (
        "baseline DC envelope did not reach the wire (retired structured read "
        f"would emit the model defaults): CPDReq envelopes = {cpd_envelope}"
    )
    assert all(s == 24 for s in cpd_soc), (
        f"baseline EVRESSSOC (24) did not reach the wire: {cpd_soc}"
    )
    assert all(o == (None, None, None) for o in cpd_omitted), (
        "Mach-E-omitted ChargeParameterDiscoveryReq fields (EVEnergyRequest / "
        f"FullSOC / BulkSOC) unexpectedly reached the wire: {cpd_omitted}"
    )

    # CurrentDemandReq: the same envelope every loop; the omitted Optionals absent.
    assert cd_envelope, "no CurrentDemandReq captured on the wire"
    assert all(e == (500, 422, 211000) for e in cd_envelope), (
        f"baseline envelope did not reach every CurrentDemandReq: {cd_envelope}"
    )
    assert all(o == (None, None, None) for o in cd_omitted), (
        "Mach-E-omitted CurrentDemandReq fields (RemainingTime* / "
        f"BulkChargingComplete) unexpectedly reached the wire: {cd_omitted}"
    )
