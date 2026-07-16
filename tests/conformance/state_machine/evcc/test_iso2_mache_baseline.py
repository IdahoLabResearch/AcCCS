"""The shipped `iso2-evcc-baseline` reproduces the Mach-E field-for-field (#97).

Issue #97 / ADR-0006: the ISO-2 EVCC baseline replicates the Ford Mach-E from
`Mach-E-ISO.pcapng` — the vehicle-side mirror of the HAL `iso2-secc-baseline`
(#96) and the direct analogue of the DIN Cadillac EVCC baseline (#74). This
drives the real EVCC through a full ISO-2 DC/EIM session with the shipped
`personalities/iso2-evcc-baseline.yaml`, feeding scripted SECC `*Res` messages,
decodes the bytes the EVCC actually put on the wire for each `*Req`, and asserts
every Mach-E baseline field — proving the message field tree reaches the wire for
the whole EVCC ISO-2 path.

Runtime/computed fields (EVCCID, SessionID, EVReady, ChargingComplete, and the
present/target voltage & current that ramp) are deliberately NOT asserted. The
Mach-E's pinned 24 % SOC, its announced 500 A / 422 V / 211000 W envelope resent
every CurrentDemandReq, and the Optional fields it omits are the headline
behaviours.
"""

from __future__ import annotations

import pytest

from tests.conformance.state_machine.evcc._iso2_session import (
    baseline_session,
    drive_dc_session,
)


@pytest.mark.asyncio
async def test_iso2_evcc_baseline_reproduces_mache_capture(exi_codec):
    reqs = await drive_dc_session(baseline_session())

    # ChargeParameterDiscoveryReq: the Mach-E DC envelope + pinned SOC, with the
    # Optional fields the Mach-E omits left unset.
    cpd = reqs["ChargeParameterDiscoveryReq"]
    dc = cpd.dc_ev_charge_parameter
    assert dc.dc_ev_status.ev_ress_soc == 24
    assert dc.ev_maximum_current_limit.get_decimal_value() == 500
    assert dc.ev_maximum_voltage_limit.get_decimal_value() == 422
    assert dc.ev_maximum_power_limit.get_decimal_value() == 211000
    assert dc.ev_energy_request is None
    assert dc.ev_energy_capacity is None
    assert dc.full_soc is None
    assert dc.bulk_soc is None
    assert dc.departure_time is None
    assert cpd.requested_energy_mode.value == "DC_extended"

    # CableCheckReq / PreChargeReq / WeldingDetectionReq carry the pinned SOC.
    assert reqs["CableCheckReq"].dc_ev_status.ev_ress_soc == 24
    assert reqs["PreChargeReq"].dc_ev_status.ev_ress_soc == 24
    assert reqs["WeldingDetectionReq"].dc_ev_status.ev_ress_soc == 24

    # PowerDeliveryReq's DC_EVPowerDeliveryParameter carries the pinned SOC and
    # omits BulkChargingComplete (Mach-E field-for-field).
    pdp = reqs["PowerDeliveryReq"].dc_ev_power_delivery_parameter
    assert pdp.dc_ev_status.ev_ress_soc == 24
    assert pdp.bulk_charging_complete is None

    # CurrentDemandReq resends the max envelope and omits the RemainingTime* /
    # BulkChargingComplete Optionals.
    cd = reqs["CurrentDemandReq"]
    assert cd.dc_ev_status.ev_ress_soc == 24
    assert cd.ev_max_voltage_limit.get_decimal_value() == 422
    assert cd.ev_max_current_limit.get_decimal_value() == 500
    assert cd.ev_max_power_limit.get_decimal_value() == 211000
    assert cd.bulk_charging_complete is None
    assert cd.remaining_time_to_full_soc is None
    assert cd.remaining_time_to_bulk_soc is None

    # The session reached SessionStop.
    assert "SessionStopReq" in reqs
    assert reqs["SessionStopReq"].charging_session.value == "Terminate"
