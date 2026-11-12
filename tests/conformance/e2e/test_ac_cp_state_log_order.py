"""E2E acceptance for issue #146 (conformance review SC-001, AC part): in the
ISO-2 and ISO-20 AC virtual demos the relay log shows State C only after
PowerDeliveryReq(Start) is on the wire, and State B before the
PowerDeliveryRes that answers the stop arrives.

Drives a real two-subprocess AC session over the veth pair and reads the
vehicle side's log. Under `--virtual` the relay bank writes nothing but still
logs every control-pilot change ("Going to state X"), and the comm session
logs every message it sends or receives, so the order of those lines is the
order of the events: AC changes the pilot right after its PowerDeliveryReq
leaves ([V2G2-846]-[848], [V2G20-1617]/[847]/[848]), not before the Start and
not after the stop response.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from tests.conformance.e2e._capture_session import (
    EVCC_SUCCESS_MARKER,
    SECC_SUCCESS_MARKER,
    _wait_for_marker,
)

TEST_PERSONALITIES_DIR = Path(__file__).resolve().parents[1] / "personalities"

CASES = {
    "iso2": "iso2-ac",
    "iso20": "iso20-ac-baseline",
}

SENT_POWER_DELIVERY = "Sent PowerDeliveryReq"
RECEIVED_POWER_DELIVERY = "PowerDeliveryRes received"
STATE_C = "Going to state C"
STATE_B = "Going to state B"
EVENTS = (SENT_POWER_DELIVERY, RECEIVED_POWER_DELIVERY, STATE_C, STATE_B)


def _session_events(proc: subprocess.Popen, deadline: float) -> tuple[list[str], bool]:
    """Read the vehicle's log up to its SessionStop marker.

    Returns the power-delivery and control-pilot events in log order, and
    whether the session reached a clean SessionStop.
    """
    assert proc.stdout is not None
    events: list[str] = []
    while time.monotonic() < deadline:
        raw = proc.stdout.readline()
        if not raw:
            if proc.poll() is not None:
                break
            continue
        line = raw.decode("utf-8", errors="replace")
        if EVCC_SUCCESS_MARKER in line:
            return events, True
        events.extend(event for event in EVENTS if event in line)
    return events, False


@pytest.mark.parametrize("case", sorted(CASES), ids=sorted(CASES))
def test_ac_pilot_changes_follow_the_power_delivery_requests(case, launch_emulator):
    personality = CASES[case]
    secc = launch_emulator("secc", TEST_PERSONALITIES_DIR / f"{personality}-secc.yaml")
    # Tiny grace period so the SECC TCP listener is up before the EVCC dials.
    time.sleep(0.5)
    evcc = launch_emulator("evcc", TEST_PERSONALITIES_DIR / f"{personality}-evcc.yaml")

    deadline = time.monotonic() + 120
    events, completed = _session_events(evcc, deadline)
    assert completed, f"{case} AC session did not complete cleanly: {events}"
    assert _wait_for_marker(secc, SECC_SUCCESS_MARKER, deadline), (
        f"{case} charger side did not reach a clean SessionStop"
    )

    # An ISO-20 EV may first send PowerDeliveryReq with EVProcessing Ongoing
    # (answered, no pilot change) before the one that starts charging, so the
    # exchange around each pilot change is what is pinned, not a fixed count.
    state_c = events.index(STATE_C)
    assert events[state_c - 1] == SENT_POWER_DELIVERY, (
        f"State C must directly follow a sent PowerDeliveryReq(Start): {events}"
    )
    assert STATE_B not in events[:state_c]

    assert events.count(STATE_C) == 1 and events.count(STATE_B) == 1, events
    state_b = events.index(STATE_B)
    assert state_b > state_c
    assert events[state_b - 1] == SENT_POWER_DELIVERY, (
        f"State B must directly follow the sent PowerDeliveryReq(Stop): {events}"
    )
    assert events[state_b + 1 :] == [RECEIVED_POWER_DELIVERY], (
        f"State B must be on the pilot before the stop response arrives: {events}"
    )
