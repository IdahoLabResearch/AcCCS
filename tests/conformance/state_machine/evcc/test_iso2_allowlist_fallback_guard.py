"""Every ISO-2 EVCC allowlist entry has a real builder fallback (empty tree).

ADR-0006 #83 (extended to the ISO-2 EVCC in #97) makes the optional-field
allowlist a **standalone** statement of which required ISO-15118-2 EVCC wire
fields the emulator produces on its own at runtime — so they may be omitted from
the message field tree. This test is the guard that the ISO-2 EVCC list cannot
lie: it drives the EVCC DC states through `process_message()` with an
**empty-tree** personality (`EVCCPersonality()`), so every `*Req` is built purely
from the builders' computed values, then asserts each allowlisted leaf still
populates. A liar entry — a field claimed emulator-produced that the builder does
*not* set — would either fail message construction outright (the fields are
Pydantic-required) or surface here as a `None`.

The load-time behaviour of the check itself lives in
`tests/personality/test_completeness.py`; the SECC counterpart is
`tests/conformance/state_machine/test_iso2_allowlist_fallback_guard.py`.
"""

from __future__ import annotations

import pytest

from app.shared.personality.completeness import allowlist_for
from tests.conformance.state_machine.evcc._iso2_session import (
    drive_dc_session,
    empty_tree_session,
)

# The DC/EIM messages the empty-tree session actually builds, mapped to the
# emitted `*Req` captured by the driver. The AC-/PnC-only messages
# (ServiceDetailReq, CertificateInstallationReq, PaymentDetailsReq,
# MeteringReceiptReq, ChargingStatusReq) are not driven here — the DC/EIM baseline
# never sources them, so they carry no allowlist entry (see completeness.py).
_DRIVEN_MESSAGES = (
    "PaymentServiceSelectionReq",
    "ChargeParameterDiscoveryReq",
    "CableCheckReq",
    "PreChargeReq",
    "PowerDeliveryReq",
    "CurrentDemandReq",
    "WeldingDetectionReq",
    "SessionStopReq",
)


def _resolve(obj, path):
    cursor = obj
    for name in path:
        if cursor is None:
            return None
        cursor = getattr(cursor, name, None)
    return cursor


@pytest.mark.asyncio
async def test_iso2_evcc_allowlist_entries_have_builder_fallback(exi_codec):
    reqs = await drive_dc_session(empty_tree_session())
    allowlist = allowlist_for("evcc", "ISO_15118_2")

    missing = []
    for message_name in _DRIVEN_MESSAGES:
        req = reqs.get(message_name)
        assert req is not None, f"driver did not emit {message_name}"
        for path in allowlist.get(message_name, set()):
            if _resolve(req, path) is None:
                missing.append(f"{message_name} -> {' -> '.join(path)}")

    assert not missing, (
        "ISO-2 EVCC allowlist entries not populated by the empty-tree builder: "
        f"{missing}"
    )
