"""Message-name -> model registry for ISO 15118-20 (ADR-0006 protocol-key slice).

The DIN and ISO 15118-2 message packages each expose a ``get_msg_type`` that
maps a message name (``SessionSetupReq``) to its Pydantic model, single-sourcing
the [[message field tree]]'s message set from the wire schema rather than a
hand-maintained parallel list. ISO 15118-20 had no such registry because its
messages are split across three modules (``common_messages`` + ``dc`` + ``ac``)
rather than one ``body.py``. This module provides the equivalent, spanning all
three so a tree keyed ``ISO_15118_20_DC`` or ``ISO_15118_20_AC`` resolves a
message within it.

Scope follows the ADR-0006 protocol-keyed amendment:

* **Common messages** (``common_messages.py``) are emitted in *both* AC and DC
  sessions, so they are registered once here and reachable under either ISO-20
  protocol key. Their names do not collide with the variant-specific messages.
* **DC** and **AC** variant messages (``dc.py`` / ``ac.py``) are already
  uniquely named (``DCChargeParameterDiscoveryReq`` != its AC sibling), so they
  coexist in one flat registry without ambiguity.
* **WPT / ACDP are excluded.** Their message models exist but no state machine
  emits them, so there is nothing to tree-source until an emitter lands (at
  which point they register here exactly as DC/AC do).
"""

from __future__ import annotations

from typing import Dict, Optional, Type

from app.shared.messages.iso15118_20.ac import (
    ACChargeLoopReq,
    ACChargeLoopRes,
    ACChargeParameterDiscoveryReq,
    ACChargeParameterDiscoveryRes,
)
from app.shared.messages.iso15118_20.common_messages import (
    AuthorizationReq,
    AuthorizationRes,
    AuthorizationSetupReq,
    AuthorizationSetupRes,
    CertificateInstallationReq,
    CertificateInstallationRes,
    MeteringConfirmationReq,
    MeteringConfirmationRes,
    PowerDeliveryReq,
    PowerDeliveryRes,
    ScheduleExchangeReq,
    ScheduleExchangeRes,
    ServiceDetailReq,
    ServiceDetailRes,
    ServiceDiscoveryReq,
    ServiceDiscoveryRes,
    ServiceSelectionReq,
    ServiceSelectionRes,
    SessionSetupReq,
    SessionSetupRes,
    SessionStopReq,
    SessionStopRes,
)
from app.shared.messages.iso15118_20.common_types import V2GMessage
from app.shared.messages.iso15118_20.dc import (
    DCCableCheckReq,
    DCCableCheckRes,
    DCChargeLoopReq,
    DCChargeLoopRes,
    DCChargeParameterDiscoveryReq,
    DCChargeParameterDiscoveryRes,
    DCPreChargeReq,
    DCPreChargeRes,
    DCWeldingDetectionReq,
    DCWeldingDetectionRes,
)

# Common messages ride both ISO-20 sessions; DC and AC variant messages are
# uniquely named so they share one flat namespace without collision.
_MSG_TYPES: Dict[str, Type[V2GMessage]] = {
    # --- common_messages.py (emitted in both AC and DC sessions) ---
    "SessionSetupReq": SessionSetupReq,
    "SessionSetupRes": SessionSetupRes,
    "AuthorizationSetupReq": AuthorizationSetupReq,
    "AuthorizationSetupRes": AuthorizationSetupRes,
    "AuthorizationReq": AuthorizationReq,
    "AuthorizationRes": AuthorizationRes,
    "ServiceDiscoveryReq": ServiceDiscoveryReq,
    "ServiceDiscoveryRes": ServiceDiscoveryRes,
    "ServiceDetailReq": ServiceDetailReq,
    "ServiceDetailRes": ServiceDetailRes,
    "ServiceSelectionReq": ServiceSelectionReq,
    "ServiceSelectionRes": ServiceSelectionRes,
    "ScheduleExchangeReq": ScheduleExchangeReq,
    "ScheduleExchangeRes": ScheduleExchangeRes,
    "PowerDeliveryReq": PowerDeliveryReq,
    "PowerDeliveryRes": PowerDeliveryRes,
    "MeteringConfirmationReq": MeteringConfirmationReq,
    "MeteringConfirmationRes": MeteringConfirmationRes,
    "CertificateInstallationReq": CertificateInstallationReq,
    "CertificateInstallationRes": CertificateInstallationRes,
    "SessionStopReq": SessionStopReq,
    "SessionStopRes": SessionStopRes,
    # --- dc.py (DC session variant messages) ---
    "DCChargeParameterDiscoveryReq": DCChargeParameterDiscoveryReq,
    "DCChargeParameterDiscoveryRes": DCChargeParameterDiscoveryRes,
    "DCChargeLoopReq": DCChargeLoopReq,
    "DCChargeLoopRes": DCChargeLoopRes,
    "DCCableCheckReq": DCCableCheckReq,
    "DCCableCheckRes": DCCableCheckRes,
    "DCPreChargeReq": DCPreChargeReq,
    "DCPreChargeRes": DCPreChargeRes,
    "DCWeldingDetectionReq": DCWeldingDetectionReq,
    "DCWeldingDetectionRes": DCWeldingDetectionRes,
    # --- ac.py (AC session variant messages) ---
    "ACChargeParameterDiscoveryReq": ACChargeParameterDiscoveryReq,
    "ACChargeParameterDiscoveryRes": ACChargeParameterDiscoveryRes,
    "ACChargeLoopReq": ACChargeLoopReq,
    "ACChargeLoopRes": ACChargeLoopRes,
}


def get_msg_type(msg_name: str) -> Optional[Type[V2GMessage]]:
    """Return the ISO 15118-20 model for *msg_name*, or ``None`` if unknown.

    Mirrors :func:`app.shared.messages.din_spec.body.get_msg_type` and its ISO-2
    sibling: the one place a message name maps to its model, spanning the common,
    DC, and AC message modules.
    """
    return _MSG_TYPES.get(msg_name, None)
