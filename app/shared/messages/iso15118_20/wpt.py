"""
This modules contains classes which implement all the elements of the
ISO 15118-20 XSD file V2G_CI_WPT.xsd (see folder 'schemas').
These are the V2GMessages exchanged between the EVCC and the SECC specifically
for wireless power transfer (WPT) charging.

All classes are ultimately subclassed from pydantic's BaseModel to ease
validation when instantiating a class and to reduce boilerplate code.
Pydantic's Field class is used to be able to create a json schema of each model
(or class) that matches the definitions in the XSD schema, including the XSD
element names by using the 'alias' attribute.

Only a minimal surface — the request used for the EXPy codec fixture corpus —
is modelled here; ADR-0002 Slice 3 (#14) needed at least one ``ISO20_WPT``
sub-namespace fixture and AcCCS's state machines don't drive WPT in
production.
"""
from enum import Enum

from pydantic import Field

from app.shared.messages.iso15118_20.common_types import V2GRequest


class WPTEVResult(str, Enum):
    """See section 8.3.5.6.x in ISO 15118-20."""

    UNKNOWN = "EVResultUnknown"
    SUCCESS = "EVResultSuccess"
    FAILED = "EVResultFailed"


class WPTProcessing(str, Enum):
    """``processingType`` reused by WPT and ACDP messages."""

    FINISHED = "Finished"
    ONGOING = "Ongoing"
    WAITING_FOR_CUSTOMER = "Ongoing_WaitingForCustomerInteraction"


class WPTPairingReq(V2GRequest):
    """See section 8.3.4.6.4.2 in ISO 15118-20."""

    ev_processing: WPTProcessing = Field(..., alias="EVProcessing")
    ev_result_code: WPTEVResult = Field(..., alias="EVResultCode")

    def __str__(self):
        return "WPT_PairingReq"
