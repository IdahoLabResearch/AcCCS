"""
This modules contains classes which implement all the elements of the
ISO 15118-20 XSD file V2G_CI_ACDP.xsd (see folder 'schemas').
These are the V2GMessages exchanged between the EVCC and the SECC specifically
for ACD-P (Automated Connection Device - Pantograph) charging.

All classes are ultimately subclassed from pydantic's BaseModel to ease
validation when instantiating a class and to reduce boilerplate code.
Pydantic's Field class is used to be able to create a json schema of each model
(or class) that matches the definitions in the XSD schema, including the XSD
element names by using the 'alias' attribute.

Only a minimal surface — the request used for the EXPy codec fixture corpus —
is modelled here; ADR-0002 Slice 3 (#14) needed at least one ``ISO20_ACDP``
sub-namespace fixture and AcCCS's state machines don't drive ACDP in
production.
"""
from enum import Enum

from pydantic import Field

from app.shared.messages.iso15118_20.common_types import V2GRequest


class ACDPChargingDeviceStatus(str, Enum):
    """``electricalChargingDeviceStatusType`` per V2G_CI_ACDP.xsd."""

    STATE_A = "State_A"
    STATE_B = "State_B"
    STATE_C = "State_C"
    STATE_D = "State_D"


class ACDPConnectReq(V2GRequest):
    """See section 8.3.4.7.6.2 in ISO 15118-20."""

    ev_electrical_charging_device_status: ACDPChargingDeviceStatus = Field(
        ..., alias="EVElectricalChargingDeviceStatus"
    )

    def __str__(self):
        return "ACDP_ConnectReq"
