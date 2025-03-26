"""
This modules contains classes which implement all the elements of the
ISO 15118-2 XSD file V2G_CI_MsgHeader.xsd (see folder 'schemas').
In particular, this is the header element of the V2GMessages exchanged between
the EVCC and the SECC.


All classes are ultimately subclassed from pydantic's BaseModel to ease
validation when instantiating a class and to reduce boilerplate code.
Pydantic's Field class is used to be able to create a json schema of each model
(or class) that matches the definitions in the XSD schema, including the XSD
element names by using the 'alias' attribute.
"""

from pydantic import Field, field_validator
from typing import Optional

from app.shared.messages import BaseModel
from app.shared.messages.iso15118_2.datatypes import Notification
from app.shared.messages.xmldsig import Signature


class MessageHeader(BaseModel):
    """See section 8.3.3 in ISO 15118-2"""

    # XSD type hexBinary with max 8 bytes encoded as 16 hexadecimal characters
    session_id: str = Field(..., max_length=16, alias="SessionID")
    notification: Optional[Notification] = Field(None, alias="Notification")
    signature: Optional[Signature] = Field(None, alias="Signature")

    @field_validator("session_id")
    @classmethod
    def check_sessionid_is_hexbinary(cls, value):
        """
        Checks whether the session_id field is a hexadecimal representation of
        8 bytes.

        Pydantic validators are "class methods",
        see https://pydantic-docs.helpmanual.io/usage/validators/
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        try:
            # convert value to int, assuming base 16
            int(value, 16)
            return value
        except ValueError as exc:
            raise ValueError(
                f"Invalid value '{value}' for SessionID (must be "
                f"hexadecimal representation of max 8 bytes)"
            ) from exc
