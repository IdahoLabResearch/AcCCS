import logging
from enum import IntEnum
from ipaddress import IPv6Address
from typing import Optional, Tuple, Union

from app.shared.exceptions import InvalidSDPRequestError, InvalidSDPResponseError
from app.shared.messages.enums import (
    DINPayloadTypes,
    ISOV2PayloadTypes,
    ISOV20PayloadTypes,
)
from app.shared.messages.out_of_spec import discard_out_of_spec

logger = logging.getLogger(__name__)

MIN_TCP_PORT = 49152
MAX_TCP_PORT = 65535


class Security(IntEnum):
    """
    These enums are the available options for the 'security' field of the
    SECC Discovery Protocol (SDP) request and response message, as defined in
    both ISO 15118-2 and ISO 15118-20
    """

    TLS = 0x00
    NO_TLS = 0x10

    @classmethod
    def options(cls) -> list:
        return list(cls)

    @classmethod
    def from_byte(cls, byte: bytes) -> "Security":
        if int.from_bytes(byte, "big") == Security.TLS:
            return Security.TLS
        if int.from_bytes(byte, "big") == Security.NO_TLS:
            return Security.NO_TLS

        logger.error(f"Invalid byte value for Security enum: {byte.hex()}")
        raise ValueError


class Transport(IntEnum):
    """
    These enums are the available options for the 'transport' field of the
    SECC Discovery Protocol (SDP) request and response message, as defined in
    both ISO 15118-2 and ISO 15118-20.

    Although UDP (0x10) is not explicitly excluded in the list of applicable
    values, a UDP connection is not allowed for transmitting any message
    except the SDP request / response itself.
    """

    TCP = 0x00
    UDP = 0x10

    @classmethod
    def options(cls) -> list:
        return list(cls)

    @classmethod
    def from_byte(cls, byte: bytes) -> "Transport":
        if int.from_bytes(byte, "big") == Transport.TCP:
            return Transport.TCP
        if int.from_bytes(byte, "big") == Transport.UDP:
            return Transport.UDP

        logger.error(f"Invalid byte value for Transport enum: {byte.hex()}")
        raise ValueError


class SDPRequest:
    """
    The SECC Discovery Protocol Request message, which the EVCC uses to
    request the IP address and port from the SECC and to indicate whether or
    not the communication channel shall be secured (TLS) or not (plain TCP).
    """

    def __init__(self, security: Security, transport_protocol: Transport):
        if security not in Security.options():
            logger.error(
                f"'{security}' is not a valid value for "
                f"the field 'security'."
                f"Allowed: {Security.options()} "
            )
            # TODO: Raise an Exception
            return

        if transport_protocol not in Transport.options():
            logger.error(
                f"'{transport_protocol}' is not a valid value for the "
                f"field 'transport_protocol'."
                f"Allowed: {Transport.options()} "
            )
            # TODO: Raise an Exception
            return

        self.security = security
        self.transport_protocol = transport_protocol
        # SDPRequest has the same payload type in -2 and -20
        self.payload_type: Union[
            DINPayloadTypes, ISOV2PayloadTypes, ISOV20PayloadTypes
        ] = ISOV2PayloadTypes.SDP_REQUEST

    def to_payload(self) -> bytes:
        message = self.security.to_bytes(1, "big") + self.transport_protocol.to_bytes(
            1, "big"
        )
        return bytes(message)

    @staticmethod
    def from_payload(payload: bytes) -> Union["SDPRequest"]:
        if len(payload) != 2:
            logger.error(
                "Payload must be of 2 bytes length. "
                f"Provided: {len(payload)} bytes ({payload.hex()})"
            )
            raise InvalidSDPRequestError

        try:
            security = Security.from_byte(payload[:1])
            transport = Transport.from_byte(payload[1:2])

            return SDPRequest(security, transport)
        except ValueError as exc:
            raise InvalidSDPRequestError from exc

    def __len__(self):
        return 2

    def __repr__(self):
        return (
            "["
            f"Security: {self.security.name}"
            f", Protocol: {self.transport_protocol.name}"
            "]"
        )


def _out_of_spec_response_field(
    port: int, security: int, transport_protocol: int
) -> Optional[Tuple[str, int, str]]:
    """The first SDP response field outside [V2G2-078] Table 8, as
    ``(field, value, bound)``, or ``None`` when all three are legal."""
    if port < MIN_TCP_PORT or port > MAX_TCP_PORT:
        return "Port", port, f"{MIN_TCP_PORT}..{MAX_TCP_PORT} ([V2G2-078] Table 8)"
    if security not in Security.options():
        return (
            "Security",
            security,
            "0x00 (TLS) or 0x10 (no TLS); other values reserved ([V2G2-078])",
        )
    if transport_protocol not in Transport.options():
        return (
            "Transport",
            transport_protocol,
            "0x00 (TCP) or 0x10 (UDP); other values reserved ([V2G2-078])",
        )
    return None


class SDPResponse:
    """
    The SECC Discovery Protocol Request message, which the SECC uses to
    respond to the EVCC's SDPRequest, informing about its IP address and port
    and its security setting (TLS or plain TCP). The security setting is a
    reaction to the EVCC's security setting.
    """

    def __init__(
        self,
        ip_address: bytes,
        port: int,
        security: Security,
        transport_protocol: Transport,
    ):
        """Build a response the SECC will send; a bad value raises ``ValueError``.

        TODO: We may want to use here the related package or something like pydantic
              which adds some better validations (but also depends if it makes sense
              given the criteria of having a small image)
        """

        # Never leave a half-built object behind (conformance review SC-046):
        # a caller that passes a bad value gets an exception, not an instance
        # whose attributes are missing.
        if len(ip_address) != 16:
            raise ValueError(
                f"Please provide a valid IPv6 address with 16 bytes. "
                f"Provided: {len(ip_address)} bytes ({ip_address.hex()})"
            )
        out_of_spec = _out_of_spec_response_field(port, security, transport_protocol)
        if out_of_spec is not None:
            field, value, bound = out_of_spec
            raise ValueError(f"SDPResponse {field}={value!r} is outside {bound}")

        self.ip_address = ip_address
        self.port = port
        self.security = security
        self.transport_protocol = transport_protocol
        self.payload_type = 0x9001

    def to_payload(self) -> bytes:
        payload = (
            self.ip_address
            + self.port.to_bytes(2, "big")
            + self.security.value.to_bytes(1, "big")
            + self.transport_protocol.to_bytes(1, "big")
        )
        return payload

    @staticmethod
    def from_payload(payload) -> "SDPResponse":
        """Decode a received SDP response, discarding one that cannot be used.

        A payload of the wrong length, a port outside the dynamic range or a
        reserved Security / Transport byte ([V2G2-078] Table 8) is logged once
        as out-of-spec and raised as :class:`InvalidSDPResponseError`, so the
        discovery loop treats the datagram as if it had never arrived instead
        of crashing on it (issue #137).
        """
        if len(payload) != 20:
            discard_out_of_spec(
                "SDPResponse", "payload", payload, "20 bytes ([V2G2-078] Table 8)"
            )
            raise InvalidSDPResponseError(
                f"Payload must be of 20 bytes length. "
                f"Provided: {len(payload)} bytes ({payload})"
            )

        port = int.from_bytes(payload[16:18], "big")
        security_byte = int.from_bytes(payload[18:19], "big")
        transport_byte = int.from_bytes(payload[19:20], "big")
        out_of_spec = _out_of_spec_response_field(port, security_byte, transport_byte)
        if out_of_spec is not None:
            field, value, bound = out_of_spec
            discard_out_of_spec("SDPResponse", field, value, bound)
            raise InvalidSDPResponseError(
                f"SDP response discarded: {field}={value!r} is outside {bound}"
            )

        return SDPResponse(
            payload[:16],  # IPv6 address
            port,
            Security(security_byte),
            Transport(transport_byte),
        )

    def __len__(self):
        return 20

    def __repr__(self):
        ip_address: str = IPv6Address(int.from_bytes(self.ip_address, "big")).compressed
        return (
            f"[ IP address: {ip_address}"
            f", Port: {str(self.port)} "
            f", Security: {self.security.name} "
            f", Transport: {self.transport_protocol.name} ]"
        )


class SDPRequestWireless(SDPRequest):
    pass


class SDPResponseWireless(SDPResponse):
    pass


def create_sdp_response(
    sdp_request: Union[SDPRequest, SDPRequestWireless],
    ip_address: bytes,
    port: int,
    tls_enabled: bool,
) -> Union[SDPResponse, SDPResponseWireless]:
    """
    Creates an SDP response based on the incoming SDP request

    Args:
        sdp_request: The SDP request received from the UDP client
        ip_address: The IP address of the TCP server
        port: The port of the TCP or TLS server
        tls_enabled: Indicates if a TLS enabled server is available on SECC

    Returns:
        An SDPResponse or an SDPResponseWireless, depending on the SDP
        request type
    """
    sdp_response = None

    if tls_enabled:
        security = Security.TLS
    else:
        security = Security.NO_TLS

    if isinstance(sdp_request, SDPRequest):
        sdp_response = SDPResponse(ip_address, port, security, Transport.TCP)
    elif isinstance(sdp_request, SDPRequestWireless):
        raise NotImplementedError("SDPRequestWireless is not yet implemented")
    else:
        logger.error("Invalid SDP request, will ignore")

    return sdp_response
