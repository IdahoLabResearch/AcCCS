"""The EVCC discards an SDP response it cannot use and keeps discovering
(issue #137, conformance review SC-046).

[V2G2-078] Table 8 restricts the SECC's TCP port to the dynamic range
49152-65535 and reserves every Security / Transport byte other than the two
defined values. A charger that answers with port 8000 (or a reserved byte)
used to leave the EVCC with a half-built ``SDPResponse`` or a bare
``ValueError``, and the handler loop ended with nothing more sent. The posture
is to log the value once as out-of-spec, drop that datagram, and go back to
listening for the rest of the request's 250 ms window, exactly as if no
response had arrived: the receive timeout then sends the next SDPRequest
within the 50-request budget of [V2G2-160].

Two seams: ``SDPResponse.from_payload`` (the decode) and the handler's UDP
path (``process_incoming_udp_packet`` and the ``get_from_rcv_queue`` loop that
drives it), with the UDP client, SDP sender and TCP client stubbed out.
"""

from __future__ import annotations

import asyncio
import logging
import types
from ipaddress import IPv6Address

import pytest

from app.evcc.comm_session_handler import CommunicationSessionHandler
from app.shared.exceptions import InvalidSDPResponseError
from app.shared.messages.enums import ISOV2PayloadTypes, Protocol
from app.shared.messages.sdp import SDPResponse, Security, Transport
from app.shared.messages.v2gtp import V2GTPMessage
from app.shared.notifications import UDPPacketNotification
from tests.conformance.out_of_spec_log import (
    OUT_OF_SPEC_LOGGER,
    assert_single_out_of_spec_warning,
)

SECC_ADDRESS = IPv6Address("fe80::1").packed
OUT_OF_RANGE_PORT = 8000
RESERVED_BYTE = 0x05


def _payload(port: int, security: int, transport: int) -> bytes:
    return (
        SECC_ADDRESS
        + port.to_bytes(2, "big")
        + security.to_bytes(1, "big")
        + transport.to_bytes(1, "big")
    )


BAD_RESPONSES = [
    pytest.param(
        _payload(OUT_OF_RANGE_PORT, Security.TLS, Transport.TCP),
        ("SDPResponse", "Port", OUT_OF_RANGE_PORT, "49152"),
        id="port-8000",
    ),
    pytest.param(
        _payload(50000, RESERVED_BYTE, Transport.TCP),
        ("SDPResponse", "Security", RESERVED_BYTE),
        id="reserved-security-byte",
    ),
    pytest.param(
        _payload(50000, Security.TLS, RESERVED_BYTE),
        ("SDPResponse", "Transport", RESERVED_BYTE),
        id="reserved-transport-byte",
    ),
    pytest.param(
        _payload(50000, Security.TLS, Transport.TCP)[:19],
        ("SDPResponse", "payload", "20 bytes"),
        id="wrong-length",
    ),
]


@pytest.mark.parametrize("payload, needles", BAD_RESPONSES)
def test_from_payload_rejects_the_value_with_one_warning(payload, needles, caplog):
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        with pytest.raises(InvalidSDPResponseError):
            SDPResponse.from_payload(payload)
    assert_single_out_of_spec_warning(caplog, *needles)


def test_constructor_never_leaves_a_half_built_response():
    """The constructor used to log and return, leaving an instance with no
    attributes for the next reader to trip over (SC-046)."""
    with pytest.raises(ValueError):
        SDPResponse(SECC_ADDRESS, OUT_OF_RANGE_PORT, Security.TLS, Transport.TCP)


def test_from_payload_still_accepts_a_conformant_response():
    response = SDPResponse.from_payload(_payload(50000, Security.TLS, Transport.TCP))
    assert (response.port, response.security, response.transport_protocol) == (
        50000,
        Security.TLS,
        Transport.TCP,
    )


# -- handler path -------------------------------------------------------------


def _handler():
    """A handler with the UDP/TCP collaborators replaced by recorders."""
    handler = CommunicationSessionHandler.__new__(CommunicationSessionHandler)
    handler.restarts = []
    handler.sessions = []
    handler.listens = 0

    async def restart_sdp(new_sdp_cycle: bool):
        handler.restarts.append(new_sdp_cycle)

    async def start_comm_session(host, port, is_tls):
        handler.sessions.append((host, port, is_tls))

    async def receive():
        handler.listens += 1

    handler.restart_sdp = restart_sdp
    handler.start_comm_session = start_comm_session
    handler.udp_client = types.SimpleNamespace(receive=receive)
    return handler


def _datagram(payload: bytes) -> UDPPacketNotification:
    data = V2GTPMessage(
        Protocol.UNKNOWN, ISOV2PayloadTypes.SDP_RESPONSE, payload
    ).to_bytes()
    return UDPPacketNotification(data, ("fe80::1", 15118))


@pytest.mark.parametrize("payload, needles", BAD_RESPONSES)
async def test_bad_response_is_discarded_and_discovery_keeps_listening(
    payload, needles, caplog
):
    handler = _handler()
    with caplog.at_level(logging.WARNING, logger=OUT_OF_SPEC_LOGGER):
        await handler.process_incoming_udp_packet(_datagram(payload))

    assert handler.sessions == [], "no TCP session may start on a discarded response"
    assert handler.listens == 1, (
        "a discarded response is no response: keep listening for the rest of "
        "the request window so the receive timeout paces the next SDPRequest"
    )
    assert handler.restarts == [], "no new retry cycle, no request out of turn"
    assert_single_out_of_spec_warning(caplog, *needles)


async def test_handler_loop_survives_a_bad_response():
    handler = _handler()
    queue: asyncio.Queue = asyncio.Queue()
    queue.put_nowait(_datagram(_payload(OUT_OF_RANGE_PORT, Security.TLS, Transport.TCP)))

    loop_task = asyncio.create_task(handler.get_from_rcv_queue(queue))
    await asyncio.wait_for(queue.join(), timeout=2.0)
    await asyncio.sleep(0)

    assert not loop_task.done(), "the discovery loop must keep running"
    assert handler.listens == 1
    loop_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await loop_task
