"""V2GTP messages are framed on the TCP stream by the header's payload length
(issue #143, conformance review SC-027).

TCP is a byte stream: one ``read()`` is not one V2GTP message. A message
larger than a PLC-link segment (a CertificateInstallationRes runs 5-6 kB
against a 1440 B MSS) arrives in several reads, and two small messages can
arrive in one. [V2G2-088]/[V2G2-094] (DIN [V2G-DC-166]/[172], [V2G20-1229])
make the eight-byte header the delimiter: read it, then exactly the payload
length it declares. A header that fails the check is ignored ([V2G2-800],
DIN [V2G-DC-171]-[173], [V2G20-800]) rather than ending the session.

Seam: the shared ``V2GCommunicationSession.rcv_loop`` both roles run, fed
through a real ``asyncio.StreamReader`` with ``process_message`` stubbed to
record each frame it is handed, plus ``V2GTPMessage.from_bytes`` to show the
reassembled frame is a whole message.
"""

from __future__ import annotations

import asyncio
import types

import pytest

from app.shared.comm_session import V2GCommunicationSession
from app.shared.exceptions import InvalidV2GTPMessageError
from app.shared.messages.enums import (
    DINPayloadTypes,
    ISOV2PayloadTypes,
    ISOV20PayloadTypes,
    Protocol,
)
from app.shared.messages.v2gtp import V2GTPMessage
from tests.conformance.out_of_spec_log import (
    OUT_OF_SPEC_LOGGER,
    assert_single_out_of_spec_warning,
)

# CertificateInstallationRes is the largest message on the wire (~5-6 kB).
CERT_SIZED_PAYLOAD = bytes(range(256)) * 24  # 6144 B
# TCP maximum segment size on the PLC links.
PLC_MSS = 1440

V2GTP_VERSION = bytes([0x01, 0xFE])
BAD_VERSION = bytes([0x02, 0xFD])
EXI_PAYLOAD_TYPE = bytes([0x80, 0x01])
RESERVED_PAYLOAD_TYPE = bytes([0x70, 0x00])

# Both roles run the one shared receive loop, so the cases vary the negotiated
# protocol (whose payload-type table the header is checked against): the EVCC
# receives the CertificateInstallationRes over ISO-2, the SECC receives the
# EV's messages over DIN or ISO-20.
PROTOCOLS = [
    pytest.param(Protocol.ISO_15118_2, ISOV2PayloadTypes.EXI_ENCODED, id="evcc-iso2"),
    pytest.param(Protocol.DIN_SPEC_70121, DINPayloadTypes.EXI_ENCODED, id="secc-din"),
    pytest.param(
        Protocol.ISO_15118_20_DC, ISOV20PayloadTypes.DC_MAINSTREAM, id="secc-iso20-dc"
    ),
]


def _frame(protocol, payload_type, payload: bytes) -> bytes:
    return V2GTPMessage(protocol, payload_type, payload).to_bytes()


def _raw_frame(version: bytes, payload_type: bytes, payload: bytes) -> bytes:
    return version + payload_type + len(payload).to_bytes(4, "big") + payload


def _session(protocol, reader):
    """The slice of a comm session ``rcv_loop`` touches, with the state
    machine stubbed: every frame is recorded and nothing is sent back."""
    received: list[bytes] = []
    stops: list[str] = []

    async def process_message(message):
        received.append(message)

    async def stop(reason):
        stops.append(reason)

    session = types.SimpleNamespace(
        reader=reader,
        protocol=protocol,
        peer_name=("fe80::1", 0),
        last_message_sent=None,
        session_handler_queue=asyncio.Queue(),
        current_state=types.SimpleNamespace(
            next_v2gtp_msg=None, next_state=None, next_msg_timeout=2
        ),
        process_message=process_message,
        stop=stop,
        go_to_next_state=lambda: None,
    )
    session.comm_session = session
    return session, received, stops


async def _run(protocol, chunks: list[bytes]):
    """Feed ``chunks`` as separate TCP reads, then EOF, through rcv_loop."""
    reader = asyncio.StreamReader()
    session, received, stops = _session(protocol, reader)

    async def feed():
        for chunk in chunks:
            reader.feed_data(chunk)
            await asyncio.sleep(0)
        reader.feed_eof()

    feeder = asyncio.create_task(feed())
    await asyncio.wait_for(V2GCommunicationSession.rcv_loop(session, 2), timeout=5)
    await feeder
    return received, stops


@pytest.mark.parametrize("protocol, payload_type", PROTOCOLS)
@pytest.mark.parametrize("split_at", [1, 7, 8, 9, PLC_MSS, 6151])
async def test_split_message_is_reassembled_once(protocol, payload_type, split_at):
    frame = _frame(protocol, payload_type, CERT_SIZED_PAYLOAD)

    received, stops = await _run(protocol, [frame[:split_at], frame[split_at:]])

    assert received == [frame]
    msg = V2GTPMessage.from_bytes(protocol, received[0])
    assert msg.payload == CERT_SIZED_PAYLOAD
    # The only stop is the peer closing the stream after the message.
    assert stops == ["TCP peer closed connection"]


@pytest.mark.parametrize("protocol, payload_type", PROTOCOLS)
async def test_message_split_across_many_segments(protocol, payload_type):
    frame = _frame(protocol, payload_type, CERT_SIZED_PAYLOAD)
    segments = [frame[i : i + PLC_MSS] for i in range(0, len(frame), PLC_MSS)]

    received, _ = await _run(protocol, segments)

    assert received == [frame]


@pytest.mark.parametrize("protocol, payload_type", PROTOCOLS)
async def test_coalesced_messages_decode_in_order(protocol, payload_type):
    first = _frame(protocol, payload_type, b"\x80\x01first")
    second = _frame(protocol, payload_type, b"\x80\x02second-message")

    received, _ = await _run(protocol, [first + second])

    assert received == [first, second]


@pytest.mark.parametrize("protocol, payload_type", PROTOCOLS)
@pytest.mark.parametrize(
    "bad_frame",
    [
        pytest.param(_raw_frame(BAD_VERSION, EXI_PAYLOAD_TYPE, b"\x80\x00garbage"), id="bad-version"),
        pytest.param(_raw_frame(V2GTP_VERSION, RESERVED_PAYLOAD_TYPE, b"\x80\x00garbage"), id="unknown-type"),
    ],
)
async def test_bad_header_is_logged_and_skipped(protocol, payload_type, bad_frame, caplog):
    good = _frame(protocol, payload_type, b"\x80\x01good")
    caplog.set_level("WARNING", logger=OUT_OF_SPEC_LOGGER)

    # The bad message coalesced with a good one, and a good one on its own:
    # neither is lost and the session does not stop on the bad header.
    received, stops = await _run(protocol, [bad_frame + good, good])

    assert received == [good, good]
    assert stops == ["TCP peer closed connection"]
    assert_single_out_of_spec_warning(caplog, "discarded", bad_frame[:8].hex())


async def test_oversized_payload_length_is_skipped_header_only(caplog):
    """A declared length beyond any receive buffer cannot be read through, so
    only the header is dropped; the stream then resynchronises."""
    protocol, payload_type = Protocol.ISO_15118_2, ISOV2PayloadTypes.EXI_ENCODED
    oversized = V2GTP_VERSION + EXI_PAYLOAD_TYPE + bytes([0xFF, 0xFF, 0xFF, 0xFF])
    good = _frame(protocol, payload_type, b"\x80\x01good")
    caplog.set_level("WARNING", logger=OUT_OF_SPEC_LOGGER)

    received, stops = await _run(protocol, [oversized + good])

    assert received == [good]
    assert_single_out_of_spec_warning(caplog, "PayloadLength", 0xFFFFFFFF)


async def test_peer_closing_mid_message_stops_the_session():
    protocol, payload_type = Protocol.ISO_15118_2, ISOV2PayloadTypes.EXI_ENCODED
    frame = _frame(protocol, payload_type, CERT_SIZED_PAYLOAD)

    received, stops = await _run(protocol, [frame[:3000]])

    assert received == []
    assert len(stops) == 1 and stops[0].startswith("TCP peer closed connection")


def test_from_bytes_rejects_payload_length_mismatch():
    frame = _frame(Protocol.ISO_15118_2, ISOV2PayloadTypes.EXI_ENCODED, b"\x80\x01ab")
    with pytest.raises(InvalidV2GTPMessageError):
        V2GTPMessage.from_bytes(Protocol.ISO_15118_2, frame + b"extra")
