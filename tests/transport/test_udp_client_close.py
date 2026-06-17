"""Regression tests for EVCC UDP-client teardown (fd-leak parity, #53).

The idle-and-re-arm lifecycle (ADR-0005) builds a fresh ``UDPClient`` — and a
fresh datagram endpoint — for every session cycle. The SECC's ``UDPServer``
already frees its bound SDP port between cycles via ``close()``; the EVCC's
client had no equivalent, so each re-arm leaked one UDP socket fd. Under
continuous auto-rearm (#43) those fds accumulate.

These cover the three acceptance criteria:

1. ``UDPClient.close()`` closes the datagram transport (and is idempotent).
2. The EVCC handler closes its UDP client when the session cycle ends, on both
   the clean and the failure path.
3. Repeated start/close cycles do not accumulate UDP socket fds.

The socket tests use a real IPv6 multicast datagram endpoint on ``lo`` (no
privileges needed for UDP); they skip on platforms that can't open one.
"""

from __future__ import annotations

import asyncio
import os
import types

import pytest

import app.evcc.comm_session_handler as csh
from app.evcc.transport.udp_client import UDPClient


def _can_open_socket() -> bool:
    try:
        sock = UDPClient._create_socket("lo")
        sock.close()
        return True
    except OSError:
        return False


_SOCKET_AVAILABLE = _can_open_socket()
_FD_DIR = "/proc/self/fd"

needs_socket = pytest.mark.skipif(
    not _SOCKET_AVAILABLE, reason="IPv6 multicast datagram socket on lo unavailable"
)


def _fd_count() -> int:
    return len(os.listdir(_FD_DIR))


async def _settle() -> None:
    """Let the event loop run the transport's deferred socket close."""
    for _ in range(5):
        await asyncio.sleep(0.01)


@needs_socket
async def test_close_releases_transport_and_resets_state():
    client = UDPClient(asyncio.Queue(), "lo")
    await client.start()
    assert client._transport is not None

    client.close()
    await _settle()

    assert client._transport is None
    assert client.started is False

    # Idempotent: a second close on an already-closed client is a no-op.
    client.close()
    assert client._transport is None


@needs_socket
@pytest.mark.skipif(
    not os.path.isdir(_FD_DIR), reason="needs /proc/self/fd to count descriptors"
)
async def test_repeated_start_close_does_not_leak_fds():
    queue = asyncio.Queue()
    n = 25
    baseline = _fd_count()

    # Hold references so the GC can't reclaim (and silently close) the
    # transports — close() must free the fds explicitly.
    clients = [UDPClient(queue, "lo") for _ in range(n)]
    for client in clients:
        await client.start()
    after_start = _fd_count()

    for client in clients:
        client.close()
    await _settle()
    after_close = _fd_count()

    # Sanity: starting really did open the sockets we're about to free.
    assert after_start >= baseline + n - 2
    # The fix: after closing every cycle's client, the fd count returns to
    # baseline (small tolerance for unrelated event-loop fds).
    assert after_close <= baseline + 2


class _FakeUDPClient:
    """Records close() calls; start() is a trivial awaitable for the task list."""

    instances: list = []

    def __init__(self, queue, iface):
        self.closed = 0
        _FakeUDPClient.instances.append(self)

    async def start(self):
        return None

    def close(self):
        self.closed += 1


def _make_handler() -> csh.CommunicationSessionHandler:
    config = types.SimpleNamespace(sdp_retry_cycles=1)
    codec = types.SimpleNamespace(get_version=lambda: "test-codec")
    return csh.CommunicationSessionHandler(
        config=config,
        iface="lo",
        codec=codec,
        ev_controller=None,
        live_control=None,
    )


@pytest.fixture
def patched_handler(monkeypatch):
    _FakeUDPClient.instances = []
    monkeypatch.setattr(csh, "UDPClient", _FakeUDPClient)
    return _make_handler


async def _drain_then(await_tasks, raise_exc):
    # Mirror wait_for_tasks' contract enough for the test: consume the task
    # coroutines so we don't leak "never awaited" warnings.
    for task in await_tasks:
        if asyncio.iscoroutine(task):
            task.close()
    if raise_exc is not None:
        raise raise_exc


async def test_handler_closes_udp_client_on_clean_cycle_end(monkeypatch, patched_handler):
    async def fake_wait(await_tasks, **_kwargs):
        await _drain_then(await_tasks, None)

    monkeypatch.setattr(csh, "wait_for_tasks", fake_wait)
    handler = patched_handler()

    await handler.start_session_handler()

    assert len(_FakeUDPClient.instances) == 1
    assert _FakeUDPClient.instances[0].closed == 1


async def test_handler_closes_udp_client_on_failed_cycle(monkeypatch, patched_handler):
    async def fake_wait(await_tasks, **_kwargs):
        await _drain_then(await_tasks, RuntimeError("session blew up"))

    monkeypatch.setattr(csh, "wait_for_tasks", fake_wait)
    handler = patched_handler()

    with pytest.raises(RuntimeError):
        await handler.start_session_handler()

    assert _FakeUDPClient.instances[0].closed == 1
