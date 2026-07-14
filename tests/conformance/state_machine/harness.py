"""Scripted-peer harness at the `State.process_message()` seam.

Per ADR-0003 § State-machine layer:

> Seam: in-process at `process_message()`. One role under test, a scripted
> peer feeding inbound messages.
> Oracle: state-trajectory match — for a given inbound sequence under a given
> personality, assert the outbound sequence and final state.

The harness deliberately stays away from sockets, EXI codec round-trips, and
the comm-session receive loop. Those are the responsibility of the E2E and
codec layers, and ADR-0003 chose this seam specifically because *not* dragging
them in is what makes the state-machine layer fast (<30 s) enough to be the
TDD loop for the personality YAML rollout.

The single thing the harness still needs the EXI codec for is the
`create_next_message` call inside the State under test — it encodes the
outbound message and wraps it in a V2GTPMessage. That's a real implementation
detail and replacing it with a stub would weaken the oracle.

Slice 1 ships the harness plus one DIN smoke test. Per-protocol fan-out is
the responsibility of personality Slices 2–4 (#7 / #8 / #9).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Type

from app.shared.messages.enums import Protocol
from app.shared.notifications import StopNotification
from app.shared.states import State


@dataclass
class StubCommSession:
    """Minimal stand-in for EVCC/SECC CommunicationSession.

    States touch a handful of session attributes — `session_id`, `protocol`,
    `stop_reason`, `evse_controller` / `ev_controller`, plus the role-specific
    fields set during the handshake. This stub starts with the universally
    required ones and accepts ad-hoc extras via `setattr`.

    Heavy collaborators (the asyncio transport, the session-handler queue) are
    intentionally absent — the seam is `process_message()`, not the rcv loop.
    """

    protocol: Protocol = Protocol.UNKNOWN
    session_id: str = bytes(1).hex()
    stop_reason: Optional[StopNotification] = None
    current_state: Optional[State] = None
    # Set by State.__init__ via comm_session.current_state assignment.
    _started: bool = True
    # Optional collaborators. Filled in by harness factory functions.
    evse_controller: Optional[Any] = None
    ev_controller: Optional[Any] = None
    # EVCC ONGOING-poll cadence (issue #88). Defaults to 0 — un-paced — so a
    # test that isn't about pacing runs at full speed; the pacing tests set it.
    ongoing_poll_interval: float = 0.0
    # Role-specific fields populated by states during a session. Allowing them
    # as Any keeps the stub honest about being a *stub* while still permitting
    # the assignments the production code does.
    evcc_id: Any = None
    evse_id: Any = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class StepResult:
    """One scripted-peer step: the inbound message and what the role did."""

    next_state: Optional[Type[State]]
    outbound_v2gtp: Any  # V2GTPMessage or None if state chose not to send.
    outbound_msg: Any  # State.message — the decoded outbound body/message.


class ScriptedPeer:
    """Driver around a single role's State graph.

    Usage:

        peer = ScriptedPeer(session, start_state=SessionSetup)
        result = await peer.feed(session_setup_req)
        assert result.next_state is ServiceDiscovery
    """

    def __init__(self, comm_session: Any, start_state: Type[State]):
        self.comm_session = comm_session
        self.state: State = start_state(comm_session)

    async def feed(self, inbound: Any) -> StepResult:
        await self.state.process_message(inbound)
        result = StepResult(
            next_state=self.state.next_state,
            outbound_v2gtp=self.state.next_v2gtp_msg,
            outbound_msg=self.state.message,
        )
        # If the state told us to advance, build the next state so subsequent
        # `feed()` calls hit the right `process_message`. Terminate is a leaf;
        # we don't instantiate it.
        from app.shared.states import Terminate

        if result.next_state is not None and result.next_state is not Terminate:
            self.state = result.next_state(self.comm_session)
        return result
