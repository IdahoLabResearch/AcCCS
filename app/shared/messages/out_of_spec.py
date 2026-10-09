"""Log-and-continue for peer values the message model tolerates (issue #124).

A real charger or vehicle sometimes sends a value that is legal on the wire
(the codec decodes it) but outside what our message model expected. The
receive posture is to *accept* such a value and keep the session alive,
logging it once at warning level so the operator can attribute a later
failure to the peer rather than to the emulator.

Every tolerant validator funnels through :func:`accept_out_of_spec` so the
line has one shape: the owning model, the wire field, the value and the spec
bound it falls outside. A peer message that cannot be used at all (an SDP
response naming a port outside the dynamic range, a SLAC frame announcing
zero sounds) is dropped rather than kept; :func:`discard_out_of_spec` logs
that with the same shape so the operator reads both outcomes the same way
(issue #137). A later tolerant-receive framework (conformance review SC-031)
can replace both helpers wholesale; nothing else should format an out-of-spec
line by hand.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def accept_out_of_spec(owner: str, field: str, value: Any, bound: str) -> None:
    """Log that ``owner.field`` carried ``value``, outside ``bound``, and was kept.

    ``owner`` is the Pydantic model that holds the field (the V2G message for a
    top-level field, the complex type otherwise); ``field`` is the wire alias;
    ``bound`` names the spec constraint the value falls outside.
    """
    logger.warning(
        "Out-of-spec value accepted: %s.%s=%r (bound: %s)", owner, field, value, bound
    )


def discard_out_of_spec(owner: str, field: str, value: Any, bound: str) -> None:
    """Log that ``owner.field`` carried ``value``, outside ``bound``, and the
    message was dropped as if never received.

    Same arguments as :func:`accept_out_of_spec`; this is the branch for a
    value the receiver cannot work around (the spec tells it to ignore the
    message), so the session continues as though the peer had stayed silent.
    """
    logger.warning(
        "Out-of-spec value discarded: %s.%s=%r (bound: %s)", owner, field, value, bound
    )
