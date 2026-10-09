"""Log-and-continue for peer values the message model tolerates (issue #124).

A real charger or vehicle sometimes sends a value that is legal on the wire
(the codec decodes it) but outside what our message model expected. The
receive posture is to *accept* such a value and keep the session alive,
logging it once at warning level so the operator can attribute a later
failure to the peer rather than to the emulator.

Every tolerant validator funnels through :func:`accept_out_of_spec` so the
line has one shape: the owning model, the wire field, the value and the spec
bound it falls outside. A later tolerant-receive framework (conformance
review SC-031) can replace this helper wholesale; nothing else should format
an out-of-spec line by hand.
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
