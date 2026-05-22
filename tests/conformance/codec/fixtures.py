"""Codec-layer fixture registry.

Per ADR-0003:

    Fixtures are `(pydantic_model, expected_bytes)` pairs.
    Bootstrapped from the current (Exificient) codec during ADR-0002 Slices 1–3.
    Rebaselined against EXPy at ADR-0002 Slice 5.

Each fixture is a `CodecFixture` registered in `FIXTURES`. The codec test
discovers entries by iterating this list. Per-protocol fixture growth happens
in EXPy Slices 1–3 (#12 / #13 / #14) — they add entries here. Slice 1 seeds
one DIN entry from the current Exificient codec to prove the layer runs.

Why a Python registry rather than data files: the messages are pydantic
models, the namespace is an enum, and constructing them in Python is the
clearest single-source-of-truth. The golden bytes are stored next to the
registry as `.bin` files, named by the fixture id.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from pydantic import BaseModel

GOLDENS_DIR = Path(__file__).parent / "goldens"


@dataclass(frozen=True)
class CodecFixture:
    id: str
    protocol: str  # "din70121" | "iso15118-2" | "iso15118-20"
    namespace: str
    build: Callable[[], BaseModel]

    @property
    def golden_path(self) -> Path:
        return GOLDENS_DIR / f"{self.id}.bin"


# --- DIN 70121 ------------------------------------------------------------


def _din_session_setup_req() -> BaseModel:
    from app.shared.messages.din_spec.body import Body, SessionSetupReq
    from app.shared.messages.din_spec.header import MessageHeader
    from app.shared.messages.din_spec.msgdef import V2GMessage

    body = Body(session_setup_req=SessionSetupReq(evcc_id="00112233445566"))
    header = MessageHeader(session_id=bytes(1).hex())
    return V2GMessage(header=header, body=body)


def _din_namespace() -> str:
    from app.shared.messages.enums import Namespace

    return Namespace.DIN_MSG_DEF


FIXTURES: list[CodecFixture] = [
    CodecFixture(
        id="din-session-setup-req",
        protocol="din70121",
        namespace=_din_namespace(),
        build=_din_session_setup_req,
    ),
]
