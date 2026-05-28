"""EXPy-backed EXI codec.

Wraps :class:`expy.EXIProcessor` per AcCCS :class:`Namespace`. The
processor's three roots (Document / Fragment / XmldsigFragment) are
surfaced as six methods on this class. The :class:`~app.shared.exi_codec.EXI`
wrapper translates Pydantic models to/from the EVerest dict shape and
dispatches here.

Per ADR-0002 the SAP and DIN namespaces only expose the Document root;
the other six namespaces expose all three. ``Namespace.XML_DSIG`` is
*not* an EXPy namespace — xmldsig payloads from AcCCS callsites are
routed to the ISO 15118-2 processor's xmldsig root (the historical
anchor for AcCCS, see ADR-0002 / replay-corpus dispatch).
"""

from __future__ import annotations

import logging
from typing import Dict, Literal

from expy import EXIProcessor, Namespace as ExpyNamespace

from app.shared.messages.enums import Namespace

logger = logging.getLogger(__name__)


_NS_MAP: Dict[str, ExpyNamespace] = {
    Namespace.SAP: ExpyNamespace.SAP,
    Namespace.DIN_MSG_DEF: ExpyNamespace.DIN,
    Namespace.ISO_V2_MSG_DEF: ExpyNamespace.ISO2,
    Namespace.ISO_V20_COMMON_MSG: ExpyNamespace.ISO20_COMMON,
    Namespace.ISO_V20_AC: ExpyNamespace.ISO20_AC,
    Namespace.ISO_V20_DC: ExpyNamespace.ISO20_DC,
    Namespace.ISO_V20_WPT: ExpyNamespace.ISO20_WPT,
    Namespace.ISO_V20_ACDP: ExpyNamespace.ISO20_ACDP,
    # AcCCS routes ``Namespace.XML_DSIG`` to ISO-2's xmldsig fragment
    # processor (libcbv2g exposes xmldsig per protocol namespace, not
    # standalone). Both sides of a session pick the same processor, so
    # SignedInfo digests still match.
    Namespace.XML_DSIG: ExpyNamespace.ISO2,
}


Root = Literal["document", "fragment", "xmldsig"]


class EXPyEXICodec:
    """Per-namespace dispatcher onto :class:`expy.EXIProcessor`.

    Processors are instantiated lazily and cached.
    """

    def __init__(self) -> None:
        self._processors: Dict[str, EXIProcessor] = {}

    def get_version(self) -> str:
        try:
            from importlib.metadata import version

            return f"EXPy {version('expy')}"
        except Exception:  # noqa: BLE001
            return "EXPy"

    def _processor(self, namespace: str) -> EXIProcessor:
        proc = self._processors.get(namespace)
        if proc is None:
            try:
                expy_ns = _NS_MAP[namespace]
            except KeyError as exc:
                raise KeyError(
                    f"No EXPy Namespace registered for AcCCS namespace {namespace!r}"
                ) from exc
            proc = EXIProcessor(expy_ns)
            self._processors[namespace] = proc
        return proc

    def encode_document(self, payload: dict, namespace: str) -> bytes:
        return self._processor(namespace).encode(payload)

    def decode_document(self, exi_bytes: bytes, namespace: str) -> dict:
        return self._processor(namespace).decode(exi_bytes)

    def encode_fragment(self, payload: dict, namespace: str) -> bytes:
        return self._processor(namespace).encode_fragment(payload)

    def decode_fragment(self, exi_bytes: bytes, namespace: str) -> dict:
        return self._processor(namespace).decode_fragment(exi_bytes)

    def encode_xmldsig(self, payload: dict, namespace: str) -> bytes:
        return self._processor(namespace).encode_xmldsig(payload)

    def decode_xmldsig(self, exi_bytes: bytes, namespace: str) -> dict:
        return self._processor(namespace).decode_xmldsig(exi_bytes)
