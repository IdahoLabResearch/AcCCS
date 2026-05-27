"""Replay-corpus discovery + non-document Pydantic class lookup.

Per ADR-0003's replay layer: captured wire bytes are fed through the
EXI codec; this module enumerates them. Each entry comes from a JSONL
record written by ``app/shared/exi_capture.py`` during a virtual or
hardware session.

Records are deduplicated by ``(ns, root, hex)`` because a single session
emits the same bytes through both an ``encode`` (sender) and ``decode``
(receiver) event, plus repeats of cyclic messages like
``CurrentDemand``.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Dict, Iterator, List, Tuple, Type

import yaml

CAPTURES_ROOT = Path(__file__).resolve().parent.parent / "captures"


@dataclasses.dataclass(frozen=True)
class ReplayRecord:
    capture: str          # logical name of the source capture file (no extension)
    source: str           # "veth" | "hw:<device>"
    protocol: str         # din70121 | iso15118-2 | iso15118-20
    energy_mode: str
    ns: str
    root: str             # document | fragment | xmldsig
    model: str            # encode-side str(model), or decoder envelope key
    direction: str        # encode | decode
    payload: bytes

    @property
    def id(self) -> str:
        # Keep the id stable per (capture, ns, root, model, hex-prefix) so
        # pytest -k can target a single record without hex collisions.
        short = self.payload.hex()[:12]
        return f"{self.capture}-{self.root}-{self.model}-{short}"


def _load_capture(jsonl_path: Path, meta: dict) -> Iterator[ReplayRecord]:
    name = jsonl_path.stem
    with jsonl_path.open() as fh:
        for line in fh:
            r = json.loads(line)
            yield ReplayRecord(
                capture=name,
                source=meta.get("source", "unknown"),
                protocol=meta.get("protocol", "unknown"),
                energy_mode=meta.get("energy_mode", "unknown"),
                ns=r["ns"],
                root=r["root"],
                model=r["model"],
                direction=r["dir"],
                payload=bytes.fromhex(r["hex"]),
            )


def iter_captures() -> Iterator[Path]:
    if not CAPTURES_ROOT.exists():
        return
    for sub in sorted(CAPTURES_ROOT.iterdir()):
        if not sub.is_dir():
            continue
        for jsonl in sorted(sub.glob("*.jsonl")):
            yield jsonl


def load_corpus() -> List[ReplayRecord]:
    """Discover all captures and return a deduplicated record list."""
    seen: Dict[Tuple[str, str, bytes], ReplayRecord] = {}
    for jsonl in iter_captures():
        yaml_path = jsonl.with_suffix(".yaml")
        meta: dict = {}
        if yaml_path.exists():
            meta = yaml.safe_load(yaml_path.read_text()) or {}
        for rec in _load_capture(jsonl, meta):
            key = (rec.ns, rec.root, rec.payload)
            if key in seen:
                # Prefer encode records — their ``model`` carries the
                # encode-site class name, which is what the fragment /
                # xmldsig harness path needs for Pydantic reconstruction.
                if seen[key].direction == "decode" and rec.direction == "encode":
                    seen[key] = rec
                continue
            seen[key] = rec
    return list(seen.values())


# ---- Pydantic class lookup for non-document records ----
#
# Documents are dispatched by ``EXI().from_exi`` via namespace inspection.
# Fragments and xmldsig fragments are not — the harness needs an explicit
# class given the encode-site model name. The set of names is small and
# enumerated here; if a new fragment shows up in a future capture, add
# its name here.


def fragment_model_class(model_name: str, ns: str) -> Type:
    if model_name == "AuthorizationReq":
        from app.shared.messages.iso15118_2.body import AuthorizationReq

        return AuthorizationReq
    if model_name == "CertificateInstallationReq":
        from app.shared.messages.iso15118_2.body import CertificateInstallationReq

        return CertificateInstallationReq
    if model_name == "MeteringReceiptReq":
        from app.shared.messages.iso15118_2.body import MeteringReceiptReq

        return MeteringReceiptReq
    if model_name == "SalesTariff":
        from app.shared.messages.iso15118_2.datatypes import SalesTariff

        return SalesTariff
    if model_name == "ContractSignatureCertChain":
        from app.shared.messages.iso15118_2.datatypes import CertificateChain

        return CertificateChain
    if model_name == "ContractSignatureEncryptedPrivateKey":
        from app.shared.messages.iso15118_2.datatypes import EncryptedPrivateKey

        return EncryptedPrivateKey
    if model_name == "DHpublickey":
        from app.shared.messages.iso15118_2.datatypes import DHPublicKey

        return DHPublicKey
    if model_name == "eMAID":
        from app.shared.messages.iso15118_2.datatypes import EMAID

        return EMAID
    if model_name == "PnC_AReqAuthorizationMode":
        from app.shared.messages.iso15118_20.common_messages import PnCAuthReqParams

        return PnCAuthReqParams
    raise KeyError(f"No fragment model class registered for {model_name!r} (ns={ns})")


def xmldsig_model_class(model_name: str) -> Type:
    if model_name == "SignedInfo":
        from app.shared.messages.xmldsig import SignedInfo

        return SignedInfo
    raise KeyError(f"No xmldsig model class registered for {model_name!r}")


# ---- EXPy namespace dispatch ----


def expy_namespace(ns: str):
    """Map an AcCCS Namespace string to the matching ``expy.Namespace``."""
    from expy import Namespace as ExpyNS

    from app.shared.messages.enums import Namespace

    if ns == Namespace.DIN_MSG_DEF:
        return ExpyNS.DIN
    if ns == Namespace.ISO_V2_MSG_DEF:
        return ExpyNS.ISO2
    if ns == Namespace.SAP:
        return ExpyNS.SAP
    if ns == Namespace.ISO_V20_COMMON_MSG:
        return ExpyNS.ISO20_COMMON
    if ns == Namespace.ISO_V20_AC:
        return ExpyNS.ISO20_AC
    if ns == Namespace.ISO_V20_DC:
        return ExpyNS.ISO20_DC
    if ns == Namespace.ISO_V20_WPT:
        return ExpyNS.ISO20_WPT
    if ns == Namespace.ISO_V20_ACDP:
        return ExpyNS.ISO20_ACDP
    if ns == Namespace.XML_DSIG:
        # xmldsig fragments are encoded under whichever sibling namespace
        # exposes the xmldsig root in EXPy v1.0; ISO2 is the historical
        # anchor (see ADR-0002). The caller decides at xmldsig call sites.
        return ExpyNS.ISO2
    raise KeyError(f"No EXPy namespace mapping for {ns!r}")
