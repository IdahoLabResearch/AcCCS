#!/usr/bin/env python3
"""Regenerate codec-layer golden bytes from the current EXI codec.

Per ADR-0003: the codec corpus is bootstrapped from the Exificient codec
during ADR-0002 Slices 1–3 and rebaselined against EXPy at Slice 5.

Usage:

    python scripts/regen_codec_goldens.py                # all fixtures
    python scripts/regen_codec_goldens.py <fixture-id>   # one fixture

Refuses to overwrite an existing golden unless `--force` is passed. That
guardrail is what gives the corpus its regression-detection value — see
ADR-0002 Slice 5 amendment.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture_id", nargs="?", help="Only regenerate this fixture")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing goldens — required for any rebaselining",
    )
    args = parser.parse_args(argv)

    from app.shared.everest_shape import (
        pydantic_to_everest_fragment,
        pydantic_to_everest_xmldsig,
    )
    from app.shared.exi_codec import EXI
    from app.shared.exificient_exi_codec import ExificientEXICodec
    from app.shared.messages.enums import Namespace
    from app.shared.settings import load_shared_settings
    from tests.conformance.codec.fixtures import FIXTURES, GOLDENS_DIR

    load_shared_settings()
    EXI().set_exi_codec(ExificientEXICodec())
    GOLDENS_DIR.mkdir(parents=True, exist_ok=True)

    selected = [f for f in FIXTURES if args.fixture_id in (None, f.id)]
    if args.fixture_id and not selected:
        print(f"No fixture with id {args.fixture_id!r}", file=sys.stderr)
        return 1

    expy_processors: dict[str, object] = {}

    def get_expy_processor(namespace: str):
        if namespace not in expy_processors:
            from expy import EXIProcessor, Namespace as ExpyNamespace

            ns_map = {
                Namespace.DIN_MSG_DEF: ExpyNamespace.DIN,
                Namespace.ISO_V2_MSG_DEF: ExpyNamespace.ISO2,
                Namespace.ISO_V20_COMMON_MSG: ExpyNamespace.ISO20_COMMON,
                Namespace.ISO_V20_AC: ExpyNamespace.ISO20_AC,
                Namespace.ISO_V20_DC: ExpyNamespace.ISO20_DC,
                Namespace.ISO_V20_WPT: ExpyNamespace.ISO20_WPT,
                Namespace.ISO_V20_ACDP: ExpyNamespace.ISO20_ACDP,
            }
            expy_processors[namespace] = EXIProcessor(ns_map[namespace])
        return expy_processors[namespace]

    for fixture in selected:
        path = fixture.golden_path
        if path.exists() and not args.force:
            print(f"skip  {fixture.id}: {path} already exists (pass --force to overwrite)")
            continue
        message = fixture.build()
        if fixture.expy_authoritative:
            # Exificient produces malformed bytes for a small set of
            # fragment-shaped elements (e.g. ``eMAID``). For those the
            # translation module + EXPy is the authoritative source. ADR-0002
            # Slice 5 promotes all goldens to EXPy and documents divergences.
            proc = get_expy_processor(fixture.namespace)
            if fixture.root_kind == "fragment":
                everest = pydantic_to_everest_fragment(
                    message, fixture.namespace, root_name=fixture.root_name
                )
                encoded = proc.encode_fragment(everest)
            elif fixture.root_kind == "xmldsig":
                everest = pydantic_to_everest_xmldsig(
                    message, fixture.namespace, root_name=fixture.root_name
                )
                encoded = proc.encode_xmldsig(everest)
            else:
                from app.shared.everest_shape import pydantic_to_everest

                everest = pydantic_to_everest(message, fixture.namespace)
                encoded = proc.encode(everest)
        else:
            encoded = EXI().to_exi(message, fixture.namespace)
        path.write_bytes(encoded)
        print(f"wrote {fixture.id}: {len(encoded)} bytes -> {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
