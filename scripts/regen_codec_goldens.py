#!/usr/bin/env python3
"""Regenerate codec-layer golden bytes from the EXPy EXI codec.

Per ADR-0002 Slice 5, the codec corpus is rebaselined against EXPy. The
:class:`~app.shared.exi_codec.EXI` wrapper now talks directly to EXPy via
:class:`~app.shared.expy_exi_codec.EXPyEXICodec`, so producing the golden
bytes is just re-encoding every fixture through that wrapper.

Usage::

    python scripts/regen_codec_goldens.py                # all fixtures
    python scripts/regen_codec_goldens.py <fixture-id>   # one fixture

Refuses to overwrite an existing golden unless ``--force`` is passed. That
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

    from app.shared.exi_codec import EXI
    from app.shared.expy_exi_codec import EXPyEXICodec
    from app.shared.settings import load_shared_settings
    from tests.conformance.codec.fixtures import FIXTURES, GOLDENS_DIR

    load_shared_settings()
    EXI().set_exi_codec(EXPyEXICodec())
    GOLDENS_DIR.mkdir(parents=True, exist_ok=True)

    selected = [f for f in FIXTURES if args.fixture_id in (None, f.id)]
    if args.fixture_id and not selected:
        print(f"No fixture with id {args.fixture_id!r}", file=sys.stderr)
        return 1

    for fixture in selected:
        path = fixture.golden_path
        if path.exists() and not args.force:
            print(f"skip  {fixture.id}: {path} already exists (pass --force to overwrite)")
            continue
        message = fixture.build()
        if fixture.root_kind == "fragment":
            encoded = EXI().to_exi_fragment(
                message, fixture.namespace, root_name=fixture.root_name
            )
        elif fixture.root_kind == "xmldsig":
            encoded = EXI().to_exi_xmldsig(
                message, fixture.namespace, root_name=fixture.root_name
            )
        else:
            encoded = EXI().to_exi_document(message, fixture.namespace)
        path.write_bytes(encoded)
        print(f"wrote {fixture.id}: {len(encoded)} bytes -> {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
