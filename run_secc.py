"""
    Copyright 2025, Ford Motor Company

    Script that runs the SECC/EVSE emulator.

    Per ADR-0001 the SECC is driven by a single personality YAML file plus an
    optional runtime.yaml. Personality fields (including NID / NMK / EVSEID
    / protocols) are not CLI-overridable; only runtime knobs have flags.
"""

import argparse
import asyncio

from app.secc.controller.evse import EVSE
from app.shared.exi_capture import enable_capture
from app.shared.personality import add_runtime_cli_args
from app.shared.process_lifecycle import die_with_parent


die_with_parent()

parser = argparse.ArgumentParser(description="Emulator for SECC/EVSE")
add_runtime_cli_args(parser)
args = parser.parse_args()

if args.capture:
    enable_capture(args.capture)

evse = EVSE(args)
asyncio.run(evse.start())
evse.openProximity()
del evse
