"""
    Copyright 2025, Ford Motor Company

    Script that runs the EVCC emulator.

    Per ADR-0001 the EVCC is driven by a single personality YAML file plus an
    optional runtime.yaml. Personality fields are not CLI-overridable; only
    runtime knobs (logging, NMAP, virtual mode, source port) have flags.
"""

import argparse
import asyncio
import sys

from app.evcc.controller.pev import PEV
from app.shared.EmulatorEnum import PEVState
from app.shared.exi_capture import enable_capture
from app.shared.personality import (
    add_runtime_cli_args,
    format_personality_listing,
    list_available_personalities,
)
from app.shared.process_lifecycle import die_with_parent


die_with_parent()

parser = argparse.ArgumentParser(description="Emulator for EVCC/PEV")
add_runtime_cli_args(parser, default_config="din_dc_extended-evcc")
args = parser.parse_args()

if args.list_configs:
    print(format_personality_listing(list_available_personalities()))
    sys.exit(0)

if args.capture:
    enable_capture(args.capture)

pev = PEV(args)
asyncio.run(pev.start())
pev.setState(PEVState.A)
del pev
