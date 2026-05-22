"""
    Copyright 2025, Ford Motor Company

    Script that runs the EVCC emulator.

    Per ADR-0001 the EVCC is driven by a single personality YAML file plus an
    optional runtime.yaml. Personality fields are not CLI-overridable; only
    runtime knobs (logging, NMAP, virtual mode, source port) have flags.
"""

import argparse
import asyncio

from app.evcc.controller.pev import PEV
from app.shared.EmulatorEnum import PEVState
from app.shared.personality import add_runtime_cli_args


parser = argparse.ArgumentParser(description="Emulator for EVCC/PEV")
add_runtime_cli_args(parser)
args = parser.parse_args()

pev = PEV(args)
asyncio.run(pev.start())
pev.setState(PEVState.A)
del pev
