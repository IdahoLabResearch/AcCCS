"""
    Copyright 2025, Ford Motor Company

    Script that runs the EVCC emulator
"""

import argparse, asyncio

from app.evcc.controller.pev import PEV
from app.shared.EmulatorEnum import PEVState

parser = argparse.ArgumentParser(description="Emulator for EVCC/PEV")

parser.add_argument("--source-port", nargs=1, type=int, help="Source port of packets (default: random port between 49152 and 65534)")

parser.add_argument("--protocols", help="Comma separated, ordered list of protocols to use (default: ISO_15118_2, DIN_SPEC_70121)")
parser.add_argument("--authmodes", help="Comma separated, ordered list of authentication modes to use (default: PNC, EIM)")
parser.add_argument("--energymode", help="Energy transfer mode to use (default: DC)")
parser.add_argument("--useTLS", help="Use TLS for communication (default: True)")

parser.add_argument("--slacSoundTimeout", type=int, help="Timeout in milliseconds to wait for SLAC sound before restarting SLAC process (default: 1000)")

args = parser.parse_args()

pev = PEV(args)
asyncio.run(pev.start())
pev.setState(PEVState.A)
del pev