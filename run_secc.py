import argparse, asyncio

from app.secc.controller.evse import EVSE

parser = argparse.ArgumentParser(description="Emulator for SECC/EVSE")
parser.add_argument("--source-port", nargs=1, type=int, help="Source port of packets (default: 25565)")
parser.add_argument("--NID", nargs=1, help="Network ID of the HomePlug GreenPHY AVLN (default: \\x9c\\xb0\\xb2\\xbb\\xf5\\x6c\\x0e)")
parser.add_argument(
    "--NMK",
    nargs=1,
    help="Network Membership Key of the HomePlug GreenPHY AVLN (default: \\x48\\xfe\\x56\\x02\\xdb\\xac\\xcd\\xe5\\x1e\\xda\\xdc\\x3e\\x08\\x1a\\x52\\xd1)",
)
parser.add_argument("--modified-cordset", action="store_true", help="Set this option when using a modified cordset during testing of a target vehicle. The AcCCS system will provide a 150 ohm ground on the proximity line to reset the connection. (default: False)")
args = parser.parse_args()

evse = EVSE(args)
asyncio.run(evse.start())
evse.openProximity()
del evse