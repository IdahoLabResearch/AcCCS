from app.secc.controller.evse import EVSE
import argparse, asyncio

parser = argparse.ArgumentParser(description="Emulator for SECC/EVSE")
parser.add_argument(
    "-M",
    "--mode",
    nargs=1,
    type=int,
    help="Mode for emulator to run in: 0 for full conversation, 1 for stalling the conversation, 2 for portscanning (default: 0)",
)
parser.add_argument("-I", "--interface", nargs=1, help="Ethernet interface to send/recieve packets on (default: eth1)")
parser.add_argument("--source-mac", nargs=1, help="Source MAC address of packets (default: 00:1e:c0:f2:6c:a0)")
parser.add_argument("--source-ip", nargs=1, help="Source IP address of packets (default: fe80::21e:c0ff:fef2:72f3)")
parser.add_argument("--source-port", nargs=1, type=int, help="Source port of packets (default: 25565)")
parser.add_argument("--NID", nargs=1, help="Network ID of the HomePlug GreenPHY AVLN (default: \\x9c\\xb0\\xb2\\xbb\\xf5\\x6c\\x0e)")
parser.add_argument(
    "--NMK",
    nargs=1,
    help="Network Membership Key of the HomePlug GreenPHY AVLN (default: \\x48\\xfe\\x56\\x02\\xdb\\xac\\xcd\\xe5\\x1e\\xda\\xdc\\x3e\\x08\\x1a\\x52\\xd1)",
)
parser.add_argument("--nmap-mac", nargs=1, help="The MAC address of the target device to NMAP scan (default: EVCC MAC address)")
parser.add_argument("--nmap-ip", nargs=1, help="The IP address of the target device to NMAP scan (default: EVCC IP address)")
parser.add_argument("--nmap-ports", nargs=1, help="List of ports to scan seperated by commas (ex. 1,2,5-10,19,...) (default: Top 8000 common ports)")
parser.add_argument("--modified-cordset", action="store_true", help="Set this option when using a modified cordset during testing of a target vehicle. The AcCCS system will provide a 150 ohm ground on the proximity line to reset the connection. (default: False)")
args = parser.parse_args()

evse = EVSE(args)
asyncio.run(evse.start())