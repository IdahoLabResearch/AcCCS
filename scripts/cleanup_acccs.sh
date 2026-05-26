#!/usr/bin/env bash
# Kill any AcCCS emulator processes still holding raw sockets.
#
# Background: run_secc.py / run_evcc.py are launched via sudo (raw sockets
# need CAP_NET_RAW), so the resulting python processes are root-owned. If
# the launching shell/agent dies abnormally — SIGKILL on a harness wrapper,
# for instance — the python child becomes orphaned and continues to hold
# the SDP port, blocking the next demo run with `[Errno 98] Address
# already in use`.
#
# This script is the escape hatch. Pair it with a sudoers NOPASSWD entry so
# devs and agent harnesses can invoke it without a password prompt.
#
# Usage:
#   sudo bash scripts/cleanup_acccs.sh
set -u

killed=0
for pattern in run_secc.py run_evcc.py; do
    # -f: match against the full command line; pkill returns 0 if it killed
    # anything, 1 if there was nothing matching. Either is fine for us.
    if pkill -TERM -f "$pattern"; then
        killed=$((killed + 1))
    fi
done

if [ "$killed" -eq 0 ]; then
    echo "No AcCCS emulator processes found."
else
    # Brief grace period for clean socket release, then force any survivors.
    sleep 1
    pkill -KILL -f run_secc.py 2>/dev/null || true
    pkill -KILL -f run_evcc.py 2>/dev/null || true
    echo "Cleaned up AcCCS emulator processes."
fi
