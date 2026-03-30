#!/bin/bash

set -e

IFACE_A="acccs_secc"
IFACE_B="acccs_evcc"

REMOVED=0

for IFACE in "$IFACE_A" "$IFACE_B"; do
    if ip link show "$IFACE" &>/dev/null; then
        echo "Removing interface $IFACE..."
        sudo ip link delete "$IFACE"
        REMOVED=1
    fi
done

if [ "$REMOVED" -eq 0 ]; then
    echo "No interfaces found to remove."
else
    echo "Done! Teardown complete."
fi
