#!/bin/bash

set -e

IFACE_A="acccs_secc"
IFACE_B="acccs_evcc"
ADDR_A="fe80::1"
ADDR_B="fe80::2"

# Teardown existing interfaces if they exist
for IFACE in "$IFACE_A" "$IFACE_B"; do
    if ip link show "$IFACE" &>/dev/null; then
        echo "Existing interface $IFACE found, removing..."
        sudo ip link delete "$IFACE"
    fi
done

echo "Creating veth pair: $IFACE_A <-> $IFACE_B"
sudo ip link add "$IFACE_A" type veth peer name "$IFACE_B"

echo "Bringing interfaces up..."
sudo ip link set "$IFACE_A" up
sudo ip link set "$IFACE_B" up

echo "Assigning link-local addresses..."
sudo ip addr add "${ADDR_A}/64" dev "$IFACE_A"
sudo ip addr add "${ADDR_B}/64" dev "$IFACE_B"

echo "Done. Interface summary:"
ip addr show "$IFACE_A"
ip addr show "$IFACE_B"
