#!/bin/bash
# Waits for two USB Ethernet adapters to be plugged in and renames their interfaces.
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root"
  exit 1
fi
declare -A seen_ifaces  # Track already-processed interfaces
adapters_found=0
configure_adapter() {
    local iface="$1"
    local name="$2"
    local link_file="$3"
    local mac
    mac=$(cat "/sys/class/net/$iface/address")
    echo "Detected USB Ethernet adapter: $iface"
    echo "MAC address: $mac"
    echo "Writing $link_file..."
    cat > "$link_file" <<EOF
[Match]
MACAddress=$mac
[Link]
Name=$name
EOF
    local network_file="/etc/systemd/network/${name}.network"
    echo "Writing $network_file..."
    cat > "$network_file" <<EOF
[Match]
Name=$name

[Network]
LinkLocalAddressing=ipv6
IPv6AcceptRA=no
EOF
    echo "Renaming $iface -> $name..."
    ip link set "$iface" down
    ip link set "$iface" name "$name"
    sysctl -w "net.ipv6.conf.$name.disable_ipv6=0"
    ip link set "$name" up
    echo "Done. Interface is live as '$name'."
}
echo "Enabling systemd-networkd..."
systemctl enable --now systemd-networkd
echo ""
echo "Waiting for USB Ethernet adapter for PEV interface... (plug it in now)"
while read -r line; do
    if echo "$line" | grep -q "^UDEV.*add.*net"; then
        iface=$(echo "$line" | grep -oP '(?<=/net/)\w+')
        [ -z "$iface" ] && continue
        [ -n "${seen_ifaces[$iface]}" ] && continue  # Skip if already processed
        [ ! -f "/sys/class/net/$iface/address" ] && continue
        [ ! -e "/sys/class/net/$iface/device" ] && continue
        realpath "/sys/class/net/$iface/device" | grep -q "/usb" || continue
        seen_ifaces[$iface]=1
        adapters_found=$(( adapters_found + 1 ))
        if [ "$adapters_found" -eq 1 ]; then
            configure_adapter "$iface" "acccs_evcc" "/etc/systemd/network/10-ethpev.link"
            echo ""
            echo "Waiting for USB Ethernet adapter for EVSE interface... (plug it in now)"
        elif [ "$adapters_found" -eq 2 ]; then
            configure_adapter "$iface" "acccs_secc" "/etc/systemd/network/10-ethevse.link"
            echo ""
            echo "All done."
            exit 0
        fi
    fi
done < <(udevadm monitor --udev --subsystem-match=net 2>/dev/null)
