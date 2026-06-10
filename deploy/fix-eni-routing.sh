#!/bin/bash
# Move the secondary ENI's (private subnet) default route into its own
# routing table so it doesn't conflict with the primary ENI's default
# route (used for SSM/dnf/pip/git egress via the public subnet).
#
# AL2023's bundled cloud-init (22.2.2) does not configure per-NIC policy
# routing for secondary ENIs - it adds a second `default` route to the main
# table, which causes the kernel to nondeterministically pick a default
# route and breaks SSM connectivity. This script runs after networking is
# up on every boot and fixes that up for the secondary interface.

set -u

IFACE=ens6
TABLE=100

# Secondary ENI may not be attached - exit quietly if so.
for i in $(seq 1 15); do
  ip link show "$IFACE" &>/dev/null && break
  sleep 2
done
ip link show "$IFACE" &>/dev/null || exit 0

IP=$(ip -4 -o addr show dev "$IFACE" | awk '{print $4}' | cut -d/ -f1)
GW=$(ip route show dev "$IFACE" | awk '/^default/ {print $3; exit}')

[ -z "$IP" ] && exit 0
[ -z "$GW" ] && exit 0

# Remove the conflicting default route from the main table (if present).
ip route del default via "$GW" dev "$IFACE" 2>/dev/null || true

# Default route for return traffic to clients on this subnet, in its own table.
ip route replace default via "$GW" dev "$IFACE" table $TABLE

# Anything sourced from this ENI's IP uses that table.
ip rule add from "$IP" lookup $TABLE 2>/dev/null || true
