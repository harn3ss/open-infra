#!/usr/bin/env bash
# A LAN client that is not a cluster node, for the probes that need one (aws-shim-elbv2-nlb.sh): a network
# namespace on this host with a macvlan on the LAN interface and its own DHCP lease. Its traffic leaves through
# the switch, so the host's own Service rules never see it, and it reaches the cluster's addresses as any
# workstation on the LAN does.
#
#   sudo probe/lan-client-netns.sh up <name> [<n>]   # n (1-254) picks a fixed, locally administered MAC,
#                                                     # so a rerun reuses its lease (default 1)
#   sudo probe/lan-client-netns.sh down <name>
#   sudo ip netns exec <name> <command>               # run as that client
#
# Needs root, iproute2 and busybox (udhcpc). The LAN interface is the one the default route uses (LAN_IFACE to
# choose another).
set -euo pipefail
cmd="${1:-}"; name="${2:-}"
[ -n "$cmd" ] && [ -n "$name" ] || { echo "usage: $0 up|down <name> [<n>]" >&2; exit 2; }
case "$cmd" in
  down)
    ip netns del "$name" 2>/dev/null || true
    echo "removed $name"
    ;;
  up)
    n="${3:-1}"
    [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le 254 ] || { echo "n must be 1-254" >&2; exit 2; }
    iface="${LAN_IFACE:-$(ip -4 route show default | awk '{for (i=1;i<NF;i++) if ($i=="dev") {print $(i+1); exit}}')}"
    [ -n "$iface" ] || { echo "no LAN interface (set LAN_IFACE)" >&2; exit 1; }
    command -v busybox >/dev/null || { echo "busybox (udhcpc) is required" >&2; exit 1; }
    script="$(mktemp)"
    trap 'rm -f "$script"' EXIT
    cat > "$script" <<'EOF'
#!/bin/sh
case "$1" in
  deconfig) ip addr flush dev "$interface" ;;
  bound|renew)
    ip addr flush dev "$interface"
    ip addr add "$ip/${mask:-24}" dev "$interface"
    for r in $router; do ip route replace default via "$r" dev "$interface"; break; done ;;
esac
exit 0
EOF
    chmod 700 "$script"
    ip netns add "$name" 2>/dev/null || true
    if ! ip netns exec "$name" ip link show mv0 >/dev/null 2>&1; then
      tmpif="mv$(printf '%s' "$name" | sha256sum | cut -c1-10)" # a host-side name within 15 characters
      ip link add "$tmpif" link "$iface" address "$(printf '02:6f:69:6c:63:%02x' "$n")" type macvlan mode bridge
      ip link set "$tmpif" netns "$name"
      ip netns exec "$name" ip link set "$tmpif" name mv0
    fi
    ip netns exec "$name" ip link set lo up
    ip netns exec "$name" ip link set mv0 up
    ip netns exec "$name" busybox udhcpc -i mv0 -n -q -f -t 5 -s "$script" >/dev/null 2>&1 \
      || { echo "no DHCP lease on $iface for $name" >&2; exit 1; }
    ip netns exec "$name" ip -4 -o addr show mv0 | awk '{print $4}'
    ;;
  *) echo "usage: $0 up|down <name> [<n>]" >&2; exit 2 ;;
esac
