#!/usr/bin/env bash
# LAN-client reachability of a routed/announced ingress endpoint — the probe that catches an ingress VIP
# that is announced and healthy on the cluster yet UNREACHABLE from a real LAN client (asymmetric
# routing, an unannounced MetalLB address, a single-replica externalTrafficPolicy: Local VIP on the
# wrong node, …).
#
# WHY THIS MUST RUN FROM A NON-NODE LAN HOST (the whole point): a request from a cluster NODE to a
# LoadBalancer / VIP succeeds even when the LAN path is broken, because the node serves its own LB IPs
# locally. So an in-cluster probe (or one run on a node) is blind to this failure class — it only shows
# up from a separate host on the LAN. Run this from the workstation an end user would actually use.
#
# Generic + env-driven — NO site addresses baked in:
#   INGRESS_URL   (required)  the external URL/VIP a LAN client should reach, e.g. https://app.example
#   EXPECT_STATUS (optional)  an HTTP status to require (e.g. 200); default: ANY HTTP response = reachable
#                             (the ingress answering at all proves the L3/L4 path; the app's own status
#                             is a separate concern)
#   TIMEOUT       (optional)  per-attempt seconds (default 8)
#   FORCE_LAN_CLIENT=1 (optional) skip the node guard (see below)
#
# Windows clients: probe/lan-ingress-reachability.ps1 is the same check in PowerShell.
#
# Exit 0 = reachable (PASS), 1 = a real reachability FAILURE (reset/timeout/refused — the bug this
# exists for), 42 = INCONCLUSIVE (not enough to judge: no URL, or run from a node).
#
#   INGRESS_URL=https://app.example ./probe/lan-ingress-reachability.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
TIMEOUT="${TIMEOUT:-8}"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v curl >/dev/null || inconclusive "curl is required"
[ -n "${INGRESS_URL:-}" ] || inconclusive "set INGRESS_URL to the external endpoint a LAN client should reach (see header)"

# Guard against the blind spot: if this looks like a cluster node, a local success proves nothing.
# What matters is the NETWORK NAMESPACE the request leaves from: a node's own netns has the cluster's
# service rules (it reaches its LB IPs locally), while a separate netns on the same machine (e.g. a
# macvlan test client with its own LAN address) is a genuine LAN client. So:
#   - a CNI interface in THIS netns (ovn0, cni0, flannel.1, cilium_host, …) => node, always;
#   - in the HOST netns, k3s / k3s-agent / rke2 / kubelet (service, config or data dir) => node.
# FORCE_LAN_CLIENT=1 skips the guard when you know the request leaves from a non-node network path.
looks_like_node() {
  if command -v ip >/dev/null 2>&1 && ip -o link show 2>/dev/null | grep -qE ': (ovn0|cni0|flannel\.1|cilium_host|vxlan\.calico|tunl0|kube-ipvs0|weave)[:@]'; then
    echo "a cluster CNI interface is present in this network namespace"; return 0
  fi
  local self host
  self="$(readlink /proc/self/ns/net 2>/dev/null)"; host="$(readlink /proc/1/ns/net 2>/dev/null)"
  if [ -n "$host" ] && [ "$self" != "$host" ]; then return 1; fi   # separate netns, no CNI iface: a LAN client
  local u
  for u in k3s k3s-agent rke2-server rke2-agent kubelet; do
    systemctl is-active --quiet "$u" 2>/dev/null && { echo "the $u service is running"; return 0; }
  done
  for f in /etc/rancher/k3s/k3s.yaml /etc/rancher/rke2/rke2.yaml /var/lib/rancher/k3s/agent /var/lib/rancher/rke2/agent /var/lib/kubelet; do
    [ -e "$f" ] && { echo "$f exists"; return 0; }
  done
  return 1
}
if [ "${FORCE_LAN_CLIENT:-0}" != 1 ] && why="$(looks_like_node)"; then
  inconclusive "this host looks like a cluster NODE (${why}) — a node reaches its own LB IPs locally, so this cannot see the LAN failure. Re-run from a separate LAN host (or set FORCE_LAN_CLIENT=1 if the request leaves from a separate network namespace)."
fi

log "probing ${INGRESS_URL} as a LAN client (timeout ${TIMEOUT}s, TLS verification off — self-signed lab issuers are a separate finding)"
# -k: a lab self-signed cert is a different concern; we are testing L3/L4 reachability, not trust.
# -o /dev/null -w: capture the HTTP status if the ingress answered at all.
code="$(curl -ksS -m "$TIMEOUT" -o /dev/null -w '%{http_code}' "$INGRESS_URL" 2>"/tmp/lan-ingress.$$.err")"
rc=$?
err="$(cat "/tmp/lan-ingress.$$.err" 2>/dev/null)"; rm -f "/tmp/lan-ingress.$$.err"

if [ "$rc" -ne 0 ]; then
  case "$rc" in
    7)  fail "connection REFUSED (rc=7) — nothing is listening at the VIP from the LAN. Likely an unannounced MetalLB address or a VIP on a down/unendpointed node. ${err}" ;;
    28) fail "connection TIMED OUT (rc=28) — the classic asymmetric-routing symptom: the SYN reaches the node but the reply bypasses the router, which then drops the flow. Replies must return through the router: platform/networking/vip-return.yaml does this for routed (BGP) VIPs. ${err}" ;;
    35|52|56) fail "connection was RESET / closed mid-TLS (rc=${rc}) — same asymmetric-routing / unannounced-VIP class seen from a LAN client. ${err}" ;;
    *)  fail "curl could not reach ${INGRESS_URL} (rc=${rc}): ${err}" ;;
  esac
fi

# The ingress answered — the LAN path works. Optionally require a specific status.
if [ -n "${EXPECT_STATUS:-}" ] && [ "$code" != "$EXPECT_STATUS" ]; then
  fail "reachable, but HTTP status ${code} != expected ${EXPECT_STATUS} (the LAN path is fine; this is an app/ingress-config concern)"
fi

printf '✓ PASS: %s is reachable from this LAN host (HTTP %s) — the routed/announced ingress path works end to end.\n' "$INGRESS_URL" "$code"
