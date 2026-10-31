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
if [ -f /etc/rancher/rke2/rke2.yaml ] || [ -f /etc/rancher/k3s/k3s.yaml ] || systemctl is-active --quiet kubelet 2>/dev/null; then
  inconclusive "this host looks like a cluster NODE (kubelet/k3s/rke2 present) — a node reaches its own LB IPs locally, so this cannot see the LAN failure. Re-run from a separate LAN host."
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
    28) fail "connection TIMED OUT (rc=28) — the classic asymmetric-routing symptom: the SYN reaches the node but the reply bypasses the router, which then drops the flow. Move the VIP pool off the node subnet, or return VIP traffic via the router. ${err}" ;;
    35|52|56) fail "connection was RESET / closed mid-TLS (rc=${rc}) — same asymmetric-routing / unannounced-VIP class seen from a LAN client. ${err}" ;;
    *)  fail "curl could not reach ${INGRESS_URL} (rc=${rc}): ${err}" ;;
  esac
fi

# The ingress answered — the LAN path works. Optionally require a specific status.
if [ -n "${EXPECT_STATUS:-}" ] && [ "$code" != "$EXPECT_STATUS" ]; then
  fail "reachable, but HTTP status ${code} != expected ${EXPECT_STATUS} (the LAN path is fine; this is an app/ingress-config concern)"
fi

printf '✓ PASS: %s is reachable from this LAN host (HTTP %s) — the routed/announced ingress path works end to end.\n' "$INGRESS_URL" "$code"
