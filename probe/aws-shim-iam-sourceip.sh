#!/usr/bin/env bash
# Live probe: aws:SourceIp is the address a request came from, which the caller cannot choose (as on AWS).
#
# A pod inside the cluster calls the AWS front door directly, signing with SigV4, as two IAM users whose
# only permission is sqs:ListQueues under an aws:SourceIp condition:
#   - HERE  : allowed from the pod's own address  → allowed (the condition is evaluated, on the real peer);
#   - THERE : allowed from 203.0.113.50 only      → refused, even when the pod sends
#             "X-Forwarded-For: 203.0.113.50" — a forwarding header is believed only from the nodes, where
#             the platform's ingress runs, so a caller inside the cluster can't claim another address.
# Before the fix, the shim took the first X-Forwarded-For entry from anyone, and THERE was let in.
#
# Exit 0 pass, 1 fail, 42 inconclusive. Needs kubectl (KUBECONFIG) and go (the console password hash
# iam-lib makes for each user); the pod pulls curlimages/curl.
set -uo pipefail
HERE_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=probe/iam-lib.sh
source "$HERE_DIR/iam-lib.sh"

PROBE_NS="${PROBE_NS:-open-infra-cfn}"
POD="sourceip-probe-$SFX"
INCLUSTER="${INCLUSTER_SHIM:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
FORGED="203.0.113.50"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.11.1}"

cleanup() {
  kubectl -n "$PROBE_NS" delete pod "$POD" --ignore-not-found --wait=false >/dev/null 2>&1
  iamp_cleanup
}
trap cleanup EXIT

command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v go >/dev/null || inconclusive "go is required (iam-lib hashes the users' console passwords)"

# --- 1. a pod inside the cluster -----------------------------------------------------------------------
log "starting $POD ($CURL_IMAGE) in $PROBE_NS"
kubectl -n "$PROBE_NS" run "$POD" --image="$CURL_IMAGE" --restart=Never --command -- sleep 900 >/dev/null \
  || inconclusive "could not start the probe pod"
kubectl -n "$PROBE_NS" wait --for=condition=Ready "pod/$POD" --timeout=180s >/dev/null 2>&1 || inconclusive "the probe pod did not become ready"
POD_IP="$(kubectl -n "$PROBE_NS" get pod "$POD" -o jsonpath='{.status.podIP}')"
[ -n "$POD_IP" ] || inconclusive "the probe pod has no address"
log "  pod address $POD_IP"

# --- 2. two users, the same permission under different addresses ---------------------------------------
doc() { printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:ListQueues","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"%s"}}}]}' "$1"; }
log "seeding a user allowed from $POD_IP/32 and one allowed from $FORGED/32"
iamp_user "sip-probe-here-$SFX" "" "$(doc "$POD_IP/32")"; HERE_AK="$U_AK"; HERE_SK="$U_SK"
iamp_user "sip-probe-there-$SFX" "" "$(doc "$FORGED/32")"; THERE_AK="$U_AK"; THERE_SK="$U_SK"
iamp_settle

# list_queues <ak> <sk> [forged address]: the HTTP status of sqs ListQueues sent from the pod, signed; the
# credentials go over stdin, never on a command line.
list_queues() {
  local xff=""
  [ -n "${3:-}" ] && xff="$3"
  printf '%s %s\n' "$1" "$2" | kubectl -n "$PROBE_NS" exec -i "$POD" -- sh -c '
    read -r AK SK
    set -- -s -o /tmp/out -w "%{http_code}" --aws-sigv4 "aws:amz:us-east-1:sqs" --user "$AK:$SK" \
      -H "Content-Type: application/x-amz-json-1.0" -H "X-Amz-Target: AmazonSQS.ListQueues" -d "{}"
    [ -n "'"$xff"'" ] && set -- "$@" -H "X-Forwarded-For: '"$xff"'"
    curl "$@" "'"$INCLUSTER"'/"' 2>/dev/null
}
body() { kubectl -n "$PROBE_NS" exec "$POD" -- cat /tmp/out 2>/dev/null | head -c 300; }

# --- 3. the decisions ----------------------------------------------------------------------------------
code="$(list_queues "$HERE_AK" "$HERE_SK")"
[ "$code" = 200 ] || { [ "$code" = 000 ] && inconclusive "the pod could not reach the shim at $INCLUSTER"; \
  fail "the user allowed from the pod's own address was refused ($code): $(body)"; }
log "  ✓ allowed from its real address ($POD_IP)"

code="$(list_queues "$HERE_AK" "$HERE_SK" "$FORGED")"
[ "$code" = 200 ] || fail "a forwarding header changed the decision for the pod's own address ($code): $(body)"
log "  ✓ still decided on the real address when the pod claims another"

code="$(list_queues "$THERE_AK" "$THERE_SK" "$FORGED")"
if [ "$code" = 200 ]; then
  fail "FORGED: a pod claiming X-Forwarded-For: $FORGED was let in under aws:SourceIp $FORGED/32"
fi
body | grep -q "AccessDenied" || fail "the refusal is not AWS's AccessDenied ($code): $(body)"
log "  ✓ refused AccessDenied: X-Forwarded-For: $FORGED from inside the cluster is not $FORGED"

log "PASS: aws:SourceIp is the real peer for a caller inside the cluster; a forwarding header can't claim another address"
