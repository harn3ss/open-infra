#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario: SECURITY DENY UNDER CHURN (the deny chain; see docs/chaos-oracle.md).
# The framework's THIRD oracle mode — `deny`, a NEGATIVE invariant verified continuously with ZERO
# tolerance. Where `recover` checks state after healing and `tolerate` allows a small SLO breach, a
# security fence may never leak, not once. The question is the one tenant isolation turns on: "when
# the forbidden target churns under a fault, does the fence ever fail open?"
#
# Chain (5 resource types): svc-allowed (Application, permitted) + svc-forbidden (Application,
# denied) + SecurityGroup svc-tier (marks the permitted destination) + SecurityGroup client-egress
# (fences the client to svc-tier only) + FaultInjection (churns svc-forbidden). An egress-locked
# prober (member of client-egress) samples BOTH targets continuously while svc-forbidden is killed
# and recreated. The oracle asserts: the prober NEVER reaches svc-forbidden (the negative invariant
# — any success = fail-open = RED), while it CAN reach svc-allowed (positive control — proves the
# fence isn't trivially blocking everything).
#
# The deny is EGRESS-based by necessity: kind: Application's default NetworkPolicy allows all
# same-namespace ingress and SG policies are additive, so isolation within one namespace lives on
# the client's egress. Proof-of-fire: svc-forbidden must actually be replaced.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"

SAMPLES="${DENY_SAMPLES:-45}"                 # sampling iterations across the window
INTERVAL="${DENY_INTERVAL:-0.2}"             # extra sleep between iterations
INJECT_AFTER="${DENY_INJECT_AFTER:-10}"      # seconds into the window before churning svc-forbidden
ALLOWED_URL="http://svc-allowed/"
FORBIDDEN_URL="http://svc-forbidden/"
EXIT_INCONCLUSIVE=42

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
trap sandbox_teardown_deny EXIT

sandbox_provision_deny

# PRE-FLIGHT — refuse the fault if it could reach anything outside the sandbox.
log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-svc-forbidden-kill.yaml"

fb_uids() { kubectl -n "$NS" get pods -l app.kubernetes.io/name=svc-forbidden -o jsonpath='{.items[*].metadata.uid}' 2>/dev/null; }
probe() { kubectl -n "$NS" exec deny-prober -- curl -sf -m "$1" -o /dev/null "$2" >/dev/null 2>&1; }

# Baseline: the fence must be LIVE before we test it under churn — svc-allowed reachable AND
# svc-forbidden refused. If svc-allowed is unreachable, connectivity/setup is broken (INCONCLUSIVE).
# If svc-forbidden is reachable at rest, the fence isn't enforcing at all — a real deny failure.
log "baseline: confirming the fence is live (allowed reachable, forbidden refused) before the fault"
allowed_ok=0
for _ in $(seq 1 10); do probe 2 "$ALLOWED_URL" && { allowed_ok=1; break; }; sleep 2; done
if [ "$allowed_ok" != 1 ]; then
  log "INCONCLUSIVE — svc-allowed not reachable from the locked prober (connectivity/setup broken). Not counting."
  kubectl -n "$NS" get pods,svc,netpol -o wide 2>/dev/null | grep -E 'svc-|client-egress|deny-prober' || true
  exit "$EXIT_INCONCLUSIVE"
fi
if probe 3 "$FORBIDDEN_URL"; then
  log "FAIL — svc-forbidden is reachable from the egress-locked client at rest: the fence is NOT enforcing (deny failure)."
  kubectl -n "$NS" get netpol sg-client-egress -o yaml 2>/dev/null | sed -n '1,40p' || true
  exit 1
fi
log "baseline OK — allowed reachable, forbidden refused. Fence is live."

# Delegate the VERDICT to the SINGULAR engine: the Go security-deny adapter (deny mode) samples the
# forbidden action continuously from the egress-locked prober and runDeny grades it with ZERO
# tolerance — the FIRST time the locked client reaches svc-forbidden is an immediate red. This
# scenario owns provisioning + the live baseline + firing the churn + the INCONCLUSIVE gate; the
# engine owns the verdict (replacing the old bash sampler/tally/breach-count PASS-FAIL fork). The
# adapter probes the SAME forbidden action this driver does (FORBIDDEN_URL from the egress-locked
# DENY_PROBER, short DENY_FORBIDDEN_TIMEOUT since a denied connect just hangs to the deadline).
REPO="$(cd "$HERE/.." && pwd)"
export CHAOS_SANDBOX_NS="$NS" DENY_PROBER="deny-prober" FORBIDDEN_URL="$FORBIDDEN_URL"
export DENY_FORBIDDEN_TIMEOUT="${DENY_FORBIDDEN_TIMEOUT:-1}"
export CONV_TIMEOUT="${DENY_WINDOW:-90}"
export PROBE_INTERVAL_MS="$(awk "BEGIN{printf \"%d\", ${INTERVAL}*1000}")"

log "sampling the fence via the singular deny engine (zero-tolerance; window ${CONV_TIMEOUT}s; churning svc-forbidden at ~${INJECT_AFTER}s)"
( cd "$REPO/apply-sink" && go test -tags convergence -run '^TestSecurityDeny$' -timeout 15m -count=1 ./... ) &
GOTEST=$!

sleep "$INJECT_AFTER"
BEFORE="$(fb_uids)"
log "injecting the svc-forbidden churn (pod-kill all)"
kubectl apply -f "$HERE/sandbox/fault-svc-forbidden-kill.yaml"

# Proof-of-fire: svc-forbidden must actually be replaced — else the churn didn't land → INCONCLUSIVE
# (the oracle won't grade a negative invariant against a fault that never fired).
replaced=0
for _ in $(seq 1 30); do
  a="$(fb_uids)"
  [ -n "$a" ] && [ "$a" != "$BEFORE" ] && { replaced=1; break; }
  sleep 2
done
if [ "$replaced" != 1 ]; then
  log "INCONCLUSIVE — svc-forbidden was not replaced; the churn didn't land. The oracle won't bless a fault that didn't fire."
  kubectl -n "$NS" get faultinjection,podchaos,pods -l app.kubernetes.io/name=svc-forbidden -o wide 2>/dev/null || true
  kill "$GOTEST" >/dev/null 2>&1 || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — svc-forbidden churned (recreated with a fresh identity); the adapter judges whether the fence held."

# The adapter samples the forbidden action through the churn; its exit code IS the verdict.
if wait "$GOTEST"; then
  log "PASS — the egress fence held with zero leaks while svc-forbidden churned (verdict: singular deny engine)."
  exit 0
fi
log "FAIL — the egress fence LEAKED: the locked client reached svc-forbidden during the churn (fail-open — release blocker)."
kubectl -n "$NS" get netpol sg-client-egress -o yaml 2>/dev/null | sed -n '1,40p' || true
exit 1
