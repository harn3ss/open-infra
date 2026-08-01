#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario 1c: LATENCY degrade (magnitude axis; see
# docs/chaos-oracle.md). Instead of CUTTING the a→b link, DELAY it: 800ms each way on the
# sink↔B apply path, held active for the whole run. The mesh is slowed, never severed.
#
# The oracle expectation is the OPPOSITE of the partition's: under a mere degrade the mesh
# MUST keep converging. Sustained divergence here is a BUG (release blocker), not a tolerated
# cut. So — unlike scenario-partition.sh — there is NO MIN_ELAPSED floor: converging FAST
# under latency is the desired outcome, not a false green. What proves the fault bit is the
# proof-of-fire probe reading `slow` (a ~1.6s handshake), not a diverge-then-converge delay.
#
# Safety is layered exactly as the other scenarios: sandbox-scoped RBAC, ResourceQuota, low
# PriorityClass, the fault's own `duration`, AND the pre-flight guard below.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
# The convergence apply path is slowed by the injected latency, so give it a generous budget.
export CONV_TIMEOUT="${CONV_TIMEOUT:-300}"
export CONV_SETTLE="${CONV_SETTLE:-15}"
export CONV_CREATE="${CONV_CREATE:-false}"
export CONV_KEYS="${CONV_KEYS:-200}"
export CONV_CONFLICTS="${CONV_CONFLICTS:-20}"
# Hold the latency active for the ENTIRE harness so convergence is proven UNDER sustained
# delay, not after it lifts. Override the fault manifest's 90s duration with a long window.
LAT_HOLD="${LAT_HOLD:-360s}"
EXIT_INCONCLUSIVE=42

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"

# Heal the latency on the way out (belt-and-braces beside the fault's own duration), then the
# usual sandbox teardown.
cleanup() {
  kubectl -n "$NS" delete faultinjection mm-latency --ignore-not-found >/dev/null 2>&1 || true
  sandbox_teardown
}
trap cleanup EXIT

sandbox_provision
sandbox_conv_members

log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-latency.yaml"

# Proof-of-fire (oracle pillar 1), part 1: the a→b link must be HEALTHY and FAST before we
# degrade it — otherwise the mesh isn't ready and nothing observed here can be trusted.
log "proof-of-fire: confirming the a→b link is up (fast) BEFORE the degrade"
if ! "$HERE/probe-partition.sh" up; then
  log "INCONCLUSIVE — a→b link not up/fast pre-fault (mesh not ready / probe path broken). Not counting."
  exit "$EXIT_INCONCLUSIVE"
fi

log "injecting ${LAT_HOLD} of 800ms latency on the a→b apply path (time-boxed + pod-scoped)"
sed "s/duration: 90s/duration: ${LAT_HOLD}/" "$HERE/sandbox/fault-latency.yaml" | kubectl apply -f -

# Proof-of-fire (oracle pillar 1), part 2 — the 07-23 gap: actively confirm the latency BIT.
# The delay takes a moment to land; sample briefly. If the handshake never crosses the `slow`
# threshold the delay never applied (e.g. the webhook rejected it) → INCONCLUSIVE, not green.
log "proof-of-fire: confirming the latency actually slowed the a→b link"
fired=0
for _ in $(seq 1 8); do
  if "$HERE/probe-partition.sh" slow; then fired=1; break; fi
  sleep 3
done
if [ "$fired" != 1 ]; then
  log "INCONCLUSIVE — a→b handshake never registered as slow during the fault; the latency did not bite."
  log "            The oracle refuses to bless a fault that didn't fire. Not counting this night."
  kubectl -n "$NS" get faultinjection,networkchaos -o wide || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — the degrade is confirmed live (a→b handshake is slow)."

# The core assertion: WITH latency sustained, the mesh must STILL converge byte-identical.
log "running the convergence harness UNDER sustained latency (must converge — degrade is not a cut)"
if ! ( cd "$REPO/apply-sink" && go test -tags convergence -run TestConvergence -timeout 20m -v ./... ); then
  log "FAIL — mesh did NOT converge under mere latency (release blocker). A degrade must never"
  log "       cause sustained divergence. Retaining state."
  kubectl -n "$NS" get faultinjection,networkchaos,pods -o wide || true
  exit 1
fi

log "PASS — mesh converged byte-identical UNDER sustained 800ms latency (degrade tolerated; fault confirmed live)."
exit 0
