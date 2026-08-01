#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario 1e: packet-LOSS degrade (magnitude axis; see
# docs/chaos-oracle.md). Drop 15% of the sink↔B packets, held for the whole run. Like the
# latency variant this is a *degrade*, not a cut: TCP retransmits carry every write, so the
# mesh MUST keep converging. Sustained divergence under mere loss is a BUG (release blocker),
# and there is NO MIN_ELAPSED floor — converging (even if slower) is the desired outcome.
#
# Proof-of-fire is STATISTICAL (probe-loss.sh): a single handshake can't witness probabilistic
# loss, so we sample many and assert a non-trivial-but-not-total impaired fraction.
#
# Safety is layered exactly as the other scenarios: sandbox-scoped RBAC, ResourceQuota, low
# PriorityClass, the fault's own `duration`, AND the pre-flight guard below.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
# Retransmits under 40% loss slow the apply path, so give convergence a generous budget.
export CONV_TIMEOUT="${CONV_TIMEOUT:-360}"
export CONV_SETTLE="${CONV_SETTLE:-15}"
export CONV_CREATE="${CONV_CREATE:-false}"
export CONV_KEYS="${CONV_KEYS:-200}"
export CONV_CONFLICTS="${CONV_CONFLICTS:-20}"
# Hold the loss active for the ENTIRE harness so convergence is proven UNDER sustained loss.
LOSS_HOLD="${LOSS_HOLD:-420s}"
EXIT_INCONCLUSIVE=42

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"

cleanup() {
  kubectl -n "$NS" delete faultinjection mm-loss --ignore-not-found >/dev/null 2>&1 || true
  sandbox_teardown
}
trap cleanup EXIT

sandbox_provision
sandbox_conv_members

log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-loss.yaml"

# Proof-of-fire part 1: the link must be CLEAN (near-zero impaired) before we degrade it.
log "proof-of-fire: confirming the a→b link is clean (near-zero loss) BEFORE the degrade"
if ! "$HERE/probe-loss.sh" clean; then
  log "INCONCLUSIVE — a→b link not clean pre-fault (mesh not ready / probe path broken). Not counting."
  exit "$EXIT_INCONCLUSIVE"
fi

log "injecting ${LOSS_HOLD} of 15% packet loss on the a→b apply path (time-boxed + pod-scoped)"
sed "s/duration: 90s/duration: ${LOSS_HOLD}/" "$HERE/sandbox/fault-loss.yaml" | kubectl apply -f -

# Proof-of-fire part 2 — the 07-23 gap: statistically confirm the loss BIT. Sample repeatedly;
# tc/netem takes a moment to land. If the impaired fraction never rises the loss never applied
# → INCONCLUSIVE, not green.
log "proof-of-fire: statistically confirming the loss actually degraded the a→b link"
fired=0
for _ in $(seq 1 8); do
  if "$HERE/probe-loss.sh" lossy; then fired=1; break; fi
  sleep 3
done
if [ "$fired" != 1 ]; then
  log "INCONCLUSIVE — a→b handshakes never showed a loss signature during the fault; loss did not bite."
  log "            The oracle refuses to bless a fault that didn't fire. Not counting this night."
  kubectl -n "$NS" get faultinjection,networkchaos -o wide || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — the degrade is confirmed live (a→b link is lossy)."

# Core assertion: WITH 40% loss sustained, the mesh must STILL converge byte-identical.
log "running the convergence harness UNDER sustained loss (must converge — degrade is not a cut)"
if ! ( cd "$REPO/apply-sink" && go test -tags convergence -run TestConvergence -timeout 20m -v ./... ); then
  log "FAIL — mesh did NOT converge under mere packet loss (release blocker). A degrade must"
  log "       never cause sustained divergence. Retaining state."
  kubectl -n "$NS" get faultinjection,networkchaos,pods -o wide || true
  exit 1
fi

log "PASS — mesh converged byte-identical UNDER sustained 15% packet loss (degrade tolerated; fault confirmed live)."
exit 0
