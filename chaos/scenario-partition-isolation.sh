#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario 1d: TOTAL ISOLATION (magnitude axis; see docs/chaos-oracle.md).
#
# Harsher than the default partition: instead of cutting only the a→b apply link (one-sided
# divergence, A stays whole), this severs site B from its ENTIRE replication mesh — both the
# inbound a-b-sink→B and the outbound b-dbz→B links — so BOTH members diverge during the cut
# and both must reconverge after heal. See sandbox/fault-isolation.yaml for how one peer
# selector (the shared openinfra.dev/replication label) achieves that.
#
# Oracle: like the partition, mid-fault divergence is EXPECTED (this is a cut, not a degrade),
# only here it's two-sided. Red = release blocker. The proof-of-fire probe and MIN_ELAPSED
# floor are identical to the partition — the a-b-sink↔B link (which the probe witnesses) is
# one of the two cut, so the proven up/down probe applies unchanged.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
export CONV_TIMEOUT="${CONV_TIMEOUT:-300}"
export CONV_SETTLE="${CONV_SETTLE:-15}"
export CONV_CREATE="${CONV_CREATE:-false}"
export CONV_KEYS="${CONV_KEYS:-200}"
export CONV_CONFLICTS="${CONV_CONFLICTS:-20}"
EXIT_INCONCLUSIVE=42

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
trap sandbox_teardown EXIT

sandbox_provision
sandbox_conv_members

log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-isolation.yaml"

# Proof-of-fire (oracle pillar 1), part 1: the a→b link must be HEALTHY before the cut.
log "proof-of-fire: confirming the a→b link is up BEFORE the isolation"
if ! "$HERE/probe-partition.sh" up; then
  log "INCONCLUSIVE — a→b link not up pre-fault (mesh not ready / probe path broken). Not counting."
  exit "$EXIT_INCONCLUSIVE"
fi

log "injecting TOTAL isolation of site B (90s, time-boxed + pod-scoped)"
kubectl apply -f "$HERE/sandbox/fault-isolation.yaml"

# Proof-of-fire (oracle pillar 1), part 2: confirm the cut BIT. The a-b-sink↔B link (which the
# probe witnesses) is one of the two links severed, so `down` proves the isolation landed.
log "proof-of-fire: confirming the isolation actually cut the a→b link"
fired=0
for _ in $(seq 1 6); do
  if "$HERE/probe-partition.sh" down; then fired=1; break; fi
  sleep 3
done
if [ "$fired" != 1 ]; then
  log "INCONCLUSIVE — a→b link still reachable during the fault window; the isolation did not bite."
  log "            The oracle refuses to bless a fault that didn't fire. Not counting this night."
  kubectl -n "$NS" get faultinjection,networkchaos -o wide || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — the isolation is confirmed live (a→b link cut)."

log "running the convergence harness through the isolation (both members diverge, must reconverge)"
START=$(date +%s)
if ! ( cd "$REPO/apply-sink" && go test -tags convergence -run TestConvergence -timeout 20m -v ./... ); then
  log "FAIL — mesh did not reconverge after total isolation (release blocker). Retaining state."
  kubectl -n "$NS" get faultinjection,networkchaos,pods -o wide || true
  exit 1
fi
ELAPSED=$(( $(date +%s) - START ))

# SECONDARY guard (the active proof-of-fire above is primary): converging well inside the 90s
# window is a second signal the cut never bit.
MIN_ELAPSED="${MIN_ELAPSED:-60}"
if [ "$ELAPSED" -lt "$MIN_ELAPSED" ]; then
  log "FAIL — converged in ${ELAPSED}s, inside the 90s isolation window (expected >=${MIN_ELAPSED}s)."
  log "       The isolation did not actually cut the mesh. Refusing a false green."
  exit 1
fi
log "PASS — mesh reconverged byte-identical after TOTAL isolation of site B (${ELAPSED}s; cut bit: >=${MIN_ELAPSED}s)"
exit 0
