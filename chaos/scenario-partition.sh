#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario 1: multimaster-partition (design §5).
#
# Partition a site off the mesh mid-write, drive conflicting writes through the cut, let
# the fault expire, and assert the mesh re-converges byte-identical. Red = release blocker.
#
# NOTE the mesh is POD-MEDIATED (pg → Debezium → NATS → apply-sink → pg): cutting
# pg-a↔pg-b directly injects NOTHING. The fault cuts the site from the engine that feeds
# it — see sandbox/fault-partition.yaml. A real cut shows up as a ~90s diverge-then-
# converge; a run that finishes in ~13s means nothing was injected.
#
# Safety (design §3) is layered and independent of this script: sandbox-scoped RBAC, a
# ResourceQuota, a low PriorityClass, the fault's own `duration`, AND the pre-flight guard
# below — which aborts before anything is applied if the fault could reach outside.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
# The poll budget must exceed fault duration + heal + settle.
export CONV_TIMEOUT="${CONV_TIMEOUT:-300}"
export CONV_SETTLE="${CONV_SETTLE:-15}"
export CONV_CREATE="${CONV_CREATE:-false}"   # sandbox_provision seeds the table
export CONV_KEYS="${CONV_KEYS:-200}"
export CONV_CONFLICTS="${CONV_CONFLICTS:-20}"

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
trap sandbox_teardown EXIT

sandbox_provision
sandbox_conv_members

# PRE-FLIGHT — refuse the fault if it could reach anything outside the sandbox.
log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-partition.yaml"

EXIT_INCONCLUSIVE=42   # neither red nor green (the nightly-chaos workflow maps this to a warning)

# Proof-of-fire (oracle pillar 1), part 1: the a→b link must be HEALTHY before the cut —
# otherwise the mesh isn't ready and nothing this run observes can be trusted.
log "proof-of-fire: confirming the a→b link is up BEFORE the cut"
if ! "$HERE/probe-partition.sh" up; then
  log "INCONCLUSIVE — a→b link not up pre-fault (mesh not ready / probe path broken). Not counting."
  exit "$EXIT_INCONCLUSIVE"
fi

log "injecting the partition (90s, time-boxed + pod-scoped)"
kubectl apply -f "$HERE/sandbox/fault-partition.yaml"

# Proof-of-fire (oracle pillar 1), part 2 — the 07-23 gap: actively confirm the cut BIT,
# from the mesh's own netns. iptables/ipset take a moment to land, so sample briefly. If the
# link stays reachable through the window the fault never fired → INCONCLUSIVE, not green.
log "proof-of-fire: confirming the partition actually cut the a→b link"
fired=0
for _ in $(seq 1 6); do
  if "$HERE/probe-partition.sh" down; then fired=1; break; fi
  sleep 3
done
if [ "$fired" != 1 ]; then
  log "INCONCLUSIVE — a→b link still reachable during the fault window; the partition did not bite."
  log "            The oracle refuses to bless a fault that didn't fire. Not counting this night."
  kubectl -n "$NS" get faultinjection,networkchaos -o wide || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — the cut is confirmed live."

log "running the convergence harness through the cut"
START=$(date +%s)
if ! ( cd "$REPO/apply-sink" && go test -tags convergence -run TestConvergence -timeout 20m -v ./... ); then
  log "FAIL — divergence after CONV_TIMEOUT (release blocker). Retaining state."
  kubectl -n "$NS" get faultinjection,pods -o wide || true
  exit 1
fi
ELAPSED=$(( $(date +%s) - START ))

# SECONDARY guard (the active proof-of-fire probe above is now the primary): converging well
# inside the 90s window is a second signal the cut never bit — the mesh replicated straight
# through. Assert the delay rather than trusting it: a member↔member partition once "passed"
# in 13s having injected nothing.
MIN_ELAPSED="${MIN_ELAPSED:-60}"
if [ "$ELAPSED" -lt "$MIN_ELAPSED" ]; then
  log "FAIL — converged in ${ELAPSED}s, inside the 90s partition window (expected >=${MIN_ELAPSED}s)."
  log "       The partition did not actually cut the mesh. Refusing a false green."
  exit 1
fi
log "PASS — mesh re-converged byte-identical after the partition (${ELAPSED}s; cut bit: >=${MIN_ELAPSED}s)"
exit 0
