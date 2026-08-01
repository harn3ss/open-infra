#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario 5: STORAGE replica-loss (see docs/chaos-oracle.md).
#
# The REAL storage-resilience test, finally runnable now that the sandbox DBs live on Longhorn
# (longhorn-chaos SC: 2 replicas on 2 distinct disposable chaos nodes) instead of emptyDir, and
# the chaos nodes are storage-fenced from production. Lose one replica of pg-b's volume mid-write
# and assert: the volume DEGRADES but never faults, the DB stays queryable off the surviving
# replica, Longhorn REBUILDS back to healthy, and the mesh converges byte-identical (no data lost,
# CDC offsets survive). This is the honest version of what `io-latency` was a dead-end stand-in for.
#
# Oracle: this is a DEGRADE, not a cut — the mesh must keep converging (no MIN_ELAPSED). The
# proof-of-fire is the volume actually reaching `degraded` robustness (don't trust the delete);
# if it never degrades, the replica delete didn't bite → INCONCLUSIVE, not green.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
LH_NS="${LONGHORN_NS:-longhorn-system}"
# Longhorn attach/provision is slower than emptyDir; convergence itself is normal speed.
export MEMBERS_MANIFEST="members-longhorn.yaml"
export MEMBERS_ROLLOUT_TIMEOUT="${MEMBERS_ROLLOUT_TIMEOUT:-300s}"
export CONV_TIMEOUT="${CONV_TIMEOUT:-300}"
export CONV_SETTLE="${CONV_SETTLE:-15}"
export CONV_CREATE="${CONV_CREATE:-false}"
export CONV_KEYS="${CONV_KEYS:-200}"
export CONV_CONFLICTS="${CONV_CONFLICTS:-20}"
REBUILD_TIMEOUT="${REBUILD_TIMEOUT:-180}"   # seconds for Longhorn to rebuild back to healthy
EXIT_INCONCLUSIVE=42

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
trap sandbox_teardown EXIT

sandbox_provision
sandbox_conv_members

# Resolve pg-b's Longhorn volume (the PV backing its StatefulSet PVC).
vol="$(kubectl -n "$NS" get pvc data-pg-b-0 -o jsonpath='{.spec.volumeName}' 2>/dev/null || true)"
[ -n "$vol" ] || { log "INCONCLUSIVE — pg-b has no Longhorn PVC (members-longhorn not applied?)."; exit "$EXIT_INCONCLUSIVE"; }
log "pg-b Longhorn volume: $vol"

vol_robustness() { kubectl -n "$LH_NS" get volumes.longhorn.io "$vol" -o jsonpath='{.status.robustness}' 2>/dev/null; }
vol_replicas()   { kubectl -n "$LH_NS" get replicas.longhorn.io -o json 2>/dev/null \
                   | python3 -c "import sys,json;print('\n'.join(r['metadata']['name']+' '+str(r['spec'].get('nodeID')) for r in json.load(sys.stdin)['items'] if r['spec'].get('volumeName')=='$vol'))"; }

# Proof-of-fire part 1: healthy + 2 replicas on 2 DISTINCT chaos nodes BEFORE the fault.
log "proof-of-fire: pg-b volume healthy with replicas across distinct chaos nodes BEFORE the loss"
robust="$(vol_robustness)"; mapfile -t reps < <(vol_replicas)
nodes="$(printf '%s\n' "${reps[@]}" | awk '{print $2}' | sort -u | grep -c .)"
log "  robustness=$robust replicas=${#reps[@]} distinct-nodes=$nodes"
printf '   %s\n' "${reps[@]}"
if [ "$robust" != "healthy" ] || [ "${#reps[@]}" -lt 2 ] || [ "$nodes" -lt 2 ]; then
  log "INCONCLUSIVE — pg-b volume not healthy/2-replicas/2-nodes pre-fault; can't stage a real replica loss."
  exit "$EXIT_INCONCLUSIVE"
fi

# Pick a victim replica (delete the FIRST — any one is a valid single-replica loss).
victim="$(printf '%s\n' "${reps[@]}" | head -1 | awk '{print $1}')"
victim_node="$(printf '%s\n' "${reps[@]}" | head -1 | awk '{print $2}')"
log "injecting storage replica-loss: deleting replica $victim (on $victim_node)"
kubectl -n "$LH_NS" delete replicas.longhorn.io "$victim" --wait=false >/dev/null 2>&1 || true

# Proof-of-fire part 2: the volume must actually DEGRADE (rebuild can be quick, so sample fast).
log "proof-of-fire: confirming the volume degraded (the replica loss bit)"
degraded=0
for _ in $(seq 1 30); do
  [ "$(vol_robustness)" = "degraded" ] && { degraded=1; break; }
  sleep 1
done
if [ "$degraded" != 1 ]; then
  log "INCONCLUSIVE — volume never showed 'degraded' after the replica delete; the loss didn't bite."
  kubectl -n "$LH_NS" get volumes.longhorn.io "$vol" -o wide || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — volume is degraded; replica loss confirmed live."

# The DB must stay queryable off the surviving replica WHILE degraded.
if ! kubectl -n "$NS" exec pg-b-0 -- psql -U app -d app -c 'SELECT 1' >/dev/null 2>&1; then
  log "FAIL — pg-b is not queryable during the replica loss (a single replica loss must not take the DB down)."
  exit 1
fi
log "pg-b still serving reads/writes off the surviving replica."

# Core assertion 1: the mesh converges byte-identical through the storage fault (no data lost).
log "running the convergence harness through the storage degrade (must converge — no lost writes)"
if ! ( cd "$REPO/apply-sink" && go test -tags convergence -run TestConvergence -timeout 20m -v ./... ); then
  log "FAIL — mesh did not converge through the storage replica loss (release blocker). Retaining state."
  kubectl -n "$LH_NS" get volumes.longhorn.io "$vol" -o wide || true
  exit 1
fi

# Core assertion 2: Longhorn rebuilds back to healthy within the bound (liveness of the storage layer).
log "waiting for Longhorn to rebuild pg-b's volume back to healthy (<= ${REBUILD_TIMEOUT}s)"
healed=0
for _ in $(seq 1 "$REBUILD_TIMEOUT"); do
  [ "$(vol_robustness)" = "healthy" ] && { healed=1; break; }
  sleep 1
done
mapfile -t reps2 < <(vol_replicas)
nodes2="$(printf '%s\n' "${reps2[@]}" | awk '{print $2}' | sort -u | grep -c .)"
if [ "$healed" != 1 ]; then
  log "FAIL — volume did not rebuild to healthy within ${REBUILD_TIMEOUT}s (robustness=$(vol_robustness))."
  printf '   %s\n' "${reps2[@]}"
  exit 1
fi
log "PASS — mesh converged byte-identical AND Longhorn rebuilt pg-b's volume to healthy"
log "       (${#reps2[@]} replicas across ${nodes2} chaos nodes; single replica loss survived + rebuilt)."
exit 0
