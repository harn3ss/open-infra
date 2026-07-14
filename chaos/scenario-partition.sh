#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario 1: multimaster-partition (design §5).
#
# Runs on the self-hosted runner (has kubectl + Go + reach to cluster ClusterIPs).
# It provisions a disposable two-site Postgres mesh in chaos-sandbox, partitions site B
# mid-write, drives conflicting writes through the cut with the convergence harness, lets
# the fault expire, and asserts the mesh re-converges byte-identical. Red = release blocker.
#
# Safety (design §3) is layered and independent of this script: sandbox-scoped RBAC, a
# ResourceQuota, a low PriorityClass, the dead-man's-switch `duration`, AND the pre-flight
# guard below — which aborts before any fault is applied if it could reach outside the sandbox.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
KEEP="${CHAOS_KEEP:-0}"                 # 1 = leave the sandbox up for debugging
export CONV_TIMEOUT="${CONV_TIMEOUT:-300s}"   # must exceed fault duration + heal + settle
export CONV_SETTLE="${CONV_SETTLE:-15s}"
export CONV_CREATE="${CONV_CREATE:-false}"   # we seed the table below; the engine's mm-prep owns the mm columns
export CONV_KEYS="${CONV_KEYS:-200}"
export CONV_CONFLICTS="${CONV_CONFLICTS:-20}"

log() { echo "▸ $*"; }
cleanup() {
  kubectl -n "$NS" delete -f "$HERE/sandbox/fault-partition.yaml" --ignore-not-found >/dev/null 2>&1 || true
  if [ "$KEEP" != "1" ]; then
    log "tearing down sandbox members + mesh"
    kubectl -n "$NS" delete -f "$HERE/sandbox/mesh.yaml" --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete -f "$HERE/sandbox/members.yaml" --ignore-not-found >/dev/null 2>&1 || true
    # sweep the engine's composed mm-prep Jobs (not GC'd with the Replication claim)
    kubectl -n "$NS" delete jobs --all --ignore-not-found >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# 1. provision the disposable members + the multi-master mesh
log "provisioning sandbox members"
kubectl apply -f "$HERE/sandbox/members.yaml"
kubectl -n "$NS" rollout status statefulset/pg-a --timeout=120s
kubectl -n "$NS" rollout status statefulset/pg-b --timeout=120s

# The table must exist BEFORE the mesh: the engine's mm-prep installs the version/origin
# columns + triggers onto it, and it CrashLoops if the table is missing. The harness then
# writes into it (it does NOT create it — CONV_CREATE=false).
log "seeding conv_test on both members"
for m in pg-a pg-b; do
  kubectl -n "$NS" exec "${m}-0" -- psql -U app -d app \
    -c "CREATE TABLE IF NOT EXISTS public.conv_test (id text PRIMARY KEY, val text);"
done

log "starting the multi-master mesh (Replication engine)"
kubectl apply -f "$HERE/sandbox/mesh.yaml"
# wait for the engine's mm-prep to finish installing triggers before we write
sleep "${MESH_WARMUP:-45}"

# Start from a clean table (the harness inserts fresh keys; leftover rows from a prior
# run would collide). Fresh-provisioned members are already empty — this makes re-runs
# on a kept sandbox safe too.
for m in pg-a pg-b; do
  kubectl -n "$NS" exec "${m}-0" -- psql -U app -d app -c "TRUNCATE conv_test;" >/dev/null 2>&1 || true
done
sleep 5

# 2. build CONV_MEMBERS from the members' ClusterIPs (reachable from the runner host)
IP_A="$(kubectl -n "$NS" get svc pg-a -o jsonpath='{.spec.clusterIP}')"
IP_B="$(kubectl -n "$NS" get svc pg-b -o jsonpath='{.spec.clusterIP}')"
export PGPASS="$(kubectl -n "$NS" get secret pg-creds -o jsonpath='{.data.password}' | base64 -d)"
export CONV_MEMBERS="[
  {\"name\":\"pg-a\",\"engine\":\"postgres\",\"dsn\":\"postgres://app:\${PGPASS}@${IP_A}:5432/app?sslmode=disable\",\"site\":\"a\",\"schema\":\"public\"},
  {\"name\":\"pg-b\",\"engine\":\"postgres\",\"dsn\":\"postgres://app:\${PGPASS}@${IP_B}:5432/app?sslmode=disable\",\"site\":\"b\",\"schema\":\"public\"}
]"

# 3. PRE-FLIGHT — refuse the fault if it could reach anything outside the sandbox
log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-partition.yaml"

# 4. inject the partition (time-boxed, pod-scoped, label-selected)
log "injecting network partition on site B (90s)"
kubectl apply -f "$HERE/sandbox/fault-partition.yaml"

# 5. drive conflicting writes THROUGH the cut, then poll until identical.
#    CONV_TIMEOUT exceeds duration+heal+settle so the harness spans the whole window.
log "running the convergence harness through the fault"
( cd "$REPO/apply-sink" && go test -tags convergence -run TestConvergence -timeout 20m -v ./... )
RC=$?

# 6. verdict
if [ "$RC" = "0" ]; then
  log "PASS — mesh re-converged byte-identical after the partition"
else
  log "FAIL — divergence after CONV_TIMEOUT (release blocker). Retaining artifacts."
  kubectl -n "$NS" get faultinjection,pods -o wide || true
fi
exit "$RC"
