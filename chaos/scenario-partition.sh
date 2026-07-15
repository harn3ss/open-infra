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
export CONV_TIMEOUT="${CONV_TIMEOUT:-300s}"
export CONV_SETTLE="${CONV_SETTLE:-15s}"
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

log "injecting the partition (90s, time-boxed + pod-scoped)"
kubectl apply -f "$HERE/sandbox/fault-partition.yaml"

log "running the convergence harness through the cut"
START=$(date +%s)
if ( cd "$REPO/apply-sink" && go test -tags convergence -run TestConvergence -timeout 20m -v ./... ); then
  log "PASS — mesh re-converged byte-identical after the partition ($(( $(date +%s) - START ))s)"
  exit 0
fi
log "FAIL — divergence after CONV_TIMEOUT (release blocker). Retaining state."
kubectl -n "$NS" get faultinjection,pods -o wide || true
exit 1
