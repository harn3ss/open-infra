#!/usr/bin/env bash
# Parallel chaos run executor — composes the isolation bricks into one runnable path.
#
# This is the orchestration a generated chain (tools/chainforge) runs through, and the thing that
# makes "continuous = parallel" real. It ties together, per run-id:
#
#   1. RESERVE   capacity_ledger.py — claim this run's footprint atomically; INCONCLUSIVE (42) and
#                back off if the chaos-node budget is already full (never oversubscribe).
#   2. ISOLATE   runspace.py — render the namespace template + sandbox manifests onto this run's OWN
#                namespace chaos-run-<id>, so fixed names never collide with a concurrent run.
#   3. PROVISION apply the (isolated) sandbox and wait for it to stand up.
#   4. PROVE     confirm it came up — a run that never provisioned is INCONCLUSIVE, not a red.
#      (A full run then injects the drawn fault, runs proof-of-fire, and judges with the mode engine;
#       here we stand up the convergence members to prove the composition end-to-end.)
#   5. TEARDOWN  scoped: delete the namespace (never a shared `--all`) and RELEASE the reservation.
#
# Steps 1/2/3/5 are workload-agnostic; only the manifests in step 3 and the oracle in a full run are
# chain-specific. Many copies of this run concurrently, each in its own reserved namespace.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
RUN_ID="${1:?usage: run-isolated.sh <run-id>}"
EXIT_INCONCLUSIVE=42
CPU_M="${RUN_CPU_M:-4000}"          # reserved footprint (matches the sandbox quota)
MEM_MI="${RUN_MEM_MI:-8192}"
NS="$(python3 "$HERE/runspace.py" --run-id "$RUN_ID" --ns)"

log() { echo "▸ [$RUN_ID] $*"; }

reserved=0
cleanup() {
  log "teardown: deleting namespace $NS (scoped — no --all)"
  kubectl delete namespace "$NS" --wait=false >/dev/null 2>&1 || true
  kubectl delete clusterrolebinding "chaos-runner-preflight-readonly-$RUN_ID" >/dev/null 2>&1 || true
  if [ "$reserved" = 1 ]; then
    python3 "$HERE/capacity_ledger.py" release --run-id "$RUN_ID" >/dev/null 2>&1 || true
    log "released capacity reservation"
  fi
}
trap cleanup EXIT

# 1. RESERVE
if ! python3 "$HERE/capacity_ledger.py" reserve --run-id "$RUN_ID" --cpu "$CPU_M" --mem "$MEM_MI"; then
  log "INCONCLUSIVE — no capacity budget; backing off (not counting this run)."
  exit "$EXIT_INCONCLUSIVE"
fi
reserved=1

# 2. ISOLATE + 3. PROVISION
log "isolating into $NS and provisioning the sandbox"
python3 "$HERE/runspace.py" --run-id "$RUN_ID" "$REPO/platform/resilience/chaos-sandbox.yaml" | kubectl apply -f - >/dev/null
python3 "$HERE/runspace.py" --run-id "$RUN_ID" "$HERE/sandbox/members.yaml" | kubectl apply -f - >/dev/null

# 4. PROVE
for ss in pg-a pg-b; do
  if ! kubectl -n "$NS" rollout status "statefulset/$ss" --timeout="${PROVISION_TIMEOUT:-150s}"; then
    log "INCONCLUSIVE — $ss never became ready in $NS; the sandbox did not stand up."
    exit "$EXIT_INCONCLUSIVE"
  fi
done
log "OK — isolated sandbox up in $NS (pg-a, pg-b Running; reserved ${CPU_M}m/${MEM_MI}Mi)."
# A full run injects the drawn fault here → proof-of-fire → mode-engine oracle → PASS/FAIL/INCONCLUSIVE.
exit 0
