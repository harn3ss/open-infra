#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario 6: mesh-under-concurrent-chaos (design §5).
#
# THE GRADUATION ACCEPTANCE TEST: the hand-run GameDay, automated. Hit the mesh with
# capture-kill + partition + sink-kill SIMULTANEOUSLY while the harness is writing, then
# assert it still converges byte-identical once everything heals.
#
# Every fault must be proven to have landed, while the harness is still in flight —
# otherwise "concurrent chaos" could quietly degrade into "no chaos" and still report green.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
# Budget must outlast the 90s partition + pod restarts + redelivery + settle.
export CONV_TIMEOUT="${CONV_TIMEOUT:-300}"
export CONV_SETTLE="${CONV_SETTLE:-15}"
export CONV_CREATE="${CONV_CREATE:-false}"
export CONV_KEYS="${CONV_KEYS:-200}"
export CONV_CONFLICTS="${CONV_CONFLICTS:-20}"

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
trap sandbox_teardown EXIT

sandbox_provision
sandbox_conv_members

# Pre-flight EVERY fault before any of them is applied.
log "pre-flight guard (all three faults)"
for f in fault-partition fault-sink-kill fault-capture-kill; do
  "$HERE/preflight.sh" "$HERE/sandbox/$f.yaml" >/dev/null
  log "  ok: $f"
done

uid_of() { kubectl -n "$NS" get pods -l "$1" -o jsonpath='{.items[0].metadata.uid}' 2>/dev/null || true; }
SINK_SEL="app=chaos-mesh-pg-repl-a-b-sink"
DBZ_SEL="app=chaos-mesh-pg-repl-b-dbz"

# The partition goes in FIRST so the harness's writes happen DURING the cut (the mesh must
# actually diverge). Injecting after the write phase lands the fault on an already-converged
# mesh — it "lands" but exercises nothing, which is a false green we hit here first.
SINK_BEFORE="$(uid_of "$SINK_SEL")"
DBZ_BEFORE="$(uid_of "$DBZ_SEL")"
log "injecting the partition (90s) — writes will be driven through the cut"
kubectl apply -f "$HERE/sandbox/fault-partition.yaml"

log "starting the convergence harness (background)"
START=$(date +%s)
( cd "$REPO/apply-sink" && go test -tags convergence -run TestConvergence -timeout 20m -v ./... ) &
HARNESS=$!

sleep "${CHAOS_AFTER:-5}"   # let writes get in flight through the cut
kill -0 "$HARNESS" 2>/dev/null || {
  log "FAIL — harness completed BEFORE the chaos was injected; nothing was exercised."
  exit 1
}

log "injecting the rest CONCURRENTLY: capture-kill + sink-kill (partition still active)"
kubectl apply -f "$HERE/sandbox/fault-capture-kill.yaml"
kubectl apply -f "$HERE/sandbox/fault-sink-kill.yaml"

# Prove each fault landed: both engine pods must be replaced, and the partition must have
# produced a live NetworkChaos. A concurrent-chaos test that silently injected nothing
# would be the most dangerous false green of all — it is the graduation gate.
landed() { # $1=selector $2=old-uid
  for _ in $(seq 1 25); do
    now="$(uid_of "$1")"
    [ -n "$now" ] && [ "$now" != "$2" ] && return 0
    sleep 2
  done
  return 1
}
landed "$DBZ_SEL"  "$DBZ_BEFORE"  && log "  landed: capture (dbz) pod replaced" || { log "FAIL — capture-kill never landed"; exit 1; }
landed "$SINK_SEL" "$SINK_BEFORE" && log "  landed: sink pod replaced"        || { log "FAIL — sink-kill never landed"; exit 1; }
NC_INJ=""
for _ in $(seq 1 20); do
  NC_INJ="$(kubectl -n "$NS" get networkchaos mm-partition \
    -o jsonpath='{.status.conditions[?(@.type=="AllInjected")].status}' 2>/dev/null || true)"
  [ "$NC_INJ" = "True" ] && break
  sleep 2
done
if [ "$NC_INJ" = "True" ]; then
  log "  landed: partition injected (NetworkChaos AllInjected=True)"
else
  log "FAIL — partition never reported AllInjected; it did not inject"; exit 1
fi

log "all three faults landed concurrently; waiting for the mesh to heal and converge"
if ! wait "$HARNESS"; then
  log "FAIL — mesh did not converge under concurrent chaos (release blocker)"
  kubectl -n "$NS" get faultinjection,pods -o wide || true
  exit 1
fi
ELAPSED=$(( $(date +%s) - START ))

# The partition runs for 90s, so a mesh that "converged" well inside that window was never
# actually cut — the faults landed on already-replicated data and proved nothing. Treat that
# as a failure, not a pass: it is precisely the false green this suite exists to prevent.
MIN_ELAPSED="${MIN_ELAPSED:-60}"
if [ "$ELAPSED" -lt "$MIN_ELAPSED" ]; then
  log "FAIL — converged in ${ELAPSED}s, inside the 90s partition window (expected >=${MIN_ELAPSED}s)."
  log "       The chaos did not actually delay convergence, so this proves nothing. Refusing a false green."
  exit 1
fi
log "PASS — mesh converged under CONCURRENT chaos in ${ELAPSED}s (partition bit: >=${MIN_ELAPSED}s)"
exit 0
