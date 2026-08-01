#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario: DATAFLOW RECONVERGES UNDER A CAPTURE KILL (the data-movement
# chain; see docs/chaos-oracle.md). Recover-mode oracle proving the kind: DataFlow — the unified
# node+edge topology — survives chaos, not just kind: Replication. A DataFlow with one replication
# edge (pg-a <-> pg-b) is the same multi-master mesh, declared the DataFlow way. We kill a node's CDC
# capture mid-write and assert the mesh still reconverges byte-identical via the convergence harness
# (SQL, reliable). Conservation of acknowledged work, DataFlow edition.
#
# Proof-of-fire: the capture pod is actually replaced. Same safety model as every scenario.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"

# The poll budget must exceed capture restart (~120-150s: JVM + logical-slot re-acquire) + settle.
export CONV_TIMEOUT="${CONV_TIMEOUT:-360}"
export CONV_SETTLE="${CONV_SETTLE:-15}"
export CONV_CREATE="${CONV_CREATE:-false}"   # sandbox_provision_dataflow seeds conv_test
export CONV_KEYS="${CONV_KEYS:-150}"
export CONV_CONFLICTS="${CONV_CONFLICTS:-15}"

CAPTURE_LABEL="app=df-flow-pg-a-dbz"
EXIT_INCONCLUSIVE=42

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
trap sandbox_teardown_dataflow EXIT

sandbox_provision_dataflow
sandbox_conv_members

# PRE-FLIGHT — refuse the fault if it could reach anything outside the sandbox.
log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-dataflow-capture-kill.yaml"

capture_uid() { kubectl -n "$NS" get pods -l "$CAPTURE_LABEL" -o jsonpath='{.items[0].metadata.uid}' 2>/dev/null || true; }

# Run the convergence harness in the BACKGROUND (drives conflicting writes + polls to convergence),
# so we can kill the capture WHILE it drives — the migration/partition pattern.
log "starting the convergence harness against the DataFlow mesh"
HARNESS_LOG="$(mktemp)"
( cd "$REPO/apply-sink" && go test -tags convergence -run TestConvergence -timeout 20m -v ./... ) >"$HARNESS_LOG" 2>&1 &
HARNESS_PID=$!

sleep 8
BEFORE="$(capture_uid)"
log "injecting the DataFlow capture kill (node pg-a, mid-write)"
kubectl apply -f "$HERE/sandbox/fault-dataflow-capture-kill.yaml"

# Proof-of-fire: the capture pod must actually be replaced.
replaced=0
for _ in $(seq 1 30); do
  a="$(capture_uid)"
  [ -n "$a" ] && [ "$a" != "$BEFORE" ] && { replaced=1; break; }
  sleep 2
done
if [ "$replaced" != 1 ]; then
  log "INCONCLUSIVE — the DataFlow capture was not replaced; the kill didn't land. The oracle won't bless a fault that didn't fire."
  kubectl -n "$NS" get faultinjection,podchaos,pods -l "$CAPTURE_LABEL" -o wide 2>/dev/null || true
  kill "$HARNESS_PID" >/dev/null 2>&1 || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — DataFlow capture killed and replaced (${BEFORE:0:8}… → new)."

log "waiting for the convergence harness to judge (DataFlow mesh must reconverge byte-identical)"
if wait "$HARNESS_PID"; then
  grep -E 'STEADY|CONVERGED|PASS|ok ' "$HARNESS_LOG" | tail -4 || tail -4 "$HARNESS_LOG"
  log "PASS — the DataFlow mesh reconverged byte-identical after a capture kill (zero lost writes, kind: DataFlow survives chaos)."
  rm -f "$HARNESS_LOG"
  exit 0
fi
log "FAIL — the DataFlow mesh did NOT reconverge within CONV_TIMEOUT after the capture kill (divergence/lost writes — release blocker)."
tail -20 "$HARNESS_LOG" || true
kubectl -n "$NS" get dataflow,faultinjection,pods -o wide 2>/dev/null | grep -iE 'df|NAME' || true
rm -f "$HARNESS_LOG"
exit 1
