#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario 3: sink-kill (design §5).
#
# Kill the apply-sink MID-FLIGHT (while the harness is writing) and assert the mesh still
# converges once the pod returns. This exercises durability of the engine's progress: the
# sink resumes from its durable NATS consumer (AckWait redelivers rather than drops) and
# applies the queued changes. A lost offset or a dropped message = a missing key, which
# the convergence harness fails on. Red = release blocker.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
# The poll budget must outlast the kill + pod restart + redelivery + settle.
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

# Pre-flight the kill BEFORE anything runs: refuse it if it could reach outside the sandbox.
log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-sink-kill.yaml"

# Drive the harness in the background so we can kill the sink WHILE it is writing.
log "starting the convergence harness (background)"
( cd "$REPO/apply-sink" && go test -tags convergence -run TestConvergence -timeout 15m -v ./... ) &
HARNESS=$!

sleep "${KILL_AFTER:-6}"   # let writes get in flight
SINK_SEL="app=chaos-mesh-pg-repl-a-b-sink"
sink_uid() { kubectl -n "$NS" get pods -l "$SINK_SEL" -o jsonpath='{.items[0].metadata.uid}' 2>/dev/null || true; }
BEFORE="$(sink_uid)"
log "killing the apply-sink mid-flight (pod ${BEFORE:0:8}…)"
kubectl apply -f "$HERE/sandbox/fault-sink-kill.yaml"

# Assert the fault ACTUALLY landed — the pod must be replaced. A chaos test whose fault
# silently no-ops is worse than no test (it reports green while proving nothing), so a
# kill we can't observe is a failure, not a pass.
KILLED=0
for _ in $(seq 1 20); do
  AFTER="$(sink_uid)"
  if [ -n "$AFTER" ] && [ "$AFTER" != "$BEFORE" ]; then
    log "fault landed: sink pod replaced (${BEFORE:0:8}… → ${AFTER:0:8}…)"
    KILLED=1
    break
  fi
  sleep 2
done
if [ "$KILLED" != 1 ]; then
  log "FAIL — the sink was never killed: the fault did not inject. Refusing a false green."
  exit 1
fi

# The sink's Deployment restarts it; the harness keeps polling until the mesh re-converges.
if wait "$HARNESS"; then
  log "PASS — mesh converged after the sink was killed mid-flight (offsets survived, no lost writes)"
  exit 0
fi
log "FAIL — mesh did not converge after the sink restart (release blocker)"
kubectl -n "$NS" get pods -o wide || true
exit 1
