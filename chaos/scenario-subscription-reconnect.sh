#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario: SUBSCRIPTION NO-LOSS UNDER ENGINE KILL (open-appsync).
#
# What it proves (recover-mode, streaming edition — mirrors scenario-stream-noloss.sh): every
# ACKNOWLEDGED mutation event survives an engine-pod kill on the durable JetStream stream the
# subscriptions ride. A createTodo mutation that returns data publishes one onCreateTodo event to
# sub.onCreateTodo; drive it across a pod kill (2 replicas, so the Service keeps serving via the
# survivor) and the subject must reach >= the number of acknowledged mutations after recovery. A
# durable consumer cannot lose an acked event, so count >= acked == nothing dropped (dups OK,
# at-least-once). Proof-of-fire: an engine pod must actually be replaced.
#
# Scope (honest): this proves publish-durability + Service availability across a pod kill. The stronger
# variant — a persistent WS subscriber that must reconnect and resume with no gap — is a future probe;
# the durable-consumer resume it depends on is the same JetStream mechanism this exercises.
#
# STATUS: RUNNABLE + WIRED — self-provisioning, verified green once by hand on the live cluster
# (2026-08-07: killed one of two replicas mid-stream; survivor acked 100/100; all 101 events reached
# sub.onCreateTodo — zero drops). That first run also earned its keep: it caught a real multi-replica
# bug (both replicas bound the same JetStream *durable* consumer → crash-loop), fixed in the engine's
# subscription bus (ephemeral fan-out). The verdict is now DE-FORKED onto the singular recover engine
# (apply-sink/subscription_noloss_test.go, proven RED/GREEN by TestSubscriptionNoLossRedGreen), and the
# scenario is registered in chaos/grammar.json (watched) so it can be drawn by the plane-wide lottery.
# Graduation is still earned the same way as every other scenario — a nightly green streak, not one run.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
EXIT_INCONCLUSIVE=42

N="${SUB_MUTATIONS:-100}"                  # mutations driven across the outage
SUB_TIMEOUT="${SUB_TIMEOUT:-180}"          # seconds for the subject to cover every acked event after recovery
CANARY_TIMEOUT="${CANARY_TIMEOUT:-90}"
ENGINE_LABEL="app=open-appsync-chaos"
export SUB_STREAM="${SUB_STREAM:-open_appsync_subscriptions}"

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
trap sandbox_teardown_appsync EXIT

sandbox_provision_appsync

# pre-flight — refuse the fault if it could reach anything outside the sandbox.
log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-appsync-node-kill.yaml"

# All current engine pod UIDs (space-separated). mode:one kills one of the replicas, so proof-of-fire
# must watch the whole set — a single-pod check misses a kill of the pod it isn't watching.
engine_uids() { kubectl -n "$NS" get pods -l "$ENGINE_LABEL" -o jsonpath='{.items[*].metadata.uid}' 2>/dev/null || true; }

# Drive M createTodo mutations against the engine Service from an ephemeral curl pod; echo how many
# were ACKNOWLEDGED (returned data.createTodo). One pod runs the whole loop (fast; no pod-per-call).
drive_mutations() {
  local start="$1" count="$2"
  kubectl -n "$NS" run "appsync-drv-$$-$start" --rm -i --restart=Never --image=curlimages/curl:latest --command -- \
    sh -c 'ok=0; for i in $(seq '"$start"' '"$(( start + count - 1 ))"'); do
      r=$(curl -s -m 5 -XPOST http://open-appsync-chaos.'"$NS"'.svc:80/graphql -H "Content-Type: application/json" \
        -d "{\"query\":\"mutation{createTodo(input:{id:\\\"k$i\\\",name:\\\"n$i\\\"}){id}}\"}");
      echo "$r" | grep -q "\"createTodo\"" && ok=$((ok+1)); done; echo "ACKED=$ok"' 2>/dev/null \
    | grep -oE 'ACKED=[0-9]+' | grep -oE '[0-9]+' | head -1
}

# Proof-of-fire part 1: the pipeline is live — one mutation reaches the subject BEFORE the fault.
log "proof-of-fire: a mutation must reach sub.onCreateTodo before the fault (pipeline live)"
canary="$(drive_mutations 0 1)"; canary="${canary:-0}"
live=0
for _ in $(seq 1 $(( CANARY_TIMEOUT / 6 )) ); do
  c="$(sandbox_appsync_msg_count)"; c="${c:-0}"
  [ "$c" -ge 1 ] && { live=1; break; }
  sleep 6
done
[ "$live" = 1 ] || { log "INCONCLUSIVE — canary never reached the subject (subscription pipeline not ready)."; kubectl -n "$NS" get deploy,pods -l "$ENGINE_LABEL" -o wide 2>/dev/null || true; exit "$EXIT_INCONCLUSIVE"; }
log "proof-of-fire OK — subscription pipeline live (canary acked=${canary})."

BEFORE_UIDS="$(engine_uids)"
log "injecting the engine-pod kill, then driving ${N} mutations across the outage"
kubectl apply -f "$HERE/sandbox/fault-appsync-node-kill.yaml"
ACKED="$(drive_mutations 1 "$N")"; ACKED="${ACKED:-0}"
log "acknowledged mutations during/after the kill: ${ACKED}/${N}"

# Proof-of-fire part 2: an engine pod must actually be replaced — a pre-kill UID must disappear from
# the live set (mode:one kills one replica; the survivor's UID stays, so watch for any lost UID).
replaced=0
for _ in $(seq 1 45); do
  cur=" $(engine_uids) "
  for u in $BEFORE_UIDS; do
    case "$cur" in *" $u "*) ;; *) replaced=1 ;; esac
  done
  [ "$replaced" = 1 ] && break
  sleep 2
done
[ "$replaced" = 1 ] || { log "INCONCLUSIVE — no engine pod was replaced; the kill didn't land."; exit "$EXIT_INCONCLUSIVE"; }
[ "$ACKED" -ge 1 ] || { log "INCONCLUSIVE — no mutation was acknowledged during the run (Service unavailable throughout)."; exit "$EXIT_INCONCLUSIVE"; }
log "proof-of-fire OK — an engine pod was killed and replaced."

# The VERDICT is owned by the singular recover engine now (apply-sink/subscription_noloss_test.go),
# de-forked from this shell like the other planes: it reads the durable subject's message count, waits
# for it to PLATEAU after the kill (SteadyState — the subject retains its log, so the terminal signal is
# a settled count, not an empty one), then asserts count >= (1 canary + ACKED) (Reconcile — no dropped
# acknowledged event; dups OK, at-least-once). Kept as two INDEPENDENT pillars so the conservation red is
# live-reachable. This scenario owns provisioning + firing the kill + the INCONCLUSIVE gates; the engine
# owns the pass/fail.
REPO="$(cd "$HERE/.." && pwd)"
export SUB_NATS_URL="${SUB_NATS_URL:-nats://nats.nats.svc:4222}"
export SUB_STREAM   # already exported above (open_appsync_subscriptions)
export SUB_WANT=$(( 1 + ACKED ))     # denominator: pre-fault canary + acknowledged mutations
# CONV_TIMEOUT covers the post-kill flush of every acked event onto the subject; give real headroom.
export CONV_TIMEOUT="$SUB_TIMEOUT"
log "judging no-loss subscription delivery via the singular recover engine (want ${SUB_WANT}; budget ${CONV_TIMEOUT}s)"
if ! ( cd "$REPO/apply-sink" && go test -tags convergence -run '^TestSubscriptionNoLoss$' -timeout 15m -count=1 ./... ); then
  log "FAIL — sub.onCreateTodo DROPPED acknowledged events across the engine kill (release blocker)."
  kubectl -n "$NS" get faultinjection,pods -l "$ENGINE_LABEL" -o wide 2>/dev/null || true
  exit 1
fi
log "PASS — every acknowledged mutation's event reached sub.onCreateTodo across an engine kill (durable stream held; no dropped events; dups OK) (verdict: singular recover engine)."
exit 0
