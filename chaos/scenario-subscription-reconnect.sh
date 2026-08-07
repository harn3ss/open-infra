#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario: SUBSCRIPTION NO-LOSS UNDER ENGINE KILL (open-appsync §3).
#
# ─── PARKED (authored, not yet run) ─────────────────────────────────────────────────────────────
# This is the graduation instrument for open-appsync subscriptions. The rung's bar is TEMPORAL, not a
# unit test: kill an engine pod mid-stream and prove reconnect/resume with no lost (and no duplicated
# past the ack point) events. It requires a sandbox with NATS JetStream + an open-appsync engine wired
# to it (NATS_URL set) serving a GraphQLApi whose subscription is triggered by a mutation. Until that
# sandbox is provisioned it exits INCONCLUSIVE (42) — it must NEVER false-green. When the deploy exists,
# remove the parked guard and let it run on the nightly clock; the label comes off after the standard
# green streak, like every other scenario. See open-appsync/README.md and the forward map §3.
# ────────────────────────────────────────────────────────────────────────────────────────────────
#
# Oracle (recover-mode, streaming edition — mirrors scenario-stream-noloss.sh): the authoritative
# signal is the JetStream message COUNT on the subscription subject (O(1), exact). A mutation that
# succeeds publishes one event to the subject; drive N mutations across an engine-pod kill and the
# subject must reach >= N (+ canary) after recovery. A durable consumer cannot lose an acknowledged
# event, so count >= driven == nothing dropped (dups OK per at-least-once). Proof-of-fire: the engine
# pod must actually be replaced.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
EXIT_INCONCLUSIVE=42

N="${SUB_MUTATIONS:-100}"                 # mutations driven across the outage
SUB_TIMEOUT="${SUB_TIMEOUT:-240}"         # seconds for the subject to cover every event after recovery
CANARY_TIMEOUT="${CANARY_TIMEOUT:-90}"
ENGINE_LABEL="app=open-appsync-chaos"
SUBJECT="${SUB_SUBJECT:-sub.onCreateTodo}"
STREAM="${SUB_STREAM:-open_appsync_subscriptions}"

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"

# --- PARKED GUARD: refuse to run (INCONCLUSIVE, never red/green) until the deploy exists. ---
if ! kubectl -n "$NS" get deploy -l "$ENGINE_LABEL" -o name >/dev/null 2>&1 \
   || [ -z "$(kubectl -n "$NS" get deploy -l "$ENGINE_LABEL" -o name 2>/dev/null)" ]; then
  log "PARKED — no open-appsync engine (${ENGINE_LABEL}) in ${NS}. This scenario needs a sandbox with"
  log "         NATS JetStream + open-appsync (NATS_URL set) serving a subscription. Not counting."
  exit "$EXIT_INCONCLUSIVE"
fi
if ! command -v nats >/dev/null 2>&1; then
  log "INCONCLUSIVE — the 'nats' CLI is unavailable on the runner; cannot read the subject count."
  exit "$EXIT_INCONCLUSIVE"
fi

# Message count on the subscription subject's stream (authoritative, exact — the stream-noloss pattern).
subject_msg_count() {
  nats --context chaos stream info "$STREAM" --json 2>/dev/null \
    | python3 -c 'import sys,json; print(json.load(sys.stdin).get("state",{}).get("messages",0))' 2>/dev/null || echo 0
}

engine_uid() { kubectl -n "$NS" get pods -l "$ENGINE_LABEL" -o jsonpath='{.items[0].metadata.uid}' 2>/dev/null || true; }

# A mutation that triggers the subscription (publishes one event to the subject). The engine is hit
# directly in the sandbox (no shim); the demo GraphQLApi's createTodo triggers onCreateTodo.
drive_mutation() {
  local i="$1"
  kubectl -n "$NS" exec deploy/open-appsync-chaos -- \
    wget -q -O- --header='Content-Type: application/json' \
    --post-data="{\"query\":\"mutation { createTodo(input:{id:\\\"k$i\\\",name:\\\"n$i\\\"}) { id } }\"}" \
    http://localhost:8080/graphql >/dev/null 2>&1 || true
}

log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-appsync-node-kill.yaml"

# Proof-of-fire part 1: the pipeline is live — a mutation reaches the subject BEFORE the fault.
log "proof-of-fire: a mutation must reach ${SUBJECT} before the fault (pipeline live)"
drive_mutation "canary"
live=0
for _ in $(seq 1 $(( CANARY_TIMEOUT / 6 )) ); do
  [ "$(subject_msg_count)" -ge 1 ] && { live=1; break; }
  sleep 6
done
[ "$live" = 1 ] || { log "INCONCLUSIVE — canary never reached ${SUBJECT} (subscription pipeline not ready)."; exit "$EXIT_INCONCLUSIVE"; }
log "proof-of-fire OK — subscription pipeline live."

BEFORE="$(engine_uid)"
log "injecting the engine-pod kill, then driving ${N} mutations across the outage"
kubectl apply -f "$HERE/sandbox/fault-appsync-node-kill.yaml"
for i in $(seq 1 "$N"); do drive_mutation "$i"; done

# Proof-of-fire part 2: the engine pod must actually be replaced.
replaced=0
for _ in $(seq 1 30); do
  a="$(engine_uid)"; [ -n "$a" ] && [ "$a" != "$BEFORE" ] && { replaced=1; break; }
  sleep 2
done
[ "$replaced" = 1 ] || { log "INCONCLUSIVE — engine pod not replaced; the kill didn't land."; exit "$EXIT_INCONCLUSIVE"; }
log "proof-of-fire OK — engine killed and replaced."

log "asserting the subject received every event across the kill (at-least-once, no loss)"
deadline=$(( SECONDS + SUB_TIMEOUT )); count=0
while [ "$SECONDS" -lt "$deadline" ]; do
  count="$(subject_msg_count)"
  [ "$count" -ge $(( N + 1 )) ] && break
  log "  ${SUBJECT} messages: ${count}/$(( N + 1 )) …"
  sleep 10
done

if [ "$count" -ge $(( N + 1 )) ]; then
  log "PASS — ${SUBJECT} received all ${count} events (>= ${N} + canary) across an engine kill (durable consumer resumed; no dropped events)."
  exit 0
fi
log "FAIL — ${SUBJECT} received only ${count}/$(( N + 1 )) after the kill (DROPPED subscription events — release blocker)."
exit 1
