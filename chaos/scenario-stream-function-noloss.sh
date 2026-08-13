#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario: STREAM→FUNCTION NO-LOSS UNDER CAPTURE KILL (the FIRST cross-kind
# chain; see docs/chaos-oracle.md). Recover-mode oracle on the STREAMING + FUNCTION planes — the
# end-to-end edition of stream-no-loss. There, the guarantee stopped at the durable JetStream stream;
# here it must travel all the way to the FUNCTION at the far end: every source change committed while
# the capture engine is DOWN must be DELIVERED TO AND ACKNOWLEDGED BY the function once the chain
# recovers. At-least-once, so duplicates are fine; only a change that never reaches the function is red.
#
# Chain (3 resource types wired by typed ports): a source Database (evt-src) → a kind: Stream (Debezium
# → JetStream cdc-evt) → a kind: Function (evt-fn, spec.trigger.stream=evt). The Function's trigger
# renders a Benthos "pump" (evt-fn-pump) holding a DURABLE JetStream consumer "fn-evt-fn" on cdc-evt;
# Benthos acks a message ONLY after its HTTP POST to the function returns 2xx, so the consumer's
# acknowledged count == events delivered to and accepted by the function. We prove the chain is live,
# then kill the capture engine and write rows WHILE it is down (they queue in the Postgres WAL behind
# the replication slot), and assert the restarted capture resumes from its durable offset and the pump
# delivers EVERY row all the way to the function — no loss anywhere in the chain.
#
# Oracle: after recovery, the function's ack count must cover every driven key. Proof-of-fire: the
# capture pod must actually be replaced. Conservation of acknowledged work, cross-kind edition.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"

N="${STREAM_ROWS:-150}"                    # rows driven during the capture outage
# End-to-end recovery is deliberately slow to survive: the capture pod-kill leaves the Postgres logical
# slot's old consumer connection lingering (single-consumer) until it times out, Debezium Server's JVM
# start is ~40s, then the pump's ack_wait redelivery + the function cold-start from scale-to-zero add on
# top. So give the whole chain a generous budget to re-attach, drain the WAL backlog, and deliver every
# event to the function. CONV_TIMEOUT is set from this and MUST stay ≥ 420 (the oracle's floor) or a
# slow-but-lossless drain would t.Fatalf as a false red.
STREAM_TIMEOUT="${STREAM_TIMEOUT:-480}"    # seconds for the function to ack every key after recovery (≥ 420)
CANARY_TIMEOUT="${CANARY_TIMEOUT:-90}"     # seconds for a source canary to reach cdc-evt (stream live)
FN_CONSUMER_TIMEOUT="${FN_CONSUMER_TIMEOUT:-240}"  # seconds for the function pump's durable consumer to appear
CAPTURE_LABEL="app=evt-stream"
FN_CONSUMER_NAME="fn-evt-fn"               # durable consumer the pump holds on cdc-evt (fn-<function>)
EXIT_INCONCLUSIVE=42

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"

# Teardown: the source + Stream via the shared helper (it also returns the cdc-evt JetStream stream,
# which drops the fn-evt-fn consumer with it), plus the Function claim (Crossplane GC's its Knative
# Service + pump ConfigMap/Deployment). Delete the Function first so the pump stops before the stream.
teardown_stream_function() {
  kubectl -n "$NS" delete faultinjection --all --ignore-not-found >/dev/null 2>&1 || true
  if [ "${CHAOS_KEEP:-0}" != "1" ]; then
    log "tearing down kind: Function (evt-fn) + pump"
    kubectl -n "$NS" delete -f "$HERE/sandbox/function.yaml" --ignore-not-found >/dev/null 2>&1 || true
  fi
  sandbox_teardown_stream
}
trap teardown_stream_function EXIT

# Provision the source Database + kind: Stream (blocks until the capture Deployment is available).
sandbox_provision_stream

# Provision the kind: Function (its trigger renders the pump + durable consumer fn-evt-fn on cdc-evt).
# A failure to even create the claim (e.g. missing RBAC / Knative not installed) is a SETUP problem, not
# a data-loss verdict — record it INCONCLUSIVE rather than a false red.
log "starting the kind: Function (evt-fn, trigger.stream=evt → pump evt-fn-pump, consumer ${FN_CONSUMER_NAME})"
if ! kubectl apply -f "$HERE/sandbox/function.yaml"; then
  log "INCONCLUSIVE — could not create kind: Function evt-fn (RBAC / Knative not ready?). Not counting."
  exit "$EXIT_INCONCLUSIVE"
fi

# PRE-FLIGHT — refuse the fault if it could reach anything outside the sandbox.
log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-stream-capture-kill.yaml"

capture_uid() { kubectl -n "$NS" get pods -l "$CAPTURE_LABEL" -o jsonpath='{.items[0].metadata.uid}' 2>/dev/null || true; }

# True (non-empty output) once the function pump's durable consumer exists on cdc-evt. Reads
# `nats consumer info` for the consumer name — the same nats-box pattern the lib uses for counts.
fn_consumer_present() {
  kubectl -n nats run "nats-fncons-$$-$RANDOM" --rm -i --restart=Never --image=natsio/nats-box:latest -- \
    sh -c "nats --server=nats://nats.nats.svc:4222 consumer info cdc-evt ${FN_CONSUMER_NAME} --json 2>/dev/null | grep -oE '${FN_CONSUMER_NAME}' | head -1" 2>/dev/null \
    | grep -oE "${FN_CONSUMER_NAME}" | head -1
}

# Proof-of-fire part 1a: the STREAM must be LIVE before we disrupt it — a source row must reach cdc-evt.
# Otherwise the Stream isn't ready and nothing this run observes is trustworthy. (The canary is the only
# row inserted pre-fault, so cdc-evt >= 1 == delivered.)
log "proof-of-fire: confirming a source row reaches cdc-evt BEFORE the fault (stream live)"
kubectl -n "$NS" exec evt-src-0 -- psql -U app -d app -c \
  "INSERT INTO public.events(id,val) VALUES ('canary','alive') ON CONFLICT (id) DO UPDATE SET val='alive';" >/dev/null 2>&1 || true
live=0
for _ in $(seq 1 $(( CANARY_TIMEOUT / 6 )) ); do
  c="$(sandbox_stream_msg_count)"; c="${c:-0}"
  [ "$c" -ge 1 ] && { live=1; break; }
  sleep 6
done
if [ "$live" != 1 ]; then
  log "INCONCLUSIVE — canary never reached cdc-evt within ${CANARY_TIMEOUT}s (Stream not ready). Not counting."
  kubectl -n "$NS" get stream,deploy,pods -o wide 2>/dev/null | grep -iE 'evt|NAME' || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — the Stream is live (source → cdc-evt confirmed)."

# Proof-of-fire part 1b: the FUNCTION end of the chain must be wired — the pump's durable consumer
# fn-evt-fn must EXIST on cdc-evt. Without it, the far-end ack count the oracle reads is meaningless
# (the pump never attached), so a run can't be trusted → INCONCLUSIVE, not a false red.
log "proof-of-fire: waiting for the function pump's durable consumer ${FN_CONSUMER_NAME} on cdc-evt"
consumer_ready=0
for _ in $(seq 1 $(( FN_CONSUMER_TIMEOUT / 6 )) ); do
  [ -n "$(fn_consumer_present)" ] && { consumer_ready=1; break; }
  sleep 6
done
if [ "$consumer_ready" != 1 ]; then
  log "INCONCLUSIVE — pump consumer ${FN_CONSUMER_NAME} never appeared on cdc-evt within ${FN_CONSUMER_TIMEOUT}s (Function not wired). Not counting."
  kubectl -n "$NS" get function,deploy,pods -o wide 2>/dev/null | grep -iE 'evt-fn|NAME' || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — the Function is wired (pump consumer ${FN_CONSUMER_NAME} present on cdc-evt)."

# Delegate the VERDICT to the SINGULAR engine: the Go stream-function-noloss adapter (recover mode)
# records the pre-fault capture identity + commits canary + N distinct single-row changes on the source
# (Drive), waits for the capture kill to LAND and the whole chain to DRAIN (SteadyState requires the
# capture pod replaced AND the function's ack count stopped changing), then asserts the drained
# function-ack count covers every acknowledged change (Reconcile — at-least-once, so duplicates are
# fine; only a change that never reaches the function is a red). This scenario owns provisioning +
# firing the fault + the INCONCLUSIVE gates; the engine owns the verdict.
#
# Recover pattern (like stream-no-loss): the Go test runs in the BACKGROUND so Drive records the
# pre-fault capture pod identity and commits the source changes BEFORE we inject the capture kill; then
# the scenario fires the fault + proves-fire; then we wait the go test for the verdict.
REPO="$(cd "$HERE/.." && pwd)"
# CONV_TIMEOUT must cover STREAM_TIMEOUT: end-to-end recovery is deliberately slow (~40s Debezium JVM
# start + a logical-slot connection that must time out + the pump's ack_wait redelivery + the function
# cold-start from scale-to-zero), so a short budget would t.Fatalf a slow-but-lossless drain as a false
# red. The oracle's floor is 420; STREAM_TIMEOUT defaults to 480.
export CHAOS_SANDBOX_NS="$NS" CAPTURE_LABEL="$CAPTURE_LABEL" STREAM_SRC_POD="evt-src-0"
export STREAM_NATS_URL="${STREAM_NATS_URL:-nats://nats.nats.svc:4222}" STREAM_NAME="${STREAM_NAME:-cdc-evt}"
export FN_CONSUMER="${FN_CONSUMER:-$FN_CONSUMER_NAME}"
export STREAM_ROWS="$N"
export CONV_TIMEOUT="$STREAM_TIMEOUT"

log "driving source changes + judging end-to-end no-loss delivery to the function via the singular recover engine (budget ${CONV_TIMEOUT}s)"
( cd "$REPO/apply-sink" && go test -tags convergence -run '^TestStreamFunctionNoLoss$' -timeout 20m -count=1 ./... ) &
GOTEST=$!
sleep "${DRIVE_SETTLE:-6}"   # let Drive record the capture pod identity + commit the source changes BEFORE the kill

# Kill the capture — the committed changes must survive to the stream AND on to the function once the
# capture resumes from its durable offset and the pump redelivers. (At-least-once: dups fine, only a
# change that never reaches the function is a red.)
BEFORE="$(capture_uid)"
log "injecting the capture kill"
kubectl apply -f "$HERE/sandbox/fault-stream-capture-kill.yaml"

# Proof-of-fire part 2: the capture pod must actually be replaced — else the kill didn't land →
# INCONCLUSIVE (not a false red from the adapter grading a disruption that never happened).
replaced=0
for _ in $(seq 1 30); do
  a="$(capture_uid)"
  [ -n "$a" ] && [ "$a" != "$BEFORE" ] && { replaced=1; break; }
  sleep 2
done
if [ "$replaced" != 1 ]; then
  log "INCONCLUSIVE — capture pod was not replaced; the kill didn't land. The oracle won't bless a fault that didn't fire."
  kubectl -n "$NS" get faultinjection,podchaos,pods -l "$CAPTURE_LABEL" -o wide 2>/dev/null || true
  kill "$GOTEST" >/dev/null 2>&1 || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — capture killed and replaced; the adapter judges every committed change survives to the function."

# The adapter drains the whole chain through the capture restart; its exit code IS the verdict.
if wait "$GOTEST"; then
  log "PASS — the function acked every acknowledged change end to end after the capture kill (durable offset held, pump redelivered, no dropped events; dups OK per at-least-once) (verdict: singular recover engine)."
  exit 0
fi
log "FAIL — the function LOST acknowledged changes after the capture kill (DROPPED somewhere in the chain — release blocker)."
kubectl -n "$NS" get stream,function,faultinjection,pods -o wide 2>/dev/null | grep -iE 'evt|NAME' || true
exit 1
