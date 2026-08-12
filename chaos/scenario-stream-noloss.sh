#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario: STREAM NO-LOSS UNDER CAPTURE KILL (the stream chain; see
# docs/chaos-oracle.md). Recover-mode oracle on the STREAMING plane (the "Kinesis" path) — distinct
# from migration, which lands in a target DB via apply-sink; here the guarantee under test is the
# JetStream DELIVERY itself: every acknowledged source change reaches the durable stream.
#
# Chain (3 resource types): a source Database (evt-src) + a kind: Stream (Debezium → JetStream
# cdc-evt) + a FaultInjection. We prove the pipeline is live, then kill the capture engine and write
# rows WHILE it is down (they queue in the Postgres WAL behind the replication slot), and assert the
# restarted capture resumes from its durable offset and publishes EVERY row to the stream — no loss.
# At-least-once, so duplicates are fine; only a MISSING key is a red.
#
# Oracle: after recovery, the distinct keys on cdc-evt must cover every driven key. Proof-of-fire:
# the capture pod must actually be replaced. Conservation of acknowledged work, streaming edition.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"

N="${STREAM_ROWS:-150}"                    # rows driven during the capture outage
# The capture resume is deliberately slow to survive: a pod-kill leaves the Postgres logical slot's
# old consumer connection lingering (single-consumer) until it times out, and Debezium Server's JVM
# start is ~40s — so give the stream a generous budget to re-attach and drain the WAL backlog.
STREAM_TIMEOUT="${STREAM_TIMEOUT:-360}"    # seconds for the stream to cover every key after recovery
CANARY_TIMEOUT="${CANARY_TIMEOUT:-90}"     # seconds for a source canary to reach the stream
CAPTURE_LABEL="app=evt-stream"
EXIT_INCONCLUSIVE=42

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
trap sandbox_teardown_stream EXIT

sandbox_provision_stream

# PRE-FLIGHT — refuse the fault if it could reach anything outside the sandbox.
log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-stream-capture-kill.yaml"

capture_uid() { kubectl -n "$NS" get pods -l "$CAPTURE_LABEL" -o jsonpath='{.items[0].metadata.uid}' 2>/dev/null || true; }

# Proof-of-fire part 1: the pipeline must be LIVE before we disrupt it — a source row must reach the
# stream. Otherwise the Stream isn't ready and nothing this run observes is trustworthy. (A cheap
# message-count check: the canary is the only row inserted pre-fault, so cdc-evt >= 1 == delivered.)
log "proof-of-fire: confirming a source row reaches cdc-evt BEFORE the fault (pipeline live)"
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

# Delegate the VERDICT to the SINGULAR engine: the Go stream-no-loss adapter (recover mode) records the
# pre-fault capture identity + commits canary + N distinct single-row changes on the source (Drive), waits
# for the capture kill to LAND and the stream to DRAIN (SteadyState requires the capture pod replaced AND
# the JetStream message count stopped changing), then asserts the drained stream covers every acknowledged
# change (Reconcile — at-least-once, so duplicates are fine; only a MISSING change is a red). This scenario
# owns provisioning + firing the fault + the INCONCLUSIVE gates; the engine owns the verdict (replacing the
# old bash row-writer + sampler/tally/count-readback PASS/FAIL fork).
#
# Recover pattern (like volume-durable): the Go test runs in the BACKGROUND so Drive records the pre-fault
# capture pod identity and commits the source changes BEFORE we inject the capture kill; then the scenario
# fires the fault + proves-fire; then we wait the go test for the verdict.
REPO="$(cd "$HERE/.." && pwd)"
# CONV_TIMEOUT must cover STREAM_TIMEOUT: a healthy Debezium resume is deliberately slow (~40s JVM start +
# a logical-slot connection that must time out), so a short budget would t.Fatalf a slow-but-lossless drain
# as a false red.
export CHAOS_SANDBOX_NS="$NS" CAPTURE_LABEL="$CAPTURE_LABEL" STREAM_SRC_POD="evt-src-0"
export STREAM_NATS_URL="${STREAM_NATS_URL:-nats://nats.nats.svc:4222}" STREAM_NAME="${STREAM_NAME:-cdc-evt}"
export STREAM_ROWS="$N"
export CONV_TIMEOUT="$STREAM_TIMEOUT"

log "driving source changes + judging no-loss delivery via the singular recover engine (budget ${CONV_TIMEOUT}s)"
( cd "$REPO/apply-sink" && go test -tags convergence -run '^TestStreamNoLoss$' -timeout 15m -count=1 ./... ) &
GOTEST=$!
sleep "${DRIVE_SETTLE:-6}"   # let Drive record the capture pod identity + commit the source changes BEFORE the kill

# Kill the capture — the committed changes must survive to the stream once capture resumes from its durable
# offset. (At-least-once: duplicates are fine, only a dropped change is a red.)
BEFORE="$(capture_uid)"
log "injecting the capture kill"
kubectl apply -f "$HERE/sandbox/fault-stream-capture-kill.yaml"

# Proof-of-fire part 2: the capture pod must actually be replaced — else the kill didn't land → INCONCLUSIVE
# (not a false red from the adapter grading a disruption that never happened).
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
log "proof-of-fire OK — capture killed and replaced; the adapter judges every committed change survives to cdc-evt."

# The adapter drains through the capture restart; its exit code IS the verdict.
if wait "$GOTEST"; then
  log "PASS — cdc-evt covered every acknowledged change after the capture kill (durable offset held, no dropped events; dups OK per at-least-once) (verdict: singular recover engine)."
  exit 0
fi
log "FAIL — cdc-evt lost acknowledged changes after the capture kill (DROPPED changes — release blocker)."
kubectl -n "$NS" get stream,faultinjection,pods -o wide 2>/dev/null | grep -iE 'evt|NAME' || true
exit 1
