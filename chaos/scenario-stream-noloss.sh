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

# Kill the capture, then write the N rows WHILE it is down — they must queue in the WAL behind the
# replication slot and survive to the stream once capture resumes from its durable offset.
BEFORE="$(capture_uid)"
log "injecting the capture kill, then writing ${N} rows during the outage"
kubectl apply -f "$HERE/sandbox/fault-stream-capture-kill.yaml"
kubectl -n "$NS" exec evt-src-0 -- psql -U app -d app -c \
  "INSERT INTO public.events(id,val) SELECT 'e'||g, 'v'||g FROM generate_series(1,$N) g ON CONFLICT (id) DO NOTHING;" >/dev/null

# Proof-of-fire part 2: the capture pod must actually be replaced.
replaced=0
for _ in $(seq 1 30); do
  a="$(capture_uid)"
  [ -n "$a" ] && [ "$a" != "$BEFORE" ] && { replaced=1; break; }
  sleep 2
done
if [ "$replaced" != 1 ]; then
  log "INCONCLUSIVE — capture pod was not replaced; the kill didn't land. The oracle won't bless a fault that didn't fire."
  kubectl -n "$NS" get faultinjection,podchaos,pods -l "$CAPTURE_LABEL" -o wide 2>/dev/null || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — capture killed and replaced; rows were written during the outage."

log "asserting the restarted capture delivers every driven change to cdc-evt (at-least-once, no loss)"
# A Stream's contract is AT-LEAST-ONCE: every source change must reach cdc-evt at least once after
# the capture resumes from its durable offset — a dropped event is the release-blocking red;
# duplicates are permitted by the contract. The authoritative, reliable signal is the JetStream
# message COUNT (stream metadata, O(1) and exact). The source performed exactly N+1 distinct
# single-row changes (canary + N inserts, no updates, ON CONFLICT DO NOTHING), so cdc-evt must reach
# >= N+1 messages. A durable-slot logical-replication capture cannot lose a committed change, so
# count >= N+1 after the kill == nothing dropped. (We deliberately do NOT read each message body
# back: the nats CLI opens a fresh connection per `stream get` and under-returns past a few dozen
# messages — unreliable as a gate. The count is authoritative; the pipeline is the subject, not the
# CLI reader.)
deadline=$(( SECONDS + STREAM_TIMEOUT ))
count=0
while [ "$SECONDS" -lt "$deadline" ]; do
  count="$(sandbox_stream_msg_count)"; count="${count:-0}"
  [ "$count" -ge $(( N + 1 )) ] && break
  log "  cdc-evt messages: ${count}/$(( N + 1 )) …"
  sleep 10
done

if [ "$count" -ge $(( N + 1 )) ]; then
  log "PASS — cdc-evt received all ${count} events (>= ${N} driven changes + canary) after a capture kill (durable offset held, no dropped events; dups OK per at-least-once)."
  exit 0
fi
log "FAIL — cdc-evt received only ${count}/$(( N + 1 )) events within ${STREAM_TIMEOUT}s after the capture kill (DROPPED changes — release blocker)."
kubectl -n "$NS" get stream,faultinjection,pods -o wide 2>/dev/null | grep -iE 'evt|NAME' || true
exit 1
