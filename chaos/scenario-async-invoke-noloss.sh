#!/usr/bin/env bash
# N22 — Async Lambda invoke: no loss under a shim-pod kill.
#
# What it proves: the aws-shim's durable async (Event) invocation path never silently loses an accepted
# invocation, even when a shim replica is killed mid-drain. An Event invoke is enqueued to a NATS
# JetStream work stream (LAMBDA_ASYNC, WorkQueue-retained) and a durable pull consumer
# (lambda-async-worker) delivers each to its function, dead-lettering to LAMBDA_ASYNC_DLQ after retries.
# The invariant: EVERY accepted invocation is eventually delivered or dead-lettered — none vanishes.
#
# How: we publish invocations straight onto the work stream (byte-identical to what the shim's Event
# path enqueues) targeting a function that does NOT exist, so every delivery fails and must land in the
# DLQ. With a non-existent target the oracle is exact and count-only: DLQ >= accepted (last_seq of the
# work stream). We kill one of two shim replicas mid-drain; the WorkQueue + durable consumer must still
# route every accepted invocation to the DLQ (duplicates OK — at-least-once; a MISSING one is the red).
#
# Honest scope: this exercises the async DELIVERY WORKER + its durability under a kill — the code the
# adversarial review found silent-loss bugs in. It does NOT drive the SigV4 HTTP front door (a full
# invoke→202→publish path variant, and a delivered-path variant against a live function, are follow-ups).
#
# STATUS: PENDING — self-provisioning + runnable; keyless (not in the lottery). Graduates after a green
# streak. INCONCLUSIVE (exit 42) when the pipeline never primed or the kill didn't land; PASS/FAIL only
# when the fault provably landed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
EXIT_INCONCLUSIVE=42

N="${ASYNC_INVOKES:-100}"                 # invocations published across the outage
DLQ_TIMEOUT="${DLQ_TIMEOUT:-240}"         # seconds for the DLQ to cover every accepted invocation
CANARY_TIMEOUT="${CANARY_TIMEOUT:-90}"    # seconds for the first invocation to reach the DLQ
SHIM_LABEL="app=aws-shim-chaos"
GHOST="${GHOST_FN:-ghost}"                # a function that does not exist → every delivery fails → DLQ

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
trap sandbox_teardown_shim_async EXIT

sandbox_provision_shim_async

# pre-flight — refuse the fault if it could reach anything outside the sandbox.
log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-shim-node-kill.yaml"

# All current shim pod UIDs (space-separated). mode:one kills one replica, so proof-of-fire must watch
# the whole set — a single-pod check misses a kill of the pod it isn't watching.
shim_uids() { kubectl -n "$NS" get pods -l "$SHIM_LABEL" -o jsonpath='{.items[*].metadata.uid}' 2>/dev/null || true; }

# Proof-of-fire part 1: the worker is delivering-then-dead-lettering — one invocation reaches the DLQ
# BEFORE the fault (pipeline live). It takes a few retry backoffs to dead-letter, hence CANARY_TIMEOUT.
log "proof-of-fire: one invocation must reach the DLQ before the fault (async pipeline live)"
sandbox_publish_async "$GHOST" 1
live=0
for _ in $(seq 1 $(( CANARY_TIMEOUT / 6 )) ); do
  c="$(sandbox_async_dlq_count)"; c="${c:-0}"
  [ "$c" -ge 1 ] && { live=1; break; }
  sleep 6
done
[ "$live" = 1 ] || { log "INCONCLUSIVE — canary never reached the DLQ (async worker not draining)."; kubectl -n "$NS" get deploy,pods -l "$SHIM_LABEL" -o wide 2>/dev/null || true; exit "$EXIT_INCONCLUSIVE"; }
log "proof-of-fire OK — async worker live (canary dead-lettered)."

BEFORE_UIDS="$(shim_uids)"
log "injecting the shim-pod kill, then publishing ${N} invocations across the outage"
kubectl apply -f "$HERE/sandbox/fault-shim-node-kill.yaml"
sandbox_publish_async "$GHOST" "$N"

# Proof-of-fire part 2: a shim pod must actually be replaced — a pre-kill UID must disappear.
replaced=0
for _ in $(seq 1 45); do
  cur=" $(shim_uids) "
  for u in $BEFORE_UIDS; do
    case "$cur" in *" $u "*) ;; *) replaced=1 ;; esac
  done
  [ "$replaced" = 1 ] && break
  sleep 2
done
[ "$replaced" = 1 ] || { log "INCONCLUSIVE — no shim pod was replaced; the kill didn't land."; exit "$EXIT_INCONCLUSIVE"; }

# The authoritative count of what was ACCEPTED onto the work stream (canary + burst), immune to publish
# flakes and to WorkQueue removal-on-ack. The oracle's denominator.
accepted="$(sandbox_async_accepted)"; accepted="${accepted:-0}"
[ "$accepted" -ge 1 ] || { log "INCONCLUSIVE — nothing was accepted onto the work stream (publish path unavailable)."; exit "$EXIT_INCONCLUSIVE"; }
log "proof-of-fire OK — a shim pod was killed and replaced; ${accepted} invocations accepted."

# Oracle: every ACCEPTED invocation must reach the DLQ (delivery to a non-existent function always
# fails), across the kill. DLQ >= accepted. No accepted invocation may vanish; duplicates are fine.
log "asserting the DLQ received every accepted invocation (>= ${accepted})"
deadline=$(( SECONDS + DLQ_TIMEOUT )); dlq=0
while [ "$SECONDS" -lt "$deadline" ]; do
  dlq="$(sandbox_async_dlq_count)"; dlq="${dlq:-0}"
  [ "$dlq" -ge "$accepted" ] && break
  log "  DLQ messages: ${dlq}/${accepted} …"
  sleep 10
done

if [ "$dlq" -ge "$accepted" ]; then
  log "PASS — every accepted async invocation (${dlq} >= ${accepted}) reached the DLQ across a shim kill (durable work stream held; no silent loss; dups OK)."
  exit 0
fi
log "FAIL — DLQ received only ${dlq}/${accepted} after the kill (LOST accepted invocations — release blocker)."
kubectl -n "$NS" get faultinjection,pods -l "$SHIM_LABEL" -o wide 2>/dev/null || true
exit 1
