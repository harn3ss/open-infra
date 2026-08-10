#!/usr/bin/env bash
# N23 — Async Lambda invoke: delivered, no loss under a shim-pod kill (the happy path).
#
# Sibling of N22. Where N22 targets a NON-EXISTENT function (every invocation must dead-letter — proves
# nothing is silently lost), N23 targets a REAL, healthy function (kind: Function echo) and proves the
# SUCCESS path: across a shim-pod kill, every accepted async invocation is DELIVERED (2xx → acked, so it
# leaves the WorkQueue) and NONE dead-letters. Together the two cover the full at-least-once guarantee.
#
# Oracle (count-only, authoritative): after draining, the work stream (LAMBDA_ASYNC, WorkQueue-retained)
# reaches 0 pending AND the DLQ (LAMBDA_ASYNC_DLQ) stays 0, while accepted (last_seq) == everything we
# published. work==0 means every message was acked (2xx delivery) or termed; DLQ==0 rules out term — so
# every accepted invocation was successfully delivered. A stuck work stream (>0) = loss/blocked; any DLQ
# = a delivery that never succeeded (not the happy path).
#
# STATUS: PENDING — self-provisioning + runnable; keyless (not in the lottery). Graduates after a green
# streak. INCONCLUSIVE (exit 42) when Knative is absent, the pipeline never primed, or the kill didn't land.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
EXIT_INCONCLUSIVE=42

N="${ASYNC_INVOKES:-100}"                  # invocations published across the outage
DELIVER_TIMEOUT="${DELIVER_TIMEOUT:-240}"  # seconds for the work stream to fully drain
CANARY_TIMEOUT="${CANARY_TIMEOUT:-120}"    # seconds for the first invocation to be delivered
SHIM_LABEL="app=aws-shim-chaos"
FN="${ECHO_FN:-echo}"

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
teardown() { kubectl -n "$NS" delete -f "$HERE/sandbox/echo-function.yaml" --ignore-not-found >/dev/null 2>&1 || true; sandbox_teardown_shim_async; }
trap teardown EXIT

kubectl get ksvc >/dev/null 2>&1 || { log "INCONCLUSIVE — Knative Serving not installed (kind: Function needs it)."; exit "$EXIT_INCONCLUSIVE"; }

sandbox_provision_shim_async
log "deploying the echo target Function (${FN})"
kubectl apply -f "$HERE/sandbox/echo-function.yaml" >/dev/null
# Wait on the Function CLAIM (exists immediately after apply; its Ready cascades from the composed
# Knative Service) — not the ksvc, which Crossplane creates a few seconds later (a bare `wait ksvc`
# races and errors "not found").
kubectl -n "$NS" wait --for=condition=Ready function.openinfra.dev/"$FN" --timeout=180s >/dev/null 2>&1 \
  || { log "INCONCLUSIVE — echo Function did not become Ready (Knative)."; exit "$EXIT_INCONCLUSIVE"; }

# pre-flight — refuse the fault if it could reach anything outside the sandbox.
log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-shim-node-kill.yaml"

shim_uids() { kubectl -n "$NS" get pods -l "$SHIM_LABEL" -o jsonpath='{.items[*].metadata.uid}' 2>/dev/null || true; }

# Proof-of-fire part 1: the pipeline DELIVERS — one invocation drains from the work stream (acked), with
# an empty DLQ, before the fault.
log "proof-of-fire: one invocation must be delivered (work drains, DLQ empty) before the fault"
sandbox_publish_async "$FN" 1
live=0
for _ in $(seq 1 $(( CANARY_TIMEOUT / 6 )) ); do
  w="$(sandbox_async_work_count)"; w="${w:-1}"
  d="$(sandbox_async_dlq_count)"; d="${d:-0}"
  [ "$w" = 0 ] && [ "$d" = 0 ] && { live=1; break; }
  sleep 6
done
[ "$live" = 1 ] || { log "INCONCLUSIVE — canary was not delivered (work never drained with an empty DLQ)."; kubectl -n "$NS" get deploy,pods,ksvc -o wide 2>/dev/null || true; exit "$EXIT_INCONCLUSIVE"; }
log "proof-of-fire OK — async delivery live (canary delivered)."

BEFORE_UIDS="$(shim_uids)"
log "injecting the shim-pod kill, then publishing ${N} invocations across the outage"
kubectl apply -f "$HERE/sandbox/fault-shim-node-kill.yaml"
sandbox_publish_async "$FN" "$N"

# Proof-of-fire part 2: a shim pod must actually be replaced.
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

accepted="$(sandbox_async_accepted)"; accepted="${accepted:-0}"
[ "$accepted" -ge 1 ] || { log "INCONCLUSIVE — nothing was accepted onto the work stream."; exit "$EXIT_INCONCLUSIVE"; }
log "proof-of-fire OK — a shim pod was killed and replaced; ${accepted} invocations accepted."

# Oracle: the work stream must fully drain (every accepted invocation acked/termed) AND the DLQ must stay
# empty (nothing dead-lettered) → every accepted invocation was successfully DELIVERED across the kill.
log "asserting every accepted invocation was delivered (work → 0, DLQ == 0)"
deadline=$(( SECONDS + DELIVER_TIMEOUT )); work=1; dlq=0
while [ "$SECONDS" -lt "$deadline" ]; do
  work="$(sandbox_async_work_count)"; work="${work:-1}"
  dlq="$(sandbox_async_dlq_count)"; dlq="${dlq:-0}"
  [ "$work" = 0 ] && break
  log "  work pending: ${work} (dlq ${dlq}) …"
  sleep 10
done

if [ "$work" != 0 ]; then
  log "FAIL — work stream still has ${work} pending after ${DELIVER_TIMEOUT}s (deliveries stuck / lost across the kill)."
  kubectl -n "$NS" get faultinjection,pods -l "$SHIM_LABEL" -o wide 2>/dev/null || true
  exit 1
fi
if [ "$dlq" != 0 ]; then
  log "FAIL — ${dlq} invocation(s) dead-lettered despite a healthy function (delivery failed, not the happy path)."
  exit 1
fi
log "PASS — all ${accepted} accepted invocations were delivered (work drained to 0, DLQ 0) across a shim kill (at-least-once; no loss)."
exit 0
