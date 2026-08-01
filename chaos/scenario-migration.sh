#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario: MIGRATION FIDELITY UNDER FAULT (the #4 zero-downtime-migration
# chain; see docs/chaos-oracle.md). This is the first NON-CONVERGENCE oracle — where scenarios 1-6
# ask "does the multi-master mesh re-agree?", this asks the asymmetric question a real migration
# turns on: "does the one-way load lose nothing when the pipeline is disrupted mid-cutover?"
#
# Chain (4 resource types): a source Database (mig-src) + a target Database (mig-tgt) + a
# kind: Migration (Debezium → NATS → apply-sink) + a FaultInjection. We prove the pipeline is live
# (a source row reaches the target), then kill the apply-sink WHILE the fidelity harness is driving
# source writes, and assert the target catches back up to EVERY acknowledged source row — the
# migration adapter (apply-sink/migration_test.go) is the judge. A dropped offset or lost CDC batch
# shows up as a missing/miscompared row and fails the oracle.
#
# Proof-of-fire is the guard against a false green: the apply-sink pod must actually be replaced
# (kill landed). If it isn't, the run is INCONCLUSIVE, not green — the oracle refuses to bless a
# fault that didn't fire. Safety (design §3) is independent: sandbox-scoped RBAC, ResourceQuota,
# low PriorityClass, the pre-flight guard below, and the fault's own pod-scoped selector.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"

# The poll budget must exceed the apply-sink restart + drain + settle. A pod-kill recovers in
# ~15-30s; give the target ample time to catch up before calling it a lost-write red.
export CONV_TIMEOUT="${CONV_TIMEOUT:-300}"
export CONV_SETTLE="${CONV_SETTLE:-15}"
export MIG_ROWS="${MIG_ROWS:-300}"
export MIG_UPDATES="${MIG_UPDATES:-40}"
export MIG_CREATE="${MIG_CREATE:-false}"   # sandbox_provision_migration pre-creates mig_test

APPLYSINK_LABEL="app=mig-migration-applysink"
CANARY_TIMEOUT="${CANARY_TIMEOUT:-90}"     # seconds for a source canary row to reach the target
EXIT_INCONCLUSIVE=42                        # neither red nor green (nightly maps this to a warning)

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
teardown() { sandbox_teardown_migration; }
trap teardown EXIT

sandbox_provision_migration
sandbox_migration_endpoints

# PRE-FLIGHT — refuse the fault if it could reach anything outside the sandbox.
log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-migration-applysink-kill.yaml"

tgt_count() { kubectl -n "$NS" exec mig-tgt-0 -- psql -U app -d app -tAc "SELECT count(*) FROM public.mig_test" 2>/dev/null | tr -d '[:space:]'; }
applysink_uid() { kubectl -n "$NS" get pods -l "$APPLYSINK_LABEL" -o jsonpath='{.items[0].metadata.uid}' 2>/dev/null || true; }

# Proof-of-fire (pillar 1), part 1: the pipeline must be LIVE before we disrupt it — a source write
# must reach the target. Otherwise the migration isn't ready and nothing this run observes is trustworthy.
log "proof-of-fire: confirming a source row reaches the target BEFORE the fault (pipeline live)"
kubectl -n "$NS" exec mig-src-0 -- psql -U app -d app -c \
  "INSERT INTO public.mig_test(id,val) VALUES ('canary','alive') ON CONFLICT (id) DO UPDATE SET val='alive';" >/dev/null 2>&1 || true
live=0
for _ in $(seq 1 "$CANARY_TIMEOUT"); do
  c="$(tgt_count)"; c="${c:-0}"
  [ "$c" -ge 1 ] && { live=1; break; }
  sleep 1
done
if [ "$live" != 1 ]; then
  log "INCONCLUSIVE — canary never reached the target within ${CANARY_TIMEOUT}s (pipeline not ready). Not counting."
  kubectl -n "$NS" get migration,deploy,pods -o wide || true
  exit "$EXIT_INCONCLUSIVE"
fi
# Clean the canary so the harness starts from a table it fully owns (its ledger == the table).
kubectl -n "$NS" exec mig-src-0 -- psql -U app -d app -c "TRUNCATE public.mig_test;" >/dev/null 2>&1 || true
sleep 3
log "proof-of-fire OK — pipeline is live (source → target confirmed)."

# Run the fidelity harness in the BACKGROUND so we can kill the apply-sink WHILE it drives source
# writes — the migration analogue of "run the convergence harness through the fault". The harness
# drives inserts+updates on the source, then polls the target until it reflects every ack.
log "starting the migration fidelity harness (driving source writes)"
HARNESS_LOG="$(mktemp)"
( cd "$REPO/apply-sink" && go test -tags convergence -run TestMigrationFidelity -timeout 20m -v ./... ) >"$HARNESS_LOG" 2>&1 &
HARNESS_PID=$!

# Give the driver a moment to start streaming changes, then kill the apply-sink mid-stream so
# events are produced into NATS while the sink is absent (the durable-offset resume is what's tested).
sleep 8
BEFORE="$(applysink_uid)"
log "injecting the apply-sink kill mid-stream (pod-scoped, one-shot)"
kubectl apply -f "$HERE/sandbox/fault-migration-applysink-kill.yaml"

# Proof-of-fire (pillar 1), part 2: the apply-sink pod must actually be replaced.
replaced=0
for _ in $(seq 1 30); do
  a="$(applysink_uid)"
  [ -n "$a" ] && [ "$a" != "$BEFORE" ] && { replaced=1; break; }
  sleep 2
done
if [ "$replaced" != 1 ]; then
  log "INCONCLUSIVE — apply-sink was not replaced; the kill didn't land. The oracle won't bless a fault that didn't fire."
  kubectl -n "$NS" get faultinjection,podchaos,pods -o wide || true
  kill "$HARNESS_PID" >/dev/null 2>&1 || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — apply-sink killed mid-stream and replaced (${BEFORE:0:8}… → new)."

log "waiting for the fidelity harness to judge (target must catch up to every acked source row)"
if wait "$HARNESS_PID"; then
  grep -E 'STEADY|CONVERGED|PASS|ok ' "$HARNESS_LOG" | tail -6 || tail -6 "$HARNESS_LOG"
  log "PASS — target stayed byte-faithful to the source across the apply-sink kill (zero lost, one-way fidelity held)."
  rm -f "$HARNESS_LOG"
  exit 0
fi

log "FAIL — target did NOT catch up to the source within CONV_TIMEOUT after the apply-sink kill (lost/miscompared rows — release blocker)."
tail -20 "$HARNESS_LOG" || true
kubectl -n "$NS" get migration,faultinjection,pods -o wide || true
rm -f "$HARNESS_LOG"
exit 1
