#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario 4x: SINK-KILL MID-DRAIN (target-selection axis; see
# docs/chaos-oracle.md). Scenario 3 kills an idle sink; this kills the sink while it is DRAINING
# A BACKLOG — the harder target state for the offset/ack machinery. We cut a→b, pile a large
# backlog into NATS (writes to pg-a that can't reach pg-b), heal, let the sink START draining,
# then kill it MID-DRAIN and assert it resumes from its durable NATS offset and delivers EVERY
# backlog row (zero lost). A sink that acks before applying would drop the in-flight batch here.
#
# Oracle: pg-b must reach exactly N rows after the mid-drain kill. Proof-of-fire is two-part —
# the cut actually built a backlog (pg-b behind), and the kill actually landed mid-drain
# (0 < pg-b < N when killed, pod replaced). If the drain finishes before we can catch it, that's
# INCONCLUSIVE, not green.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
N="${DRAIN_BACKLOG:-10000}"          # backlog rows piled onto pg-a behind the cut
DRAIN_TIMEOUT="${DRAIN_TIMEOUT:-240}" # seconds for pg-b to catch up to N after the mid-drain kill
SINK_LABEL="app=chaos-mesh-pg-repl-a-b-sink"
EXIT_INCONCLUSIVE=42

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
trap sandbox_teardown EXIT

sandbox_provision   # provisions members + mesh + mm-prep (triggers installed), conv_test empty

pgb() { kubectl -n "$NS" exec pg-b-0 -- psql -U app -d app -tAc "SELECT count(*) FROM conv_test" 2>/dev/null | tr -d '[:space:]'; }
pga() { kubectl -n "$NS" exec pg-a-0 -- psql -U app -d app -tAc "SELECT count(*) FROM conv_test" 2>/dev/null | tr -d '[:space:]'; }
sink_uid() { kubectl -n "$NS" get pods -l "$SINK_LABEL" -o jsonpath='{.items[0].metadata.uid}' 2>/dev/null || true; }

log "start clean"
for m in pg-a pg-b; do kubectl -n "$NS" exec "${m}-0" -- psql -U app -d app -c "TRUNCATE conv_test;" >/dev/null 2>&1 || true; done
sleep 3

log "cutting a→b so a backlog can pile up behind it"
kubectl apply -f "$HERE/sandbox/fault-partition.yaml"
fired=0; for _ in $(seq 1 6); do "$HERE/probe-partition.sh" down && { fired=1; break; }; sleep 3; done
[ "$fired" = 1 ] || { log "INCONCLUSIVE — cut never bit; can't stage a backlog."; exit "$EXIT_INCONCLUSIVE"; }

log "piling a ${N}-row backlog onto pg-a (queues in NATS; can't reach pg-b while cut)"
kubectl -n "$NS" exec pg-a-0 -- psql -U app -d app -c \
  "INSERT INTO conv_test(id,val) SELECT 'k'||g, 'v'||g FROM generate_series(1,$N) g;" >/dev/null
sleep 8
b_cut="$(pgb)"; a_cnt="$(pga)"
log "  after seeding under the cut: pg-a=$a_cnt pg-b=${b_cut:-0}"
if [ "${a_cnt:-0}" != "$N" ] || [ "${b_cut:-0}" -ge "$N" ]; then
  log "INCONCLUSIVE — backlog not staged (pg-a!=$N or pg-b already caught up). Not counting."
  exit "$EXIT_INCONCLUSIVE"
fi

log "healing the cut → the sink starts draining the backlog"
kubectl -n "$NS" delete -f "$HERE/sandbox/fault-partition.yaml" --ignore-not-found >/dev/null 2>&1 || true
BEFORE="$(sink_uid)"

log "watching for the drain to START, then killing the sink MID-DRAIN"
killed=0
for _ in $(seq 1 120); do
  c="$(pgb)"; c="${c:-0}"
  if [ "$c" -ge "$N" ]; then
    log "INCONCLUSIVE — backlog fully drained before we could kill mid-drain (drain too fast; raise DRAIN_BACKLOG)."
    exit "$EXIT_INCONCLUSIVE"
  fi
  if [ "$c" -gt 0 ]; then
    log "  drain in progress (pg-b=$c/$N) — killing the sink now"
    kubectl -n "$NS" delete pod -l "$SINK_LABEL" --grace-period=0 --force >/dev/null 2>&1 || true
    killed=1; break
  fi
  sleep 1
done
[ "$killed" = 1 ] || { log "INCONCLUSIVE — drain never started (nothing to interrupt)."; exit "$EXIT_INCONCLUSIVE"; }

# Proof-of-fire: the sink pod was actually replaced.
replaced=0
for _ in $(seq 1 20); do a="$(sink_uid)"; [ -n "$a" ] && [ "$a" != "$BEFORE" ] && { replaced=1; break; }; sleep 2; done
[ "$replaced" = 1 ] || { log "FAIL — sink was not replaced; the mid-drain kill didn't land."; exit 1; }
log "proof-of-fire OK — sink killed mid-drain and replaced (${BEFORE:0:8}… → new)."

log "asserting the restarted sink resumes from its offset and delivers ALL ${N} rows"
for _ in $(seq 1 "$DRAIN_TIMEOUT"); do
  c="$(pgb)"; c="${c:-0}"
  [ "$c" -ge "$N" ] && { log "PASS — pg-b reached $c/$N after a mid-drain sink kill (offset survived, zero lost)."; exit 0; }
  sleep 1
done
log "FAIL — pg-b only reached $(pgb)/$N within ${DRAIN_TIMEOUT}s after the mid-drain kill (lost/stalled backlog — release blocker)."
kubectl -n "$NS" get pods,faultinjection -o wide || true
exit 1
