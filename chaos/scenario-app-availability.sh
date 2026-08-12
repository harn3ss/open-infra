#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario: APP AVAILABILITY UNDER REPLICA LOSS (the availability chain; see
# docs/chaos-oracle.md). This is the framework's SECOND oracle mode — "tolerate", a continuous SLO
# measured DURING the fault, distinct from the conservation mode (convergence/migration) that
# checks state after healing. The question is the one a real web workload turns on: "does the
# service keep serving when an instance dies?"
#
# Chain (4 resource types): an HA Application (traefik/whoami, ≥2 replicas behind a Service) + its
# managed Database (Postgres) + a SecurityGroup + a FaultInjection. We sample the app's HTTP
# endpoint continuously from an IN-SANDBOX prober (the app's NetworkPolicy denies off-cluster
# ingress — the prober must be in-namespace, which is itself the fence working), kill ONE replica
# mid-traffic, and assert availability stays within SLO across the whole window: the survivor keeps
# serving while the Deployment restarts the killed pod. If success rate drops below the SLO the app
# tier is not actually HA (SPOF / missing PDB / endpoints misbehaving) — a real red.
#
# Proof-of-fire guards a false green: an app pod must actually be replaced. If not, INCONCLUSIVE.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"

SAMPLES="${AVAIL_SAMPLES:-120}"                 # number of probes across the window
INTERVAL="${AVAIL_INTERVAL:-0.5}"               # seconds between probes (~60s window at defaults)
MIN_SUCCESS="${AVAIL_MIN_SUCCESS:-90}"          # SLO: min success rate (percent) across the window
MAX_CONSEC_FAIL="${AVAIL_MAX_CONSEC_FAIL:-4}"   # SLO: max consecutive failures (endpoint-update lag)
INJECT_AFTER="${AVAIL_INJECT_AFTER:-8}"         # seconds into the window before killing a replica
APP_URL="http://web/"                            # in-namespace Service DNS (Service web:80)
EXIT_INCONCLUSIVE=42

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
trap sandbox_teardown_appavail EXIT

sandbox_provision_appavail

# PRE-FLIGHT — refuse the fault if it could reach anything outside the sandbox.
log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-app-replica-kill.yaml"

app_uids() { kubectl -n "$NS" get pods -l app.kubernetes.io/name=web -o jsonpath='{.items[*].metadata.uid}' 2>/dev/null; }
ready_replicas() { kubectl -n "$NS" get deploy web -o jsonpath='{.status.readyReplicas}' 2>/dev/null | tr -d '[:space:]'; }

# HA precondition: the fault is only meaningful with ≥2 ready replicas to survive it.
rr="$(ready_replicas)"; rr="${rr:-0}"
if [ "$rr" -lt 2 ]; then
  log "INCONCLUSIVE — app has only ${rr} ready replica(s); need ≥2 for a replica-loss availability test. Not counting."
  kubectl -n "$NS" get deploy web hpa/web pods -l app.kubernetes.io/name=web -o wide 2>/dev/null || true
  exit "$EXIT_INCONCLUSIVE"
fi

# Proof-of-fire part 1: the app must serve BEFORE the fault (and the in-ns prober must reach it —
# proves the SecurityGroup/netpol allow path). Otherwise nothing this run observes is trustworthy.
log "proof-of-fire: confirming the app serves 200 from the in-sandbox prober BEFORE the fault"
healthy=0
for _ in $(seq 1 10); do
  if kubectl -n "$NS" exec avail-prober -- curl -sf -m 2 -o /dev/null "$APP_URL" >/dev/null 2>&1; then healthy=1; break; fi
  sleep 2
done
if [ "$healthy" != 1 ]; then
  log "INCONCLUSIVE — app not reachable from the in-sandbox prober pre-fault (not ready / netpol path broken). Not counting."
  kubectl -n "$NS" get svc web netpol -o wide 2>/dev/null || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — app serves and the in-namespace allow path works."

# Start continuous sampling in the background (the prober loops N probes at INTERVAL, one OK/FAIL
# per line). The fault is injected partway through so the window straddles the disruption.
REPO="$(cd "$HERE/.." && pwd)"
# Delegate the VERDICT to the SINGULAR engine: the Go app-availability adapter (tolerate mode) samples
# the app continuously from the in-ns prober and runTolerate grades the SLO — success rate ≥ CHAOS_SLO
# AND no bad streak > CHAOS_MAX_STREAK. This scenario owns provisioning + firing the fault + the
# INCONCLUSIVE gate; the engine owns the verdict (replacing the old bash sampler/tally/PASS-FAIL fork).
export CHAOS_SANDBOX_NS="$NS" AVAIL_PROBER="avail-prober" APP_URL="$APP_URL"
export CHAOS_SLO="$(awk "BEGIN{printf \"%.4f\", ${MIN_SUCCESS}/100}")"
export CHAOS_MAX_STREAK="$MAX_CONSEC_FAIL"
export CONV_TIMEOUT="${AVAIL_WINDOW:-70}"
export PROBE_INTERVAL_MS="$(awk "BEGIN{printf \"%d\", ${INTERVAL}*1000}")"

log "sampling availability via the singular tolerate engine (window ${CONV_TIMEOUT}s @ ${INTERVAL}s; fault at ~${INJECT_AFTER}s)"
( cd "$REPO/apply-sink" && go test -tags convergence -run '^TestAppAvailability$' -timeout 15m -count=1 ./... ) &
GOTEST=$!

sleep "$INJECT_AFTER"
BEFORE="$(app_uids)"
log "injecting the replica kill (mode: one — one of ≥2 pods)"
kubectl apply -f "$HERE/sandbox/fault-app-replica-kill.yaml"

# Proof-of-fire: an app pod must actually be replaced — else the fault didn't fire → INCONCLUSIVE
# (not a false red from the adapter grading a disruption that never happened).
replaced=0
for _ in $(seq 1 30); do
  a="$(app_uids)"
  [ -n "$a" ] && [ "$a" != "$BEFORE" ] && { replaced=1; break; }
  sleep 2
done
if [ "$replaced" != 1 ]; then
  log "INCONCLUSIVE — no app pod was replaced; the kill didn't land. The oracle won't bless a fault that didn't fire."
  kubectl -n "$NS" get faultinjection,podchaos,pods -l app.kubernetes.io/name=web -o wide 2>/dev/null || true
  kill "$GOTEST" >/dev/null 2>&1 || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — an app replica was killed and replaced mid-traffic."

# The adapter samples through the disruption + recovery; its exit code IS the verdict.
if wait "$GOTEST"; then
  log "PASS — the Service stayed within SLO through the replica kill (verdict: singular tolerate engine)."
  exit 0
fi
log "FAIL — availability breached SLO during the replica kill — the app tier is not HA (release blocker)."
kubectl -n "$NS" get deploy web pods -l app.kubernetes.io/name=web -o wide 2>/dev/null || true
exit 1
