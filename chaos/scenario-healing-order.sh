#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario 2x: HEALING ORDER (timing/overlap axis; see docs/chaos-oracle.md).
#
# Two overlapping faults on the a→b apply path — a network partition (sink↔B cut) AND the sink
# held down (pod-failure) — then HEAL them in a controlled order with a gap between. The mesh
# must reconverge byte-identical regardless of which fault clears first. This catches recovery
# bugs that a single fault can't: a sink that comes back INTO a still-partitioned network (or a
# network that heals while the sink is still down) must not drop its NATS consumer, lose its
# offset, or wedge a half-open connection. Red = release blocker.
#
# HEAL_ORDER (default the design's example, partition-first):
# partition-first : network restored, THEN the sink returns (sink recovers into a healthy net)
# sink-first : sink returns into a STILL-cut network, THEN the partition heals (harsher)
#
# Oracle: this is cut-class — divergence DURING the overlap is expected; convergence AFTER both
# heal is mandatory. Proof-of-fire fires BOTH faults independently (sequenced so each is witnessed).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
export CONV_TIMEOUT="${CONV_TIMEOUT:-360}"
export CONV_SETTLE="${CONV_SETTLE:-15}"
export CONV_CREATE="${CONV_CREATE:-false}"
export CONV_KEYS="${CONV_KEYS:-200}"
export CONV_CONFLICTS="${CONV_CONFLICTS:-20}"
HEAL_ORDER="${HEAL_ORDER:-partition-first}"
HEAL_GAP="${HEAL_GAP:-25}"          # seconds between healing the first fault and the second
OVERLAP_HOLD="${OVERLAP_HOLD:-20}"  # seconds both faults stay active before healing begins
EXIT_INCONCLUSIVE=42
SINK_SEL="app=chaos-mesh-pg-repl-a-b-sink"

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
cleanup() {
  kubectl -n "$NS" delete faultinjection mm-partition mm-sink-failure --ignore-not-found >/dev/null 2>&1 || true
  sandbox_teardown
}
trap cleanup EXIT

sandbox_provision
sandbox_conv_members

log "pre-flight guard (both faults)"
"$HERE/preflight.sh" "$HERE/sandbox/fault-partition.yaml"
"$HERE/preflight.sh" "$HERE/sandbox/fault-sink-failure.yaml"

# pod-failure swaps the sink container for a pause image WITHOUT flipping readiness (the sink
# Deployment has no readiness probe), so readyReplicas is a false signal. Witness the canonical
# Chaos Mesh injection condition instead (the io-latency lesson: assert AllInjected, not a proxy).
sink_injected() { kubectl -n "$NS" get podchaos mm-sink-failure \
  -o jsonpath='{range .status.conditions[?(@.type=="AllInjected")]}{.status}{end}' 2>/dev/null; }

# Proof-of-fire part 0: link healthy before we start.
log "proof-of-fire: a→b link up BEFORE the overlap"
"$HERE/probe-partition.sh" up || { log "INCONCLUSIVE — link not up pre-fault. Not counting."; exit "$EXIT_INCONCLUSIVE"; }

# Drive the harness in the background so both faults land WHILE it is writing.
log "starting the convergence harness (background)"
( cd "$REPO/apply-sink" && go test -tags convergence -run TestConvergence -timeout 20m -v ./... ) &
HARNESS=$!
sleep "${WRITE_WARMUP:-6}"
kill -0 "$HARNESS" 2>/dev/null || { echo "▸ FAIL — harness finished before faults injected; proved nothing."; exit 1; }

# Inject fault 1 (partition) FIRST and witness it from the still-healthy sink netns.
log "injecting fault 1/2: partition (a→b)"
kubectl apply -f "$HERE/sandbox/fault-partition.yaml"
fired=0; for _ in $(seq 1 6); do "$HERE/probe-partition.sh" down && { fired=1; break; }; sleep 3; done
[ "$fired" = 1 ] || { log "INCONCLUSIVE — partition never cut the link; fault 1 didn't bite."; exit "$EXIT_INCONCLUSIVE"; }
log "proof-of-fire: partition confirmed live (a→b cut)."

# Inject fault 2 (sink held down) and witness it via the Deployment losing its ready replica.
log "injecting fault 2/2: sink held down (pod-failure)"
kubectl apply -f "$HERE/sandbox/fault-sink-failure.yaml"
downed=0; for _ in $(seq 1 20); do [ "$(sink_injected)" = "True" ] && { downed=1; break; }; sleep 2; done
[ "$downed" = 1 ] || { log "INCONCLUSIVE — sink pod-failure never reached AllInjected; fault 2 didn't bite."; exit "$EXIT_INCONCLUSIVE"; }
log "proof-of-fire: sink pod-failure confirmed live (AllInjected). Both faults overlapping."

# Hold the overlap, then heal in the chosen ORDER with a gap between the two heals.
sleep "$OVERLAP_HOLD"
case "$HEAL_ORDER" in
  partition-first)
    log "healing order = partition-first: restoring network, then (after ${HEAL_GAP}s) the sink"
    kubectl -n "$NS" delete faultinjection mm-partition --ignore-not-found >/dev/null 2>&1 || true
    sleep "$HEAL_GAP"
    kubectl -n "$NS" delete faultinjection mm-sink-failure --ignore-not-found >/dev/null 2>&1 || true
    ;;
  sink-first)
    log "healing order = sink-first: sink returns into a still-cut network, then (after ${HEAL_GAP}s) the partition heals"
    kubectl -n "$NS" delete faultinjection mm-sink-failure --ignore-not-found >/dev/null 2>&1 || true
    sleep "$HEAL_GAP"
    kubectl -n "$NS" delete faultinjection mm-partition --ignore-not-found >/dev/null 2>&1 || true
    ;;
  *) log "unknown HEAL_ORDER '$HEAL_ORDER' (use partition-first|sink-first)"; exit 2 ;;
esac

# Both faults cleared; the mesh must reconverge byte-identical.
if wait "$HARNESS"; then
  log "PASS — mesh reconverged byte-identical after overlapping partition+sink outage healed ${HEAL_ORDER} (recovery is heal-order-independent)."
  exit 0
fi
log "FAIL — mesh did not reconverge after overlapping faults healed ${HEAL_ORDER} (release blocker)."
kubectl -n "$NS" get faultinjection,pods -o wide || true
exit 1
