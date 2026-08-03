#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario 7: THE CHAOS LOTTERY (correlation axis; see docs/chaos-oracle.md).
#
# The capstone the whole suite feeds. A seeded draw (lottery-draw.py) picks 2-4 concurrent faults
# across primitives, biased toward a shared surface (interaction bugs live where faults overlap);
# we apply them all at once, PROVE each one fired (per-fault proof-of-fire — a partial no-op is
# INCONCLUSIVE, never green), drive the convergence harness through the combined chaos, heal, and
# require the mesh to reconverge byte-identical. The universal oracle across any draw: whatever the
# mix of cuts and degrades, once everything heals the mesh must be byte-identical with zero lost.
#
# REPLAYABLE: the seed is printed prominently. A red night reruns with LOTTERY_SEED=<that seed>.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
# Very generous: a draw can combine a whole-mesh CUT (isolation) with sink-failure, whose recovery
# restarts the apply-sink (re-establishing its NATS consumer each time) — so the post-heal drain of
# a both-directions backlog is slow (~500-600s observed) but DOES complete. Budget for the worst
# combo so a slow-but-correct reconvergence isn't a false red. (Standalone scenarios stay tighter.)
export CONV_TIMEOUT="${CONV_TIMEOUT:-720}"
export CONV_SETTLE="${CONV_SETTLE:-15}"
export CONV_CREATE="${CONV_CREATE:-false}"
export CONV_KEYS="${CONV_KEYS:-200}"
export CONV_CONFLICTS="${CONV_CONFLICTS:-20}"
# Hold the drawn faults for a bounded window, then let them auto-heal well INSIDE the convergence
# budget. This must be short relative to CONV_TIMEOUT: a CUT draw (partition/isolation) can't
# reconverge until it heals, so the budget needs generous post-heal drain time (a 360s hold under a
# 420s budget left only 60s to drain a both-directions backlog and timed out — a false red).
FAULT_HOLD="${FAULT_HOLD:-120s}"
EXIT_INCONCLUSIVE=42
SINKD="app=chaos-mesh-pg-repl-a-b-sink"
DBZB="app=chaos-mesh-pg-repl-b-dbz"

# --- the draw (seeded, replayable) ---
DRAW_JSON="$(python3 "$HERE/lottery-draw.py")"   # resolves LOTTERY_SEED or a fresh seed
SEED="$(printf '%s' "$DRAW_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin)["meta"]["seed"])')"
NAMES="$(printf '%s' "$DRAW_JSON" | python3 -c 'import json,sys;print(" ".join(json.load(sys.stdin)["meta"]["faults"]))')"
FILES="$(printf '%s' "$DRAW_JSON" | python3 -c 'import json,sys;print(" ".join(f["fault"] for f in json.load(sys.stdin)["faults"]))')"
echo "▸ ============================================================"
echo "▸  CHAOS LOTTERY  seed=$SEED   draw: $NAMES"
echo "▸  replay this exact run with:  LOTTERY_SEED=$SEED"
echo "▸ ============================================================"
# In CI, surface the drawn faults + seed so the workflow can stamp per-fault nightly dates
# into chaos/nightly-status.json (only the faults ACTUALLY drawn get today's date).
[ -n "${GITHUB_OUTPUT:-}" ] && { echo "faults=$NAMES"; echo "seed=$SEED"; } >> "$GITHUB_OUTPUT"

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
cleanup() {
  for f in $FILES; do kubectl -n "$NS" delete -f "$HERE/sandbox/$f" --ignore-not-found >/dev/null 2>&1 || true; done
  sandbox_teardown
}
trap cleanup EXIT

sandbox_provision
sandbox_conv_members

log "pre-flight guard (every drawn fault)"
for f in $FILES; do "$HERE/preflight.sh" "$HERE/sandbox/$f"; done

# Record pre-fault pod UIDs for the pod-kill witnesses.
uid() { kubectl -n "$NS" get pods -l "$1" -o jsonpath='{.items[0].metadata.uid}' 2>/dev/null || true; }
SINK_UID0="$(uid "$SINKD")"; DBZ_UID0="$(uid "$DBZB")"

# Apply the whole draw at once (hold each for the run; the netem/stress/failure faults honor duration).
log "injecting the draw concurrently ($NAMES)"
for f in $FILES; do sed "s/duration: 90s/duration: ${FAULT_HOLD}/" "$HERE/sandbox/$f" | kubectl apply -f - >/dev/null; done

# Per-fault proof-of-fire. Each drawn fault must be independently witnessed to have fired; a
# partial injection (some faults silently no-op) is INCONCLUSIVE — the lottery won't bless it.
allinjected() { kubectl -n "$NS" get "$1" "$2" -o jsonpath='{range .status.conditions[?(@.type=="AllInjected")]}{.status}{end}' 2>/dev/null; }
pod_replaced() { local sel="$1" was="$2" now; now="$(uid "$sel")"; [ -n "$now" ] && [ "$now" != "$was" ]; }
# Proof-of-fire for the LOTTERY differs from the standalone scenarios on purpose. A standalone
# scenario witnesses the fault's EFFECT with an external probe (link down / handshake slow / lossy)
# — the strongest signal. But under a MULTI-fault draw those probes are confounded: e.g. a co-drawn
# sink-kill restarts the sink, staling the netem's peer ipset, so the latency probe sees no delay
# even though Chaos Mesh applied the netem. So the lottery witnesses each fault via Chaos Mesh's own
# AllInjected condition (netem/stress/pod-failure) or pod-replacement (pod-kill). AllInjected is not
# blind trust — it is exactly what io-latency and dns FAIL (their injectors panic), so the
# silent-no-op class (the 07-23 failure) is still caught; it just isn't confounded by interactions.
# The real verdict on the combination is the convergence judge below.
witness() { # name -> 0 if fired
  case "$1" in
    partition)    for _ in $(seq 1 20); do [ "$(allinjected networkchaos mm-partition)" = "True" ] && return 0; sleep 2; done; return 1 ;;
    isolation)    for _ in $(seq 1 20); do [ "$(allinjected networkchaos mm-isolation)" = "True" ] && return 0; sleep 2; done; return 1 ;;
    latency)      for _ in $(seq 1 20); do [ "$(allinjected networkchaos mm-latency)" = "True" ] && return 0; sleep 2; done; return 1 ;;
    loss)         for _ in $(seq 1 20); do [ "$(allinjected networkchaos mm-loss)" = "True" ] && return 0; sleep 2; done; return 1 ;;
    sink-kill)    for _ in $(seq 1 20); do pod_replaced "$SINKD" "$SINK_UID0" && return 0; sleep 2; done; return 1 ;;
    capture-kill) for _ in $(seq 1 20); do pod_replaced "$DBZB" "$DBZ_UID0" && return 0; sleep 2; done; return 1 ;;
    sink-failure) for _ in $(seq 1 20); do [ "$(allinjected podchaos mm-sink-failure)" = "True" ] && return 0; sleep 2; done; return 1 ;;
    stress-cpu)   for _ in $(seq 1 20); do [ "$(allinjected stresschaos mm-stress-cpu)" = "True" ] && return 0; sleep 2; done; return 1 ;;
    stress-mem)   for _ in $(seq 1 20); do [ "$(allinjected stresschaos mm-stress-mem)" = "True" ] && return 0; sleep 2; done; return 1 ;;
    *) echo "  (no witness for '$1' — treating as unproven)"; return 1 ;;
  esac
}

log "proof-of-fire: confirming EVERY drawn fault actually fired (AllInjected / pod-replaced)"
for n in $NAMES; do
  if witness "$n"; then log "  ✓ $n fired"; else
    log "INCONCLUSIVE — drawn fault '$n' never fired; the lottery refuses to bless a partial draw."
    log "            replay: LOTTERY_SEED=$SEED"
    kubectl -n "$NS" get faultinjection,networkchaos,podchaos,stresschaos -o wide || true
    exit "$EXIT_INCONCLUSIVE"
  fi
done
log "proof-of-fire OK — all ${NAMES// /, } confirmed live."

# The judge: drive writes through the combined chaos and require byte-identical reconvergence.
log "running the convergence harness through the drawn chaos (must reconverge byte-identical)"
if ! ( cd "$REPO/apply-sink" && go test -tags convergence -run TestConvergence -timeout 25m -v ./... ); then
  log "FAIL — mesh did NOT reconverge under the lottery draw [$NAMES] (release blocker)."
  log "       REPLAY THIS EXACT FAILURE: LOTTERY_SEED=$SEED   Retaining state."
  kubectl -n "$NS" get faultinjection,networkchaos,podchaos,stresschaos,pods -o wide || true
  exit 1
fi

log "PASS — mesh reconverged byte-identical under the lottery draw [$NAMES] (seed $SEED)."
exit 0
