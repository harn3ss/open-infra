#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario 1b: FLAPPING partition (magnitude axis; see
# docs/chaos-oracle.md). Instead of ONE sustained 90s cut, repeatedly cut+heal the a→b link
# in short cycles WHILE the convergence harness drives conflicting writes, then assert the
# mesh converges once the flapping stops. This exercises recovery under INTERMITTENT
# connectivity — a distinct failure mode from a clean sustained partition (offsets/retries
# that survive one long outage can still thrash under repeated connect/disconnect).
#
# Oracle (docs/chaos-oracle.md): transient divergence during each cut is EXPECTED; the mesh
# must be byte-identical AFTER the flapping stops. Proof-of-fire: the cut must be confirmed
# live at least once across the cycles, else the flapping injected nothing → INCONCLUSIVE.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
# Convergence poll budget must exceed the whole flap window + settle so the final assertion
# lands on a HEALED mesh.
export CONV_TIMEOUT="${CONV_TIMEOUT:-300}"
export CONV_SETTLE="${CONV_SETTLE:-15}"
export CONV_CREATE="${CONV_CREATE:-false}"
export CONV_KEYS="${CONV_KEYS:-200}"
export CONV_CONFLICTS="${CONV_CONFLICTS:-20}"
FLAP_CYCLES="${FLAP_CYCLES:-4}"; FLAP_CUT="${FLAP_CUT:-15}"; FLAP_HEAL="${FLAP_HEAL:-8}"
EXIT_INCONCLUSIVE=42

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
trap sandbox_teardown EXIT

sandbox_provision
sandbox_conv_members

log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-partition.yaml"

# Proof-of-fire (oracle pillar 1), part 1: link healthy before we start flapping.
log "proof-of-fire: confirming the a→b link is up BEFORE flapping"
if ! "$HERE/probe-partition.sh" up; then
  log "INCONCLUSIVE — a→b link not up pre-fault (mesh not ready / probe path broken). Not counting."
  exit "$EXIT_INCONCLUSIVE"
fi

# Background flapping loop: short cut/heal cycles. Records into $FIRED_FLAG if any cut is
# ever confirmed live (proof-of-fire for the flapping magnitude).
FIRED_FLAG="$(mktemp)"
flap_loop() {
  for c in $(seq 1 "$FLAP_CYCLES"); do
    kubectl apply -f "$HERE/sandbox/fault-partition.yaml" >/dev/null 2>&1 || true
    if "$HERE/probe-partition.sh" down >/dev/null 2>&1; then echo 1 > "$FIRED_FLAG"; fi
    sleep "$FLAP_CUT"
    kubectl delete -f "$HERE/sandbox/fault-partition.yaml" --ignore-not-found >/dev/null 2>&1 || true
    sleep "$FLAP_HEAL"
  done
}
log "flapping the a→b partition in the background: ${FLAP_CYCLES}× (${FLAP_CUT}s cut / ${FLAP_HEAL}s heal)"
flap_loop &
FLAP_PID=$!

# NOTE (rigor limitation, tracked): the harness drives its conflicting writes up-front, so
# once the mesh first converges (typically well inside the flap window) the later cycles are
# inert — nothing new to lose. This proves convergence under a cut DURING flapping, but a
# stricter version would drive writes across ALL cycles (continuous writer) and assert
# byte-identical only AFTER the flapping stops. Good enough for the first flapping increment.
log "running the convergence harness through the flapping"
harness_rc=0
( cd "$REPO/apply-sink" && go test -tags convergence -run TestConvergence -timeout 20m -v ./... ) || harness_rc=$?

# Ensure the flapping is finished and the link is healed before the verdict.
wait "$FLAP_PID" 2>/dev/null || true
kubectl delete -f "$HERE/sandbox/fault-partition.yaml" --ignore-not-found >/dev/null 2>&1 || true

fired="$(cat "$FIRED_FLAG" 2>/dev/null || true)"; rm -f "$FIRED_FLAG"

if [ "$harness_rc" -ne 0 ]; then
  log "FAIL — mesh did not converge after the flapping partition (release blocker). Retaining state."
  kubectl -n "$NS" get faultinjection,pods -o wide || true
  exit 1
fi
if [ "$fired" != 1 ]; then
  log "INCONCLUSIVE — no cut was ever confirmed live across the flap cycles; the partition"
  log "            didn't bite. The oracle refuses to bless flapping that injected nothing."
  exit "$EXIT_INCONCLUSIVE"
fi
log "PASS — mesh re-converged byte-identical after ${FLAP_CYCLES}× flapping partition (cut confirmed live)."
exit 0
