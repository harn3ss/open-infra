#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario 3x: CPU-PRESSURE degrade (fault-variety axis; see
# docs/chaos-oracle.md). Saturate the a→b apply-sink's CPU (2 stressor threads at 100% inside
# its 1-core cgroup) for the whole run, and assert the mesh still converges byte-identical. Like
# latency/loss this is a *degrade*, not a cut: a starved sink applies slowly but never drops a
# write, so sustained divergence would be a BUG. No MIN_ELAPSED — converging (even if slower) is
# the desired outcome; the proof-of-fire is the StressChaos actually injecting, not a slow clock.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
export CONV_TIMEOUT="${CONV_TIMEOUT:-360}"
export CONV_SETTLE="${CONV_SETTLE:-15}"
export CONV_CREATE="${CONV_CREATE:-false}"
export CONV_KEYS="${CONV_KEYS:-200}"
export CONV_CONFLICTS="${CONV_CONFLICTS:-20}"
# Hold the CPU pressure across the whole harness so convergence is proven UNDER sustained stress.
STRESS_HOLD="${STRESS_HOLD:-420s}"
EXIT_INCONCLUSIVE=42

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
cleanup() {
  kubectl -n "$NS" delete faultinjection mm-stress-cpu --ignore-not-found >/dev/null 2>&1 || true
  sandbox_teardown
}
trap cleanup EXIT

sandbox_provision
sandbox_conv_members

log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-stress-cpu.yaml"

log "injecting ${STRESS_HOLD} of CPU pressure on the a→b apply-sink (2 workers @100%, 1-core cgroup)"
sed "s/duration: 90s/duration: ${STRESS_HOLD}/" "$HERE/sandbox/fault-stress-cpu.yaml" | kubectl apply -f -

# Proof-of-fire: the StressChaos must reach AllInjected (CPU contention has no external probe).
stress_injected() { kubectl -n "$NS" get stresschaos mm-stress-cpu \
  -o jsonpath='{range .status.conditions[?(@.type=="AllInjected")]}{.status}{end}' 2>/dev/null; }
log "proof-of-fire: confirming the CPU stressors actually injected into the sink"
fired=0
for _ in $(seq 1 20); do [ "$(stress_injected)" = "True" ] && { fired=1; break; }; sleep 2; done
if [ "$fired" != 1 ]; then
  log "INCONCLUSIVE — StressChaos never reached AllInjected; the CPU pressure didn't bite. Not counting."
  kubectl -n "$NS" get faultinjection,stresschaos -o wide || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — CPU pressure confirmed live on the apply-sink."

# Core assertion: WITH the sink CPU-starved, the mesh must STILL converge byte-identical.
log "running the convergence harness UNDER sustained CPU pressure (must converge — degrade is not a cut)"
if ! ( cd "$REPO/apply-sink" && go test -tags convergence -run TestConvergence -timeout 20m -v ./... ); then
  log "FAIL — mesh did NOT converge under mere CPU pressure (release blocker). A degrade must never"
  log "       cause sustained divergence. Retaining state."
  kubectl -n "$NS" get faultinjection,stresschaos,pods -o wide || true
  exit 1
fi

log "PASS — mesh converged byte-identical UNDER sustained CPU pressure on the apply-sink (degrade tolerated; fault confirmed live)."
exit 0
