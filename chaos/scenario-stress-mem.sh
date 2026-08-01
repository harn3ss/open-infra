#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario 3y: MEMORY-PRESSURE degrade (fault-variety axis; see
# docs/chaos-oracle.md). Consume 300MB inside site B's Postgres cgroup (512Mi limit) for the
# whole run and assert the mesh still converges byte-identical. A degrade, not a cut: the DB is
# pressured (slower, possibly swapping) but stays up, so sustained divergence would be a BUG.
# No MIN_ELAPSED; proof-of-fire is the StressChaos actually injecting.
#
# Distinct from stress-cpu: different fault (memory) on a different target (the DB, not the sink).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
export CONV_TIMEOUT="${CONV_TIMEOUT:-360}"
export CONV_SETTLE="${CONV_SETTLE:-15}"
export CONV_CREATE="${CONV_CREATE:-false}"
export CONV_KEYS="${CONV_KEYS:-200}"
export CONV_CONFLICTS="${CONV_CONFLICTS:-20}"
STRESS_HOLD="${STRESS_HOLD:-420s}"
EXIT_INCONCLUSIVE=42

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
cleanup() {
  kubectl -n "$NS" delete faultinjection mm-stress-mem --ignore-not-found >/dev/null 2>&1 || true
  sandbox_teardown
}
trap cleanup EXIT

sandbox_provision
sandbox_conv_members

log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-stress-mem.yaml"

log "injecting ${STRESS_HOLD} of memory pressure on pg-b (300MB in a 512Mi cgroup)"
sed "s/duration: 90s/duration: ${STRESS_HOLD}/" "$HERE/sandbox/fault-stress-mem.yaml" | kubectl apply -f -

stress_injected() { kubectl -n "$NS" get stresschaos mm-stress-mem \
  -o jsonpath='{range .status.conditions[?(@.type=="AllInjected")]}{.status}{end}' 2>/dev/null; }
log "proof-of-fire: confirming the memory stressor actually injected into pg-b"
fired=0
for _ in $(seq 1 20); do [ "$(stress_injected)" = "True" ] && { fired=1; break; }; sleep 2; done
if [ "$fired" != 1 ]; then
  log "INCONCLUSIVE — StressChaos never reached AllInjected; memory pressure didn't bite. Not counting."
  kubectl -n "$NS" get faultinjection,stresschaos -o wide || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — memory pressure confirmed live on pg-b."

# pg-b must stay queryable under pressure (a degrade must not take the DB down).
if ! kubectl -n "$NS" exec pg-b-0 -- psql -U app -d app -c 'SELECT 1' >/dev/null 2>&1; then
  log "FAIL — pg-b is not queryable under memory pressure (a degrade must not OOM the DB down)."
  kubectl -n "$NS" get pods -o wide || true
  exit 1
fi
log "pg-b still serving queries under memory pressure."

log "running the convergence harness UNDER sustained memory pressure (must converge — degrade is not a cut)"
if ! ( cd "$REPO/apply-sink" && go test -tags convergence -run TestConvergence -timeout 20m -v ./... ); then
  log "FAIL — mesh did NOT converge under mere memory pressure (release blocker). Retaining state."
  kubectl -n "$NS" get faultinjection,stresschaos,pods -o wide || true
  exit 1
fi

log "PASS — mesh converged byte-identical UNDER sustained memory pressure on pg-b (degrade tolerated; fault confirmed live)."
exit 0
