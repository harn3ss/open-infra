#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario 4: cnpg-failover (design §5).
#
# Kill site B's CNPG PRIMARY mid-write. CNPG must promote the replica, the -rw service
# must follow the new primary, and the mesh must converge across the promotion with no
# lost writes. This is the scenario that exercises the REAL managed-Postgres path (raw
# StatefulSets can't fail over). Red = release blocker.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
# Budget must outlast: kill + promotion + -rw re-point + engine reconnect + settle.
export CONV_TIMEOUT="${CONV_TIMEOUT:-300}"
export CONV_SETTLE="${CONV_SETTLE:-20}"
export CONV_CREATE="${CONV_CREATE:-false}"   # provisioning seeds the table
export CONV_KEYS="${CONV_KEYS:-200}"
export CONV_CONFLICTS="${CONV_CONFLICTS:-20}"

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
trap sandbox_teardown_cnpg EXIT

sandbox_provision_cnpg
sandbox_conv_members_cnpg

log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-cnpg-failover.yaml"

primary() { kubectl -n "$NS" get pods -l cnpg.io/cluster=cnpg-b,cnpg.io/instanceRole=primary \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true; }

log "starting the convergence harness (background)"
( cd "$REPO/apply-sink" && go test -tags convergence -run TestConvergence -timeout 20m -v ./... ) &
HARNESS=$!

sleep "${KILL_AFTER:-4}"   # let writes get in flight

# The harness MUST still be running — if it already finished, the fault lands after the
# test is over and proves nothing. That exact false green happened once; never again.
kill -0 "$HARNESS" 2>/dev/null || {
  echo "▸ FAIL — the harness completed BEFORE the fault was injected; the fault exercised nothing. Refusing a false green."
  exit 1
}
BEFORE="$(primary)"
log "killing site B's CNPG primary mid-flight (${BEFORE})"
kubectl apply -f "$HERE/sandbox/fault-cnpg-failover.yaml"

# Assert a PROMOTION actually happened — a different instance must become primary. Without
# this, a fault that silently no-ops (or that killed a replica) would report green while
# proving nothing about failover.
PROMOTED=0
for _ in $(seq 1 45); do
  NOW="$(primary)"
  if [ -n "$NOW" ] && [ -n "$BEFORE" ] && [ "$NOW" != "$BEFORE" ]; then
    log "fault landed: CNPG promoted ${BEFORE} → ${NOW}"
    PROMOTED=1
    break
  fi
  sleep 2
done
if [ "$PROMOTED" != 1 ]; then
  log "FAIL — no promotion observed (primary still ${BEFORE}): the failover did not happen. Refusing a false green."
  kubectl -n "$NS" get pods -l cnpg.io/cluster=cnpg-b -o wide || true
  exit 1
fi

if wait "$HARNESS"; then
  log "PASS — mesh converged across the CNPG failover (promotion + no lost writes)"
  exit 0
fi
log "FAIL — mesh did not converge across the promotion (release blocker)"
kubectl -n "$NS" get cluster,pods -o wide || true
exit 1
