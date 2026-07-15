#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario 5: storage degradation (design §5 `longhorn-replica-loss`).
#
# Degrade the IO path of the sandbox's Longhorn-backed CNPG member while the harness writes,
# and assert the mesh still converges — i.e. CDC offsets and the engine survive slow storage.
#
# SCOPE, stated honestly: this does NOT kill a real Longhorn replica. Those live in
# longhorn-system instance-manager pods that host replicas for many REAL volumes (VMs,
# databases, MinIO), so faulting one would endanger the cluster — forbidden by §3 and
# refused by the pre-flight guard. Per §10 that experiment needs a separate validation
# cluster. What this DOES cover: the workload-visible half — storage gets slow, does the
# mesh still converge?
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
export CONV_TIMEOUT="${CONV_TIMEOUT:-300}"
export CONV_SETTLE="${CONV_SETTLE:-20}"
export CONV_CREATE="${CONV_CREATE:-false}"
export CONV_KEYS="${CONV_KEYS:-200}"
export CONV_CONFLICTS="${CONV_CONFLICTS:-20}"

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
trap sandbox_teardown_cnpg EXIT

sandbox_provision_cnpg   # CNPG members are Longhorn-backed (unlike the emptyDir raw members)
sandbox_conv_members_cnpg

log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-io-latency.yaml"

# Degrade storage FIRST so the writes are driven through slow IO (injecting afterwards
# would land on already-replicated data and prove nothing — a false green we hit before).
log "injecting IO latency (300ms, 90s) on site B's Longhorn-backed volume"
kubectl apply -f "$HERE/sandbox/fault-io-latency.yaml"

# Prove it actually INJECTED. An object that merely exists proves nothing — Chaos Mesh
# reports AllInjected=True only once it has injected into the target containers.
LANDED=0
for _ in $(seq 1 30); do
  inj="$(kubectl -n "$NS" get iochaos mm-io-latency \
    -o jsonpath='{.status.conditions[?(@.type=="AllInjected")].status}' 2>/dev/null || true)"
  [ "$inj" = "True" ] && { LANDED=1; break; }
  sleep 2
done
[ "$LANDED" = 1 ] && log "fault landed: IOChaos AllInjected=True" || {
  log "FAIL — IOChaos never reported AllInjected; the IO fault did not inject. Refusing a false green."
  kubectl -n "$NS" get iochaos mm-io-latency -o yaml 2>/dev/null | tail -20 || true
  exit 1; }

log "running the convergence harness through the degraded storage"
START=$(date +%s)
if ! ( cd "$REPO/apply-sink" && go test -tags convergence -run TestConvergence -timeout 20m -v ./... ); then
  log "FAIL — mesh did not converge under storage degradation (release blocker)"
  kubectl -n "$NS" get faultinjection,iochaos,pods -o wide || true
  exit 1
fi
log "PASS — mesh converged despite degraded storage ($(( $(date +%s) - START ))s; CDC offsets survived)"
exit 0
