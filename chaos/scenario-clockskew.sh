#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario 2: clock-skew (the T6 regression, design §5).
#
# T6 was a MySQL backward-clock lost write. Per the design (§3): NO real clock skew /
# TimeChaos. Instead this provisions a disposable MySQL member, installs mm-prep, and
# forces the physical clock BACKWARD deterministically via the injectable clk_off offset,
# asserting the HLC still stamps a strictly increasing version (no silent lost write).
# Runs on the self-hosted runner (kubectl + Go + cluster reach). Red = release blocker.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
KEEP="${CHAOS_KEEP:-0}"
export CONV_SKEW_MS="${CONV_SKEW_MS:--3600000}"   # one hour backward

log() { echo "▸ $*"; }
cleanup() {
  if [ "$KEEP" != "1" ]; then
    log "tearing down MySQL member"
    kubectl -n "$NS" delete -f "$HERE/sandbox/member-mysql.yaml" --ignore-not-found >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

log "provisioning disposable MySQL member"
kubectl apply -f "$HERE/sandbox/member-mysql.yaml"
kubectl -n "$NS" rollout status statefulset/my-b --timeout=180s

IP="$(kubectl -n "$NS" get svc my-b -o jsonpath='{.spec.clusterIP}')"
export PGPASS="$(kubectl -n "$NS" get secret pg-creds -o jsonpath='{.data.password}' | base64 -d)"
export CONV_SKEW_ENGINE=mysql
# go-sql-driver DSN (root, plain TCP). ${PGPASS} is expanded by the test (os.ExpandEnv).
export CONV_SKEW_DSN="root:\${PGPASS}@tcp(${IP}:3306)/app"

log "running the T6 clock-skew regression (force clock ${CONV_SKEW_MS} ms backward via clk_off)"
( cd "$REPO/apply-sink" && go test -tags convergence -run TestClockSkewMonotonic -timeout 5m -v ./... )
RC=$?

if [ "$RC" = "0" ]; then
  log "PASS — HLC stayed monotonic under a backward clock (no T6 lost write)"
else
  log "FAIL — backward clock produced a non-increasing version (T6 regression, release blocker)"
fi
exit "$RC"
