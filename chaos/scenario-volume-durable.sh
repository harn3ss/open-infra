#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario: VOLUME SURVIVES A POD RESCHEDULE (the block chain; see
# docs/chaos-oracle.md). Recover-mode oracle on the BLOCK-STORAGE plane — a standalone Longhorn
# block volume (EBS-style) must keep its data when the pod attached to it dies and a new pod
# re-attaches it. Conservation of acknowledged work: a raw-block signature written before the fault
# must read back identical afterward.
#
# Chain (2 resource types + the writer): a kind: Volume + a FaultInjection. We write a signature to
# the raw block device, kill the attached pod, and assert the rescheduled pod re-attaches the same
# volume and reads the signature back. Proof-of-fire: the attached pod is actually replaced.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"

SIG="CHAOSVOL-PERSIST-OK"
DEV="/dev/xvda"
EXIT_INCONCLUSIVE=42

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
trap sandbox_teardown_volume EXIT

sandbox_provision_volume

# PRE-FLIGHT — refuse the fault if it could reach anything outside the sandbox.
log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-volume-kill.yaml"

writer_uid() { kubectl -n "$NS" get pods -l app=vol-writer -o jsonpath='{.items[0].metadata.uid}' 2>/dev/null || true; }

REPO="$(cd "$HERE/.." && pwd)"
# Confirm the block device is attached (inconclusive if the volume never came up) — the adapter needs
# a writable device to lay down its signature.
if ! sandbox_vol_exec "[ -b $DEV ]" 2>/dev/null; then
  log "INCONCLUSIVE — block device $DEV not attached in the writer (volume not ready). Not counting."
  kubectl -n "$NS" get volume,pvc,pods -o wide 2>/dev/null | grep -iE 'vol|NAME' || true
  exit "$EXIT_INCONCLUSIVE"
fi

# Delegate the VERDICT to the SINGULAR engine: the Go volume-durability adapter writes the raw-block
# signature (Drive), waits for the fault to LAND and the volume to re-attach (SteadyState requires the
# writer pod replaced + the device readable again), and asserts the signature survived (Reconcile).
# This scenario owns firing the fault + the INCONCLUSIVE gate; the engine owns the verdict.
export CHAOS_SANDBOX_NS="$NS" VOL_DEV="$DEV"
( cd "$REPO/apply-sink" && go test -tags convergence -run '^TestVolumeDurability$' -timeout 15m -count=1 ./... ) &
GOTEST=$!
sleep "${DRIVE_SETTLE:-6}"   # let Drive record the writer identity + write the signature BEFORE the kill

BEFORE="$(writer_uid)"
log "injecting the attached-pod kill (pod-scoped)"
kubectl apply -f "$HERE/sandbox/fault-volume-kill.yaml"

# Proof-of-fire: the attached pod must actually be replaced — else the kill didn't land → INCONCLUSIVE.
replaced=0
for _ in $(seq 1 40); do
  a="$(writer_uid)"
  [ -n "$a" ] && [ "$a" != "$BEFORE" ] && { replaced=1; break; }
  sleep 2
done
if [ "$replaced" != 1 ]; then
  log "INCONCLUSIVE — the attached pod was not replaced; the kill didn't land. The oracle won't bless a fault that didn't fire."
  kubectl -n "$NS" get faultinjection,podchaos,pods -l app=vol-writer -o wide 2>/dev/null || true
  kill "$GOTEST" >/dev/null 2>&1 || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — attached pod killed and replaced (${BEFORE:0:8}… → new); the adapter judges the signature survived."

if wait "$GOTEST"; then
  log "PASS — the volume re-attached with its raw-block signature intact (verdict: singular recover engine)."
  exit 0
fi
log "FAIL — block data lost across the reschedule (release blocker)."
kubectl -n "$NS" get pods -l app=vol-writer -o wide 2>/dev/null || true
exit 1
