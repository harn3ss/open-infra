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

# Confirm the block device is attached, then write the signature (the acked work).
if ! sandbox_vol_exec "[ -b $DEV ]" 2>/dev/null; then
  log "INCONCLUSIVE — block device $DEV not attached in the writer (volume not ready). Not counting."
  kubectl -n "$NS" get volume,pvc,pods -o wide 2>/dev/null | grep -iE 'vol|NAME' || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "writing raw-block signature to $DEV (the acked work)"
sandbox_vol_exec "printf '%s' '$SIG' | dd of=$DEV bs=512 seek=0 conv=notrunc 2>/dev/null; sync"
got="$(sandbox_vol_exec "dd if=$DEV bs=1 count=${#SIG} 2>/dev/null")"
if [ "$got" != "$SIG" ]; then
  log "INCONCLUSIVE — signature did not read back before the fault (got '${got}'; write path broken). Not counting."
  exit "$EXIT_INCONCLUSIVE"
fi
log "signature present on the volume before the fault."

# Inject the pod kill.
BEFORE="$(writer_uid)"
log "injecting the attached-pod kill (pod-scoped)"
kubectl apply -f "$HERE/sandbox/fault-volume-kill.yaml"

# Proof-of-fire: the attached pod must actually be replaced.
replaced=0
for _ in $(seq 1 40); do
  a="$(writer_uid)"
  [ -n "$a" ] && [ "$a" != "$BEFORE" ] && { replaced=1; break; }
  sleep 2
done
if [ "$replaced" != 1 ]; then
  log "INCONCLUSIVE — the attached pod was not replaced; the kill didn't land. The oracle won't bless a fault that didn't fire."
  kubectl -n "$NS" get faultinjection,podchaos,pods -l app=vol-writer -o wide 2>/dev/null || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — attached pod killed and replaced (${BEFORE:0:8}… → new)."

# Recover: the rescheduled pod must re-attach the SAME volume and read the signature back.
log "waiting for the rescheduled pod to re-attach the volume (Recreate: detach then reattach)"
kubectl -n "$NS" rollout status deploy/vol-writer --timeout=180s || true
if ! sandbox_vol_exec "[ -b $DEV ]" 2>/dev/null; then
  log "FAIL — the rescheduled pod did not re-attach the block device within the budget (volume did not recover — release blocker)."
  kubectl -n "$NS" get pods -l app=vol-writer -o wide 2>/dev/null || true
  exit 1
fi
got="$(sandbox_vol_exec "dd if=$DEV bs=1 count=${#SIG} 2>/dev/null")"
if [ "$got" = "$SIG" ]; then
  log "PASS — the volume re-attached with its raw-block signature intact after a pod kill (block data survived the reschedule)."
  exit 0
fi
log "FAIL — the volume re-attached but the signature is GONE (read '${got}', want '${SIG}') — block data lost across the reschedule (release blocker)."
exit 1
