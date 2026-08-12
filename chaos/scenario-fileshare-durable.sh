#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario: FILESHARE SURVIVES A SERVER KILL (the file chain; see
# docs/chaos-oracle.md). Recover-mode oracle on the FILE plane — a Samba SMB share must come back
# from a pod kill with its files intact and writable, or a mounted network drive loses data.
# Conservation of acknowledged work: a file written before the fault must still be readable after,
# and the share must accept new writes.
#
# Chain (2 resource types + the probe): a kind: FileShare + a FaultInjection. We write a probe file
# over SMB (smbclient — userspace, so it exercises the real share via the Service), kill the Samba
# pod, and assert the restarted share still has the file and accepts a new write. Proof-of-fire: the
# Samba pod is actually replaced.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"

RECOVER_TRIES="${FS_RECOVER_TRIES:-30}"   # x6s = 180s for the share to serve again after the kill
EXIT_INCONCLUSIVE=42

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
trap sandbox_teardown_fileshare EXIT

sandbox_provision_fileshare

# PRE-FLIGHT — refuse the fault if it could reach anything outside the sandbox.
log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-fileshare-kill.yaml"

smb_uid() { kubectl -n "$NS" get pods -l app=fs-smb -o jsonpath='{.items[0].metadata.uid}' 2>/dev/null || true; }
PASS="$(kubectl -n "$NS" get secret fs-fileshare -o jsonpath='{.data.PASSWORD}' 2>/dev/null | base64 -d)"
[ -n "$PASS" ] || { log "INCONCLUSIVE — could not read the fileshare password secret. Not counting."; exit "$EXIT_INCONCLUSIVE"; }

# Wait for the share to actually answer SMB (not just the pod Running), then write the probe file.
log "waiting for the share to answer SMB"
up=0
for _ in $(seq 1 30); do
  if sandbox_smb "$PASS" "ls" | grep -q '\.'; then up=1; break; fi
  sleep 6
done
if [ "$up" != 1 ]; then
  log "INCONCLUSIVE — the share never answered SMB pre-fault (not ready / client path broken). Not counting."
  kubectl -n "$NS" get fileshare,deploy,svc,pods -o wide 2>/dev/null | grep -iE 'fs|NAME' || true
  exit "$EXIT_INCONCLUSIVE"
fi

# Delegate the VERDICT to the SINGULAR engine: the Go fileshare-durability adapter (recover mode)
# writes the probe file over SMB (Drive) + records the pre-fault Samba pod identity, waits for the
# fault to LAND and the share to serve SMB again (SteadyState requires the Samba pod replaced AND the
# restarted share answering), then asserts the probe file survived AND the recovered share accepts a
# NEW write (Reconcile). This scenario owns provisioning + firing the fault + the INCONCLUSIVE gate;
# the engine owns the verdict (replacing the old bash probe-write/readback + PASS-FAIL fork).
REPO="$(cd "$HERE/.." && pwd)"
export CHAOS_SANDBOX_NS="$NS" FS_SECRET="fs-fileshare" FS_SELECTOR="app=fs-smb"
export CONV_TIMEOUT="$(( RECOVER_TRIES * 6 ))"   # preserve the original recover budget for the share to serve again

log "driving the probe file + judging conservation via the singular recover engine"
( cd "$REPO/apply-sink" && go test -tags convergence -run '^TestFileshareDurability$' -timeout 15m -count=1 ./... ) &
GOTEST=$!
sleep "${FS_DRIVE_SETTLE:-8}"   # let Drive record the Samba pod identity + write the probe file BEFORE the kill

# Inject the Samba kill.
BEFORE="$(smb_uid)"
log "injecting the Samba server kill (pod-scoped)"
kubectl apply -f "$HERE/sandbox/fault-fileshare-kill.yaml"

# Proof-of-fire: the Samba pod must actually be replaced — else the kill didn't land → INCONCLUSIVE.
replaced=0
for _ in $(seq 1 30); do
  a="$(smb_uid)"
  [ -n "$a" ] && [ "$a" != "$BEFORE" ] && { replaced=1; break; }
  sleep 2
done
if [ "$replaced" != 1 ]; then
  log "INCONCLUSIVE — the Samba pod was not replaced; the kill didn't land. The oracle won't bless a fault that didn't fire."
  kubectl -n "$NS" get faultinjection,podchaos,pods -l app.kubernetes.io/name=fs -o wide 2>/dev/null || true
  kill "$GOTEST" >/dev/null 2>&1 || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — Samba pod killed and replaced (${BEFORE:0:8}… → new); the adapter judges the probe file survived."

# The adapter waits for the restarted share to serve again, then asserts the probe file survived and the
# recovered share accepts a new write; its exit code IS the verdict.
if wait "$GOTEST"; then
  log "PASS — the share recovered with 'probe.txt' intact and accepted a new write after a Samba kill (verdict: singular recover engine)."
  exit 0
fi
log "FAIL — file data lost or the share came back read-only-stale across the Samba kill (release blocker)."
kubectl -n "$NS" get pods -l app.kubernetes.io/name=fs -o wide 2>/dev/null || true
exit 1
