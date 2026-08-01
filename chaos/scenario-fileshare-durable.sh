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

log "writing the probe file over SMB (the acked work)"
kubectl -n "$NS" exec fs-client -- sh -c 'echo chaos-probe-payload > /tmp/probe.txt'
sandbox_smb "$PASS" "put /tmp/probe.txt probe.txt" >/dev/null 2>&1 || true
if ! sandbox_smb "$PASS" "ls" | grep -q 'probe.txt'; then
  log "INCONCLUSIVE — probe file not present after write (share not accepting writes). Not counting."
  exit "$EXIT_INCONCLUSIVE"
fi
log "probe file present on the share before the fault."

# Inject the Samba kill.
BEFORE="$(smb_uid)"
log "injecting the Samba server kill (pod-scoped)"
kubectl apply -f "$HERE/sandbox/fault-fileshare-kill.yaml"

# Proof-of-fire: the Samba pod must actually be replaced.
replaced=0
for _ in $(seq 1 30); do
  a="$(smb_uid)"
  [ -n "$a" ] && [ "$a" != "$BEFORE" ] && { replaced=1; break; }
  sleep 2
done
if [ "$replaced" != 1 ]; then
  log "INCONCLUSIVE — the Samba pod was not replaced; the kill didn't land. The oracle won't bless a fault that didn't fire."
  kubectl -n "$NS" get faultinjection,podchaos,pods -l app.kubernetes.io/name=fs -o wide 2>/dev/null || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — Samba pod killed and replaced (${BEFORE:0:8}… → new)."

# Recover: the restarted share must serve again, still have the probe file, and accept a new write.
log "waiting for the restarted share to serve again (up to $(( RECOVER_TRIES * 6 ))s)"
served=0
for _ in $(seq 1 "$RECOVER_TRIES"); do
  if sandbox_smb "$PASS" "ls" | grep -q '\.'; then served=1; break; fi
  sleep 6
done
if [ "$served" != 1 ]; then
  log "FAIL — the share did NOT answer SMB again within the budget after the kill (did not recover — release blocker)."
  kubectl -n "$NS" get pods -l app.kubernetes.io/name=fs -o wide 2>/dev/null || true
  exit 1
fi

if ! sandbox_smb "$PASS" "ls" | grep -q 'probe.txt'; then
  log "FAIL — the share recovered but 'probe.txt' is GONE (file data lost across the kill — release blocker)."
  sandbox_smb "$PASS" "ls" | head || true
  exit 1
fi
# And it must accept a NEW write (fully functional, not read-only-stale).
sandbox_smb "$PASS" "put /tmp/probe.txt probe2.txt" >/dev/null 2>&1 || true
if ! sandbox_smb "$PASS" "ls" | grep -q 'probe2.txt'; then
  log "FAIL — the share recovered with data but will not accept new writes (degraded — release blocker)."
  exit 1
fi
log "PASS — the share recovered with 'probe.txt' intact and accepted a new write after a Samba kill (file data survived, share functional)."
exit 0
