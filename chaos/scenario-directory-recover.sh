#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario: DIRECTORY SURVIVES A DC KILL (the identity chain; see
# docs/chaos-oracle.md). Recover-mode oracle on the IDENTITY plane — a Samba AD Domain Controller
# must come back from a pod kill with its directory intact, or every domain-joined machine loses
# authentication. Conservation of acknowledged work: an account created before the fault must still
# exist after the DC restarts from its stable domain-database PVC.
#
# Chain (2 resource types + the probe): a kind: Directory + a FaultInjection. We provision the DC,
# wait for the AD domain to actually serve (samba-tool answers — first-boot provisioning is slow),
# create a probe user (the acked work), kill the DC pod, and assert the restarted DC serves again
# AND still has the probe user. Proof-of-fire: the DC pod is actually replaced.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"

PROBE_USER="${DIR_PROBE_USER:-chaosprobe}"
PROBE_PASS="${DIR_PROBE_PASS:-Aa1!chaosprobe99}"   # AD complexity: upper+lower+digit+symbol
RECOVER_TRIES="${DIR_RECOVER_TRIES:-40}"           # x6s = 240s for the DC to serve again after the kill
EXIT_INCONCLUSIVE=42

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
trap sandbox_teardown_directory EXIT

sandbox_provision_directory

# PRE-FLIGHT — refuse the fault if it could reach anything outside the sandbox.
log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-directory-kill.yaml"

dc_uid() { kubectl -n "$NS" get pod dir-dc-0 -o jsonpath='{.metadata.uid}' 2>/dev/null || true; }

# Proof-of-fire part 1: the domain must actually SERVE before we disrupt it.
log "waiting for the AD domain to provision + serve (samba-tool)"
if ! sandbox_dc_wait_ready 50; then
  log "INCONCLUSIVE — the AD domain never came up (samba-tool never answered). Not counting."
  kubectl -n "$NS" get directory,statefulset,pods -o wide 2>/dev/null | grep -iE 'dir|NAME' || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "domain is serving."

# Create the probe account — the acknowledged work that must survive the fault.
log "creating probe account '${PROBE_USER}' (the acked work)"
if ! sandbox_dc_exec samba-tool user create "$PROBE_USER" "$PROBE_PASS" >/dev/null 2>&1; then
  # already-exists from a prior run is fine; anything else is a setup problem
  if ! sandbox_dc_exec samba-tool user list 2>/dev/null | grep -qx "$PROBE_USER"; then
    log "INCONCLUSIVE — could not create the probe account (setup problem). Not counting."
    exit "$EXIT_INCONCLUSIVE"
  fi
fi
sandbox_dc_exec samba-tool user list 2>/dev/null | grep -qx "$PROBE_USER" || {
  log "INCONCLUSIVE — probe account not present after create. Not counting."; exit "$EXIT_INCONCLUSIVE"; }
log "probe account present before the fault."

# Inject the DC kill.
BEFORE="$(dc_uid)"
log "injecting the DC kill (pod-scoped)"
kubectl apply -f "$HERE/sandbox/fault-directory-kill.yaml"

# Proof-of-fire part 2: the DC pod must actually be replaced.
replaced=0
for _ in $(seq 1 30); do
  a="$(dc_uid)"
  [ -n "$a" ] && [ "$a" != "$BEFORE" ] && { replaced=1; break; }
  sleep 3
done
if [ "$replaced" != 1 ]; then
  log "INCONCLUSIVE — the DC pod was not replaced; the kill didn't land. The oracle won't bless a fault that didn't fire."
  kubectl -n "$NS" get faultinjection,podchaos,pods -l app=dir-dc -o wide 2>/dev/null || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — DC pod killed and replaced (${BEFORE:0:8}… → new)."

# Recover: the restarted DC must serve again AND still have the probe account.
log "waiting for the restarted DC to serve again (up to $(( RECOVER_TRIES * 6 ))s)"
if ! sandbox_dc_wait_ready "$RECOVER_TRIES"; then
  log "FAIL — the DC did NOT serve again within the budget after the kill (directory did not recover — release blocker)."
  kubectl -n "$NS" get pods -l app=dir-dc -o wide 2>/dev/null || true
  exit 1
fi

if sandbox_dc_exec samba-tool user list 2>/dev/null | grep -qx "$PROBE_USER"; then
  log "PASS — the DC recovered and still has account '${PROBE_USER}' after a pod kill (domain database intact, zero identity loss)."
  exit 0
fi
log "FAIL — the DC recovered but account '${PROBE_USER}' is GONE (domain database lost across the kill — release blocker)."
sandbox_dc_exec samba-tool user list 2>/dev/null | head || true
exit 1
