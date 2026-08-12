#!/usr/bin/env bash
# Nightly Chaos Suite — Scenario: VM SURVIVES A VIRT-LAUNCHER KILL (the compute chain; see
# docs/chaos-oracle.md). Recover-mode oracle on the VIRT plane — a KubeVirt VM whose launcher pod is
# killed must be brought back by KubeVirt (runStrategy: Always): the VMI returns to Running as the
# guest reboots from its persistent disk. A VM that stays down is a red.
#
# Chain (2 resource types): a kind: VirtualMachine + a FaultInjection. We wait for the VM to boot
# (VMI Running), kill its virt-launcher pod, and assert the VMI returns to Running. Proof-of-fire:
# the virt-launcher pod is actually replaced. Verification is via the KubeVirt API (VMI phase) — no
# guest access needed, so it's reliable.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"

BOOT_TRIES="${VM_BOOT_TRIES:-70}"        # x6s = 420s for CDI import + first boot
RECOVER_TRIES="${VM_RECOVER_TRIES:-40}"  # x6s = 240s for the VM to return to Running after the kill
EXIT_INCONCLUSIVE=42

# shellcheck source=lib-sandbox.sh
. "$HERE/lib-sandbox.sh"
trap sandbox_teardown_vm EXIT

sandbox_provision_vm

# PRE-FLIGHT — refuse the fault if it could reach anything outside the sandbox.
log "pre-flight guard"
"$HERE/preflight.sh" "$HERE/sandbox/fault-vm-kill.yaml"

launcher_uid() { kubectl -n "$NS" get pods -l kubevirt.io/domain=vm -o jsonpath='{.items[0].metadata.uid}' 2>/dev/null || true; }

# Proof-of-fire part 1: the VM must actually be RUNNING before we disrupt it.
log "waiting for the VM to boot (VMI Running — CDI import + boot, up to $(( BOOT_TRIES * 6 ))s)"
if ! sandbox_vm_wait_running "$BOOT_TRIES"; then
  log "INCONCLUSIVE — the VM never reached Running (import/boot did not complete). Not counting."
  kubectl -n "$NS" get vm,vmi,dv,pods -o wide 2>/dev/null | grep -iE 'vm|NAME' || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "VM is Running."

REPO="$(cd "$HERE/.." && pwd)"
# Delegate the VERDICT to the SINGULAR engine: the Go vm-liveness adapter (recover mode) records the
# pre-fault virt-launcher identity (Drive), then SteadyState requires the fault to have LANDED (the
# launcher pod identity changed) AND the VMI to have returned to Running — runOracle reds on the
# liveness timeout if the VM stays down. This scenario owns provisioning + booting the VM + firing the
# fault + the INCONCLUSIVE gates; the engine owns the verdict (replacing the old bash Running-readback
# PASS/FAIL fork). No data marker on this plane — the verdict is pure liveness.
export CHAOS_SANDBOX_NS="$NS" VM_NAME="vm" VM_LAUNCHER_SELECTOR="kubevirt.io/domain=vm"
export CONV_TIMEOUT="$(( RECOVER_TRIES * 6 ))"   # recover budget: the VM must return to Running within this

( cd "$REPO/apply-sink" && go test -tags convergence -run '^TestVmLiveness$' -timeout 15m -count=1 ./... ) &
GOTEST=$!
sleep "${DRIVE_SETTLE:-6}"   # let Drive record the pre-fault virt-launcher identity BEFORE the kill

# Inject the virt-launcher kill.
BEFORE="$(launcher_uid)"
log "injecting the virt-launcher kill (pod-scoped)"
kubectl apply -f "$HERE/sandbox/fault-vm-kill.yaml"

# Proof-of-fire part 2: the virt-launcher pod must actually be replaced.
replaced=0
for _ in $(seq 1 40); do
  a="$(launcher_uid)"
  [ -n "$a" ] && [ "$a" != "$BEFORE" ] && { replaced=1; break; }
  sleep 3
done
if [ "$replaced" != 1 ]; then
  log "INCONCLUSIVE — the virt-launcher pod was not replaced; the kill didn't land. The oracle won't bless a fault that didn't fire."
  kubectl -n "$NS" get faultinjection,podchaos,pods -l kubevirt.io/domain=vm -o wide 2>/dev/null || true
  kill "$GOTEST" >/dev/null 2>&1 || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — virt-launcher killed and replaced (${BEFORE:0:8}… → new); the adapter judges the VMI returns to Running."

# Recover: KubeVirt must bring the VMI back to Running — the adapter's SteadyState waits for it and
# its exit code IS the verdict.
if wait "$GOTEST"; then
  log "PASS — the VM returned to Running after its virt-launcher was killed (verdict: singular recover engine)."
  exit 0
fi
log "FAIL — the VM did NOT return to Running within the budget after the virt-launcher kill (VM stayed down — release blocker)."
kubectl -n "$NS" get vmi vm -o wide 2>/dev/null || true
kubectl -n "$NS" get pods -l kubevirt.io/domain=vm -o wide 2>/dev/null || true
exit 1
