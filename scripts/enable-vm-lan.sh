#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Enable direct-LAN networking for VMs (kind: VirtualMachine, network: bridge).
#
#   scripts/enable-vm-lan.sh [--interface eno1] [--dry-run]
#
# This is an OPT-IN, network-sensitive step (kept out of install.sh): it installs
# Multus as the cluster's primary CNI (delegating to the existing flannel), adds
# the macvlan reference plugin, and creates a NetworkAttachmentDefinition that
# bridges VMs onto your physical LAN so they pull a real DHCP lease.
#
# Blast radius: existing pods keep their networking; a misconfigured Multus only
# affects NEW pod creation (recoverable). This script self-tests new-pod
# networking after install and prints rollback steps if it regresses.
#
# After it succeeds: label the nodes whose LAN NIC matches --interface
#   kubectl label node <node> openinfra.dev/vm-lan=true
# then create VMs with `network: bridge`.
# ─────────────────────────────────────────────────────────────
set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${REPO_DIR}/config.yaml"
MULTUS_VERSION="v4.1.0"
CNI_PLUGINS_VERSION="v1.5.1"
IFACE=""; DRY_RUN=0
LOG() { printf '\033[1;36m[vm-lan]\033[0m %s\n' "$*"; }
WARN(){ printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
DIE() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do case "$1" in
  --interface) IFACE="$2"; shift 2 ;;
  --dry-run) DRY_RUN=1; shift ;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -20; exit 0 ;;
  *) DIE "unknown arg: $1" ;;
esac; done

command -v kubectl >/dev/null || DIE "kubectl is required"
# Fall back to config.yaml networking.vmLan.interface.
if [ -z "$IFACE" ] && [ -f "$CONFIG" ]; then
  IFACE="$(awk '/^  vmLan:/{f=1} f&&/interface:/{sub(/.*interface:[ ]*/,"");sub(/[ ]*#.*/,"");print;exit}' "$CONFIG")"
fi
[ -n "$IFACE" ] || DIE "no LAN interface — pass --interface <nic> or set networking.vmLan.interface"
LOG "LAN interface (macvlan parent): $IFACE"
RUN(){ if [ "$DRY_RUN" = 1 ]; then printf '  + %s\n' "$*"; else eval "$@"; fi; }

K3S_CNI_BIN="/var/lib/rancher/k3s/data/current/bin"
K3S_CNI_CONF="/var/lib/rancher/k3s/agent/etc/cni/net.d"

# 1. Install the reference CNI plugins (macvlan, static, tuning) into k3s' bin dir
#    via a one-shot DaemonSet (k3s ships only a minimal set).
LOG "installing CNI reference plugins ${CNI_PLUGINS_VERSION} (macvlan…)"
RUN "cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata: { name: install-cni-plugins, namespace: kube-system }
spec:
  selector: { matchLabels: { app: install-cni-plugins } }
  template:
    metadata: { labels: { app: install-cni-plugins } }
    spec:
      hostNetwork: true
      tolerations: [ { operator: Exists } ]
      initContainers:
        - name: install
          image: curlimages/curl:8.10.1
          securityContext: { runAsUser: 0 }
          command: [sh, -c]
          args:
            - |
              set -e
              cd /tmp
              curl -sfL https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-amd64-${CNI_PLUGINS_VERSION}.tgz | tar xz
              for p in macvlan static tuning host-local; do cp -f \\\$p /host/bin/ && echo installed \\\$p; done
          volumeMounts: [ { name: bin, mountPath: /host/bin } ]
      containers:
        - name: pause
          image: registry.k8s.io/pause:3.9
      volumes:
        - name: bin
          hostPath: { path: ${K3S_CNI_BIN} }
EOF"
RUN "kubectl -n kube-system rollout status ds/install-cni-plugins --timeout=180s || true"

# 2. Install Multus (thick), pointed at k3s' CNI paths. Multus becomes the primary
#    CNI and delegates the default network to the existing flannel config.
LOG "installing Multus ${MULTUS_VERSION} (k3s paths)"
RUN "curl -sfL https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/${MULTUS_VERSION}/deployments/multus-daemonset-thick.yml \
  | sed -e 's#/etc/cni/net.d#${K3S_CNI_CONF}#g' -e 's#/opt/cni/bin#${K3S_CNI_BIN}#g' \
  | kubectl apply -f -"
RUN "kubectl -n kube-system rollout status ds/kube-multus-ds --timeout=180s || true"

# 3. Self-test: a NEW pod must still get networking (proves Multus delegates OK).
if [ "$DRY_RUN" = 0 ]; then
  LOG "self-test: scheduling a throwaway pod to confirm new-pod networking…"
  kubectl run vmlan-selftest --image=busybox:1.36 --restart=Never -- sleep 30 >/dev/null 2>&1 || true
  if kubectl wait --for=condition=Ready pod/vmlan-selftest --timeout=60s >/dev/null 2>&1; then
    LOG "✅ new pods still get networking — Multus is delegating correctly."
    kubectl delete pod vmlan-selftest --wait=false >/dev/null 2>&1 || true
  else
    kubectl delete pod vmlan-selftest --wait=false >/dev/null 2>&1 || true
    WARN "new-pod networking FAILED after Multus install. Roll back on each node:"
    WARN "  sudo rm ${K3S_CNI_CONF}/00-multus.conf*; kubectl -n kube-system delete ds kube-multus-ds"
    DIE "aborting before creating the NAD — fix or roll back first."
  fi
fi

# 4. The NetworkAttachmentDefinition: macvlan onto the LAN NIC, NO IPAM — the VM
#    guest pulls its own DHCP lease from the LAN router.
LOG "creating NetworkAttachmentDefinition default/openinfra-lan (master=$IFACE)"
RUN "cat <<EOF | kubectl apply -f -
apiVersion: k8s.cni.cncf.io/v1
kind: NetworkAttachmentDefinition
metadata: { name: openinfra-lan, namespace: default }
spec:
  config: |
    {
      \"cniVersion\": \"0.3.1\",
      \"type\": \"macvlan\",
      \"master\": \"${IFACE}\",
      \"mode\": \"bridge\",
      \"ipam\": {}
    }
EOF"

cat <<NEXT

✅ VM LAN networking enabled.

Next:
  1. Label the nodes whose LAN NIC is '${IFACE}' (bridged VMs schedule only there):
       kubectl label node <node> openinfra.dev/vm-lan=true
     (NICs may differ per node — check with: ip route show default)
  2. Create a VM with  network: bridge  (or pick "Bridged to LAN" in the console).
     The guest pulls a real LAN DHCP lease; reach it directly, no MetalLB.

Note: macvlan does not allow the *host node* to talk to its own bridged VMs
(other LAN hosts can). See docs/virtual-machines.md.
NEXT
LOG "done."
