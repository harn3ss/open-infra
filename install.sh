#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# open-infra one-command bootstrap.
#
#   cp config.example.yaml config.yaml   # edit first
#   ./install.sh                          # idempotent; safe to re-run
#   ./install.sh --dry-run                # print what would happen, change nothing
#
# Installs k3s, bootstraps Argo CD, and applies the app-of-apps so the rest of
# the platform installs itself declaratively. Designed for commodity Linux.
# ─────────────────────────────────────────────────────────────
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${REPO_DIR}/config.yaml"
DRY_RUN=0
LOG()  { printf '\033[1;36m[open-infra]\033[0m %s\n' "$*"; }
WARN() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
DIE()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }
RUN()  { if [ "$DRY_RUN" = 1 ]; then printf '  + %s\n' "$*"; else eval "$@"; fi; }

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -16; exit 0 ;;
    *) DIE "unknown arg: $arg" ;;
  esac
done

# ── 0. Preflight ─────────────────────────────────────────────
[ -f "$CONFIG" ] || DIE "missing config.yaml — run: cp config.example.yaml config.yaml && edit it"
command -v curl >/dev/null || DIE "curl is required"
[ "$(id -u)" -ne 0 ] || WARN "running as root; a non-root user with sudo is recommended"

# Tiny dependency-free YAML reader for the flat keys we need.
# (Good enough for config.yaml; not a general YAML parser.)
yget() { # yget some.nested.key  -> value (or empty)
  awk -v path="$1" '
    function indent(s){ match(s,/^ */); return RLENGTH }
    /^[ \t]*$/ { next }          # skip blank lines (would reset the key stack)
    /^[ \t]*#/ { next }          # skip comments (may contain colons)
    { lvl=indent($0); key=$0; sub(/^ +/,"",key); sub(/:.*/,"",key)
      stack[lvl]=key; full=""
      for(i=0;i<=lvl;i+=2){ full=full (full?".":"") stack[i] }
      if(full==path){ v=$0
        sub(/^[^:]*:[ \t]*/,"",v)   # strip "key:"
        sub(/[ \t]+#.*$/,"",v)       # strip trailing inline comment
        sub(/[ \t]+$/,"",v)          # trim trailing whitespace
        gsub(/^"|"$/,"",v)           # strip surrounding quotes
        print v; exit } }
  ' "$CONFIG"
}

MODE="$(yget mode)";            MODE="${MODE:-dev}"
CLUSTER_NAME="$(yget cluster.name)"; CLUSTER_NAME="${CLUSTER_NAME:-open-infra}"
K3S_CHANNEL="$(yget cluster.k3sChannel)"; K3S_CHANNEL="${K3S_CHANNEL:-stable}"
METALLB_POOL="$(yget networking.metallbPool)"
GITOPS_REPO="$(yget gitops.repoUrl)"
GITOPS_PATH="$(yget gitops.path)"; GITOPS_PATH="${GITOPS_PATH:-deploy}"

# Per-component install toggles (config.yaml `components.*`). Default = install
# everything; a component set to "false" is excluded from the app-of-apps include
# path. (console manifests/ are always excluded — deployed by the console child app.)
EXCLUDES="**/manifests/**"
excl() {
  if [ "$(yget "components.$1")" = "false" ]; then
    EXCLUDES="${EXCLUDES},$2"
    LOG "component disabled: $1"
  fi
}
excl minio         "storage/minio.yaml,storage/minio-ha.yaml"
excl cloudnativePG "data/cloudnativepg.yaml"
excl nats          "data/nats.yaml"
excl redis         "data/redis.yaml"
excl observability "observability/*"
excl sealedSecrets "security/sealed-secrets.yaml"
excl crossplane    "abstraction/*"
excl console       "console/*"
excl serverless    "serverless/*"
excl gpu           "gpu/*"
excl velero        "backup/*"
excl mariadbOperator "data/mariadb-operator.yaml"
excl airbyte       "data/airbyte.yaml"

# MinIO topology: standalone (storage/minio.yaml) by default; HA selects the
# distributed variant (storage/minio-ha.yaml). Exactly one is included — we do
# NOT default to HA. (Skip when MinIO is disabled — both already excluded above.)
if [ "$(yget components.minio)" != "false" ]; then
  if [ "$(yget storage.highAvailability)" = "true" ]; then
    EXCLUDES="${EXCLUDES},storage/minio.yaml"
    LOG "storage: MinIO HA (distributed)"
  else
    EXCLUDES="${EXCLUDES},storage/minio-ha.yaml"
  fi
fi
case "$EXCLUDES" in *,*) EXCLUDE_GLOB="{${EXCLUDES}}";; *) EXCLUDE_GLOB="$EXCLUDES";; esac

LOG "mode=$MODE cluster=$CLUSTER_NAME k3s=$K3S_CHANNEL"
[ "$DRY_RUN" = 1 ] && LOG "DRY RUN — no changes will be made"

# ── 1. k3s server ────────────────────────────────────────────
if command -v k3s >/dev/null 2>&1; then
  LOG "k3s already installed — skipping install"
else
  LOG "installing k3s (server)…"
  # Traefik ships with k3s; we keep it (see docs). servicelb disabled in favor of MetalLB.
  RUN "curl -sfL https://get.k3s.io | INSTALL_K3S_CHANNEL='$K3S_CHANNEL' sh -s - server --disable servicelb --write-kubeconfig-mode 0644"
fi

export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
KUBECTL="k3s kubectl"
$KUBECTL version >/dev/null 2>&1 || [ "$DRY_RUN" = 1 ] || DIE "k3s not responding; check: systemctl status k3s"

# ── 2. MetalLB (L2) ──────────────────────────────────────────
if [ -z "$METALLB_POOL" ]; then
  WARN "networking.metallbPool unset — LoadBalancer services won't get IPs. Set a reserved LAN range."
else
  LOG "configuring MetalLB pool: $METALLB_POOL"
  RUN "$KUBECTL apply -f https://raw.githubusercontent.com/metallb/metallb/v0.14.8/config/manifests/metallb-native.yaml"
  RUN "$KUBECTL -n metallb-system wait --for=condition=available deploy/controller --timeout=120s || true"
  # The pool/L2Advertisement carry your LAN IPs, so they are rendered at runtime, not committed.
  if [ "$DRY_RUN" = 1 ]; then
    printf '  + apply IPAddressPool(%s) + L2Advertisement\n' "$METALLB_POOL"
  else
    cat <<EOF | $KUBECTL apply -f -
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata: { name: default-pool, namespace: metallb-system }
spec: { addresses: ["$METALLB_POOL"] }
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata: { name: default-l2, namespace: metallb-system }
spec: { ipAddressPools: [default-pool] }
EOF
  fi
fi

# ── 2b. KubeVirt + CDI (VMs) ─────────────────────────────────
# Cluster virtualization for the kind: VirtualMachine (EC2) abstraction. Installed
# from upstream release manifests (like MetalLB), not Argo. Needs hardware virt
# (/dev/kvm) on the nodes. The abstraction's XRD/Composition ship with Crossplane.
if [ "$(yget components.virtualization)" = "false" ]; then
  LOG "component disabled: virtualization (KubeVirt/CDI)"
else
  KUBEVIRT_VERSION="v1.8.4"; CDI_VERSION="v1.65.0"
  LOG "installing KubeVirt ${KUBEVIRT_VERSION} + CDI ${CDI_VERSION} (VMs)…"
  RUN "$KUBECTL apply -f https://github.com/kubevirt/kubevirt/releases/download/${KUBEVIRT_VERSION}/kubevirt-operator.yaml"
  RUN "$KUBECTL apply -f https://github.com/kubevirt/kubevirt/releases/download/${KUBEVIRT_VERSION}/kubevirt-cr.yaml"
  # Opt into HotplugVolumes (attach/detach EBS-style volumes to running VMs) and
  # Snapshot (VM/volume snapshots) — both are feature-gated in v1.8.4, not GA.
  RUN "$KUBECTL patch kubevirt kubevirt -n kubevirt --type=merge -p '{\"spec\":{\"configuration\":{\"developerConfiguration\":{\"featureGates\":[\"HotplugVolumes\",\"Snapshot\"]}}}}'"
  RUN "$KUBECTL apply -f https://github.com/kubevirt/containerized-data-importer/releases/download/${CDI_VERSION}/cdi-operator.yaml"
  RUN "$KUBECTL apply -f https://github.com/kubevirt/containerized-data-importer/releases/download/${CDI_VERSION}/cdi-cr.yaml"
  RUN "$KUBECTL -n kubevirt wait --for=condition=Available kubevirt/kubevirt --timeout=300s || true"
  # Holds the golden Windows image (cloned per-VM). Created empty; see docs.
  RUN "$KUBECTL create namespace openinfra-images --dry-run=client -o yaml | $KUBECTL apply -f -"
fi

# ── 2c. VM direct-LAN networking (bridge) ────────────────────
# Opt-in (networking.vmLan.enabled): installs Multus + the macvlan plugin so
# kind: VirtualMachine network=bridge can attach VMs straight to the physical LAN
# (real DHCP lease). Auto-labels nodes that actually have the LAN NIC, so bridged
# VMs schedule only where they can work. Self-service: a config flag, no manual
# scripts. Multus changes the cluster CNI (delegates to flannel), hence opt-in.
if [ "$(yget networking.vmLan.enabled)" = "true" ]; then
  VMLAN_IFACE="$(yget networking.vmLan.interface)"; VMLAN_IFACE="${VMLAN_IFACE:-eno1}"
  MULTUS_VERSION="v4.1.0"; CNI_PLUGINS_VERSION="v1.5.1"
  K3S_CNI_BIN="/var/lib/rancher/k3s/data/current/bin"
  K3S_CNI_CONF="/var/lib/rancher/k3s/agent/etc/cni/net.d"
  LOG "VM LAN bridge: Multus + macvlan (parent NIC: $VMLAN_IFACE)…"
  if [ "$DRY_RUN" = 1 ]; then
    printf '  + install macvlan plugin + Multus %s; create NAD; label nodes with %s\n' "$MULTUS_VERSION" "$VMLAN_IFACE"
  else
    # 1. macvlan reference plugin into k3s' CNI bin (k3s ships a minimal set).
    cat <<EOF | $KUBECTL apply -f - || WARN "macvlan plugin install failed"
apiVersion: apps/v1
kind: DaemonSet
metadata: { name: openinfra-cni-plugins, namespace: kube-system }
spec:
  selector: { matchLabels: { app: openinfra-cni-plugins } }
  template:
    metadata: { labels: { app: openinfra-cni-plugins } }
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
              cd /tmp
              curl -sfL https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-amd64-${CNI_PLUGINS_VERSION}.tgz | tar xz
              for p in macvlan static tuning; do cp -f \$p /host/bin/ && echo installed \$p; done
          volumeMounts: [ { name: bin, mountPath: /host/bin } ]
      containers:
        - { name: pause, image: registry.k8s.io/pause:3.9 }
      volumes:
        - { name: bin, hostPath: { path: ${K3S_CNI_BIN} } }
EOF
    # 2. Multus (thick), pointed at k3s' CNI paths; delegates default to flannel.
    curl -sfL "https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/${MULTUS_VERSION}/deployments/multus-daemonset-thick.yml" \
      | sed -e "s#/etc/cni/net.d#${K3S_CNI_CONF}#g" -e "s#/opt/cni/bin#${K3S_CNI_BIN}#g" \
      | $KUBECTL apply -f - || WARN "Multus install failed"
    $KUBECTL -n kube-system rollout status ds/kube-multus-ds --timeout=180s || WARN "Multus not ready yet"
    # 3. The macvlan NetworkAttachmentDefinition (no IPAM -> guest DHCP).
    cat <<EOF | $KUBECTL apply -f - || WARN "NAD create failed"
apiVersion: k8s.cni.cncf.io/v1
kind: NetworkAttachmentDefinition
metadata: { name: openinfra-lan, namespace: default }
spec:
  config: '{ "cniVersion": "0.3.1", "type": "macvlan", "master": "${VMLAN_IFACE}", "mode": "bridge", "ipam": {} }'
EOF
    # 4. Auto-label nodes that actually have the LAN NIC (handles per-node NIC
    #    name differences — only matching nodes can host bridged VMs).
    for node in $($KUBECTL get nodes -o jsonpath='{.items[*].metadata.name}'); do
      has="$($KUBECTL run vmlan-detect-${node%%.*} --rm -i --restart=Never --image=busybox:1.36 \
        --overrides="{\"spec\":{\"hostNetwork\":true,\"nodeName\":\"$node\",\"tolerations\":[{\"operator\":\"Exists\"}],\"containers\":[{\"name\":\"d\",\"image\":\"busybox:1.36\",\"command\":[\"sh\",\"-c\",\"[ -d /sys/class/net/$VMLAN_IFACE ] && echo yes || echo no\"]}]}}" 2>/dev/null | tr -d '[:space:]')" || has="no"
      case "$has" in
        *yes*) $KUBECTL label node "$node" openinfra.dev/vm-lan=true --overwrite >/dev/null 2>&1 && LOG "  $node has $VMLAN_IFACE → labelled vm-lan" ;;
        *)     $KUBECTL label node "$node" openinfra.dev/vm-lan- >/dev/null 2>&1 || true ;;
      esac
    done
  fi
fi

# ── 3. Argo CD ───────────────────────────────────────────────
LOG "installing Argo CD…"
RUN "$KUBECTL create namespace argocd --dry-run=client -o yaml | $KUBECTL apply -f -"
RUN "$KUBECTL -n argocd apply --server-side --force-conflicts -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml"
RUN "$KUBECTL -n argocd rollout status deploy/argocd-server --timeout=300s || true"

# ── 4. App-of-apps ───────────────────────────────────────────
if [ -z "$GITOPS_REPO" ]; then
  WARN "gitops.repoUrl unset — applying the bundled root-app pointed at THIS repo for a local trial."
  GITOPS_REPO="https://github.com/harn3ss/open-infra"
  GITOPS_PATH="platform"
fi
LOG "bootstrapping app-of-apps from $GITOPS_REPO ($GITOPS_PATH)…"
# root-app.yaml carries no private values; repo/path are patched in at apply time.
if [ "$DRY_RUN" = 1 ]; then
  printf '  + apply platform/root-app.yaml (repoURL=%s path=%s exclude=%s)\n' "$GITOPS_REPO" "$GITOPS_PATH" "$EXCLUDE_GLOB"
else
  sed -e "s#__REPO_URL__#${GITOPS_REPO}#g" -e "s#__PATH__#${GITOPS_PATH}#g" \
    -e "s#'\*\*/manifests/\*\*'#'${EXCLUDE_GLOB}'#g" \
    "${REPO_DIR}/platform/root-app.yaml" | $KUBECTL apply -f -
fi

# ── Done ─────────────────────────────────────────────────────
LOG "bootstrap complete."
cat <<'NEXT'

Next steps:
  • Watch the platform converge:   k3s kubectl -n argocd get applications
  • Argo CD admin password:        k3s kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d; echo
  • Port-forward the Argo UI:       k3s kubectl -n argocd port-forward svc/argocd-server 8080:443
  • Deploy your first app:          ./cli/open-infra init && ./cli/open-infra deploy

Full walkthrough: docs/quickstart.md
NEXT
