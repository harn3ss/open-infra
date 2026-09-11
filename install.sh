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
AUDIT_LOG_DIR="$(yget cluster.auditLogDir)"; AUDIT_LOG_DIR="${AUDIT_LOG_DIR:-/var/lib/rancher/k3s/server/logs}"
METALLB_POOL="$(yget networking.metallbPool)"
GITOPS_REPO="$(yget gitops.repoUrl)"
GITOPS_PATH="$(yget gitops.path)"; GITOPS_PATH="${GITOPS_PATH:-deploy}"

# ── Audit-log portability preflight (#15) ────────────────────
# The audit-trail features (off-siting to WORM + the console CloudTrail view) read
# the API-server audit log from a HOST directory (cluster.auditLogDir), which is
# k3s-shaped by default. On other distributions the path differs, and a wrong path
# yields a SILENTLY empty audit trail. Probe the node so it fails LOUDLY here instead.
# Best-effort: only meaningful when install.sh runs on a control-plane node (the norm).
audit_preflight() {
  [ -d /etc/rancher ] || [ -d /var/lib/rancher ] || [ -d /etc/kubernetes ] || return 0
  if [ -f "$AUDIT_LOG_DIR/audit.log" ]; then
    LOG "audit log present at $AUDIT_LOG_DIR (cluster.auditLogDir)"
    return 0
  fi
  local found=""
  for d in /var/lib/rancher/k3s/server/logs /var/lib/rancher/rke2/server/logs /var/log/kubernetes/audit; do
    [ -f "$d/audit.log" ] && found="$d" && break
  done
  if [ -n "$found" ]; then
    WARN "API-server audit log is at $found, but cluster.auditLogDir=$AUDIT_LOG_DIR."
    WARN "  Audit off-siting + the console CloudTrail view will be EMPTY until these match."
    WARN "  Set cluster.auditLogDir: $found and the flagged hostPath in both"
    WARN "  platform/observability/promtail.yaml and platform/security/audit-offsite.yaml."
    WARN "  See docs/portability.md."
  else
    WARN "No API-server audit log found at $AUDIT_LOG_DIR or known k3s/RKE2/kubeadm paths."
    WARN "  If audit logging isn't enabled on the API server, the audit-trail features won't"
    WARN "  work — enable --audit-log-path + --audit-policy-file and point cluster.auditLogDir"
    WARN "  at its directory. See docs/portability.md."
  fi
}
audit_preflight

# Per-component install toggles (config.yaml `components.*`). Default = install
# everything; a component set to "false" is excluded from the app-of-apps include
# path. (console manifests/ are always excluded — deployed by the console child app.)
# security/apiserver/* is kube-apiserver config read off disk (the audit policy),
# not a cluster resource — Argo must never try to apply it. See platform/root-app.yaml.
EXCLUDES="**/manifests/**,security/apiserver/**,abstraction/policy-boundary.yaml"
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
excl lakehouse     "query/*" # Trino + Iceberg REST catalog (DuckDB Query needs none of this)

# Opt-in, OFF by default (experimental surfaces): exclude UNLESS explicitly enabled — the inverse
# of excl(). The base EXCLUDES doesn't list these, so they must be excluded unless set to "true"
# (mirrors networking.vmLan.enabled / storage.highAvailability). Flip components.awsShim: true and
# re-run install.sh to bring the AWS-SDK shim up.
incl() {
  if [ "$(yget "components.$1")" != "true" ]; then
    EXCLUDES="${EXCLUDES},$2"
    LOG "component (opt-in) not enabled: $1"
  fi
}
incl awsShim "aws-shim/*"
incl openAppsync "open-appsync/*" # open-appsync engine (backs the shim's AppSync surface)
# Customer-owned encryption: Vault (Transit KMS), kind: EncryptionKey + its reconciler, and the
# encrypted Longhorn StorageClass. OFF unless components.encryption: true (Vault needs an operator to
# initialize/unseal it — see docs/encryption.md).
incl encryption "abstraction/encryptionkey-xrd.yaml,abstraction/encryptionkey-composition.yaml,abstraction/destruction-xrd.yaml,abstraction/destruction-composition.yaml,abstraction/parameter-xrd.yaml,abstraction/parameter-composition.yaml,security/vault.yaml,security/encryptionkey-reconciler.yaml,security/destruction-reconciler.yaml,security/parameter-reconciler.yaml,storage/longhorn-encrypted.yaml,security/volume-crypto.yaml,security/luks-host-prereq.yaml"
# Private certificate authority: kind: CertificateAuthority (its XRD/composition), the Vault-PKI
# reconciler, and the synchronous ca-issuer. OFF unless components.pki: true; RIDES ON the encryption
# component (reuses its Vault + Kubernetes-auth wiring — see docs/certificate-authority.md).
incl pki "abstraction/certificateauthority-xrd.yaml,abstraction/certificateauthority-composition.yaml,security/ca-reconciler.yaml,security/ca-issuer.yaml"
# Object encryption at rest: MinIO SSE-KMS via MinIO KES → Vault KV, with crypto-erase (destroy the key
# → objects unreadable). OFF unless components.objectEncryption: true; RIDES ON the encryption component
# (reuses its Vault + the minio-kes k8s-auth identity). Ships KES + certs; it does NOT touch the live
# MinIO — turning SSE-KMS on for the platform MinIO is a deliberate, snapshot-first step (docs/encryption.md).
incl objectEncryption "security/minio-kes.yaml"
# Transactional email: kind: EmailSender (its XRD/composition) + the shared in-cluster SMTP relay.
# OFF unless components.mail: true. Reliable internet delivery needs a smarthost/SPF/DKIM — an
# operator concern; see docs/email.md.
incl mail "abstraction/emailsender-xrd.yaml,abstraction/emailsender-composition.yaml,mail/relay.yaml"
# Daily immutable compliance-attestation snapshots to the WORM audit store. OFF by default; requires
# audit off-siting. Signing is an out-of-band operator/CI step (docs/compliance-attestation.md).
incl attestation "security/compliance-attest.yaml"
# Air-gap support (issue #72): the in-cluster registry mirror + image prefetch — the "front-load"
# half. OFF by default (internet stays allowed). Safe to enable on-net; it severs nothing.
incl airgap "airgap/registry-mirror.yaml,airgap/image-prefetch.yaml,airgap/node-registries.yaml"
# The public-egress cutoff is a SEPARATE, deliberate election: applied ONLY when the airgap component
# is on AND airgap.denyPublicEgress is true. Front-load the mirror and point nodes at it first, or
# image pulls will fail once the internet is cut (docs/airgapping.md). Reversible: flip back + re-sync.
if [ "$(yget components.airgap)" = "true" ] && [ "$(yget airgap.denyPublicEgress)" = "true" ]; then
  # The egress cutoff is CNI-specific: Cilium uses a CiliumClusterwideNetworkPolicy (cilium.io/v2),
  # Calico/Canal a GlobalNetworkPolicy (projectcalico.org/v3). Detect each by the EXACT resource its
  # manifest applies — not a proxy — so the guard can't pass while the target is unappliable or vice
  # versa. Cilium's CCNP is a plain CRD, so `get crd …cilium.io` is exact. Calico's projectcalico.org/v3
  # is served by the Calico APISERVER (aggregated), NOT the underlying crd.projectcalico.org (v1) CRD —
  # so checking that CRD is the wrong surface (it can exist while v3 is unserved, e.g. CRD-only Calico,
  # → the v3 manifest would fail). Probe the served v3 resource path directly instead. If neither is
  # present, skip the cutoff (front-load only) rather than hard-failing on "no matches for kind".
  if $KUBECTL get crd ciliumclusterwidenetworkpolicies.cilium.io >/dev/null 2>&1; then
    LOG "air-gap cutoff ELECTED — Cilium detected; using egress-deny.yaml (CiliumClusterwideNetworkPolicy)"
    EXCLUDES="${EXCLUDES},airgap/egress-deny-calico.yaml"
  elif $KUBECTL get --raw /apis/projectcalico.org/v3/globalnetworkpolicies >/dev/null 2>&1; then
    LOG "air-gap cutoff ELECTED — Calico/Canal detected (projectcalico.org/v3 served); using egress-deny-calico.yaml (GlobalNetworkPolicy)"
    EXCLUDES="${EXCLUDES},airgap/egress-deny.yaml"
  else
    LOG "air-gap cutoff ELECTED but no Cilium CRD / served projectcalico.org/v3 present — SKIPPING the egress cutoff (front-load only; add egress denial in your CNI)"
    EXCLUDES="${EXCLUDES},airgap/egress-deny.yaml,airgap/egress-deny-calico.yaml"
  fi
else
  EXCLUDES="${EXCLUDES},airgap/egress-deny.yaml,airgap/egress-deny-calico.yaml"
fi
# Hardened deployment profile: enforce restricted Pod Security Standards on the control
# plane + warn/audit elsewhere. OFF by default (opt-in for a production/authorized deploy —
# see docs/security-and-compliance.md). Do not enable until workloads are PSS-compliant.
incl hardened "security/hardened-profile.yaml"

# LAN-exposure controller (networking.lanExpose.enabled — nested, so not a components.* key):
# exclude the manifest unless explicitly enabled. Its site-specific config ConfigMap is
# rendered at runtime below (like the MetalLB pool), not committed.
if [ "$(yget networking.lanExpose.enabled)" != "true" ]; then
  EXCLUDES="${EXCLUDES},networking/lan-expose.yaml"
  LOG "networking.lanExpose not enabled"
fi

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
  # CNI: flannel + the embedded network-policy controller are disabled — kube-ovn
  # (installed next) is the CNI and enforces NetworkPolicy (incl. ipBlock/CIDR, the
  # basis for kind: SecurityGroup). kube-proxy is KEPT (kube-ovn relies on it for
  # ClusterIP services, --enable-lb-svc=false) — unlike a Cilium kube-proxy-replacement.
  RUN "curl -sfL https://get.k3s.io | INSTALL_K3S_CHANNEL='$K3S_CHANNEL' sh -s - server --disable servicelb --flannel-backend=none --disable-network-policy --write-kubeconfig-mode 0644"
fi

export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
KUBECTL="k3s kubectl"
$KUBECTL version >/dev/null 2>&1 || [ "$DRY_RUN" = 1 ] || DIE "k3s not responding; check: systemctl status k3s"

# ── 1b. kube-ovn CNI ─────────────────────────────────────────
# kube-ovn is the cluster CNI (migration #120): it provides pod networking, real
# NetworkPolicy enforcement (incl. ipBlock/CIDR — the basis for kind: SecurityGroup),
# and the OVN-native VPC/Subnet/EIP objects that the kind: Vpc/Subnet abstractions and
# the lan-expose external gateway (§2a-gw) build on. Installed directly (not via Argo)
# because it IS the network — it must be up before any other pod gets an IP. k3s's
# kube-proxy is left in place (kube-ovn uses it for ClusterIP services).
KUBEOVN_VERSION="v1.14.41"       # pinned to the version proven in-cluster
KUBEOVN_SVC_CIDR="10.43.0.0/16"  # k3s's service CIDR (the installer defaults to 10.96/12)
if $KUBECTL -n kube-system get ds/kube-ovn-cni >/dev/null 2>&1; then
  LOG "kube-ovn already installed — skipping"
elif [ "$DRY_RUN" = 1 ]; then
  printf '  + install kube-ovn %s (POD_CIDR 10.16.0.0/16, SVC_CIDR %s, JOIN 100.64.0.0/16, enable-eip-snat)\n' "$KUBEOVN_VERSION" "$KUBEOVN_SVC_CIDR"
else
  LOG "installing kube-ovn ${KUBEOVN_VERSION} (CNI)…"
  # The upstream installer hardcodes its CIDRs (they are NOT env-overridable), so fetch
  # the pinned script and rewrite SVC_CIDR to k3s's before running. POD_CIDR (10.16/16),
  # JOIN_CIDR (100.64/16), REGISTRY, VERSION and the control-plane LABEL already match;
  # ENABLE_EIP_SNAT defaults true — it drives the default-VPC external gateway (§2a-gw).
  # kubectl resolves via the k3s symlink and KUBECONFIG is exported above.
  KUBEOVN_INSTALLER="$(mktemp)"
  curl -sfL "https://raw.githubusercontent.com/kubeovn/kube-ovn/${KUBEOVN_VERSION}/dist/images/install.sh" -o "$KUBEOVN_INSTALLER" \
    || DIE "failed to download kube-ovn installer ${KUBEOVN_VERSION}"
  sed -i "s#^SVC_CIDR=.*#SVC_CIDR=\"${KUBEOVN_SVC_CIDR}\"#" "$KUBEOVN_INSTALLER"
  bash "$KUBEOVN_INSTALLER" || DIE "kube-ovn install failed"
  rm -f "$KUBEOVN_INSTALLER"
fi

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
    # metallbPool may be comma-separated (leaving gaps for lanExpose FIP IPs); render
    # each range as its own addresses[] entry.
    MLB_ADDR_YAML=""
    IFS=',' read -ra _mlb <<<"$METALLB_POOL"
    for a in "${_mlb[@]}"; do
      MLB_ADDR_YAML="${MLB_ADDR_YAML}    - \"${a}\""$'\n'
    done
    cat <<EOF | $KUBECTL apply -f -
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata: { name: default-pool, namespace: metallb-system }
spec:
  addresses:
$MLB_ADDR_YAML---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata: { name: default-l2, namespace: metallb-system }
spec: { ipAddressPools: [default-pool] }
EOF
  fi
fi

# ── 2a. lan-expose controller config (networking.lanExpose) ──
# The controller's addressing (LAN CIDR + EIP range) is site-specific, so — like the
# MetalLB pool — it is rendered into a ConfigMap at runtime, not committed. The
# Deployment (platform/networking/lan-expose.yaml) is included by the root-app only
# when enabled (see the exclude above).
if [ "$(yget networking.lanExpose.enabled)" = "true" ]; then
  LAN_EXPOSE_CIDR="$(yget networking.lanExpose.lanCIDR)"
  LAN_EXPOSE_RANGE="$(yget networking.lanExpose.eipRange)"
  LAN_EXPOSE_SUBNET="$(yget networking.lanExpose.externalSubnet)"; LAN_EXPOSE_SUBNET="${LAN_EXPOSE_SUBNET:-external}"
  if [ -z "$LAN_EXPOSE_CIDR" ] || [ -z "$LAN_EXPOSE_RANGE" ]; then
    WARN "networking.lanExpose.enabled but lanCIDR/eipRange unset — controller will crashloop until set."
  fi
  LOG "configuring lan-expose: EIP range $LAN_EXPOSE_RANGE on $LAN_EXPOSE_CIDR (subnet $LAN_EXPOSE_SUBNET)"
  if [ "$DRY_RUN" = 1 ]; then
    printf '  + apply ConfigMap lan-expose-config (EIP range %s)\n' "$LAN_EXPOSE_RANGE"
  else
    cat <<EOF | $KUBECTL apply -f -
apiVersion: v1
kind: ConfigMap
metadata: { name: lan-expose-config, namespace: kube-system }
data:
  LAN_CIDR: "$LAN_EXPOSE_CIDR"
  EIP_RANGE: "$LAN_EXPOSE_RANGE"
  EXTERNAL_SUBNET: "$LAN_EXPOSE_SUBNET"
  DEFAULT_VPC: "ovn-cluster"
EOF
  fi
fi

# ── 2a-gw. lan-expose external-gateway substrate (networking.lanExpose.gateway) ──
# The kube-ovn default-VPC external gateway that makes the operator's FIPs reachable
# from the physical LAN — the hand-built recipe in memory kube-ovn-lan-exposure, now
# config-driven so a from-scratch rebuild reproduces it with no manual OVN steps. All
# site addressing comes from config.yaml, so this public script carries no site IPs.
# Guarded on kube-ovn being the CNI (the ProviderNetwork/Subnet/OvnEip CRDs): on a
# non-kube-ovn cluster it warns and skips instead of erroring.
GW_NODE="$(yget networking.lanExpose.gateway.node)"
if [ "$(yget networking.lanExpose.enabled)" = "true" ] && [ -n "$GW_NODE" ]; then
  GW_IFACE="$(yget networking.lanExpose.gateway.interface)";  GW_IFACE="${GW_IFACE:-eno1}"
  GW_ROUTER="$(yget networking.lanExpose.gateway.routerIP)"
  GW_LRP="$(yget networking.lanExpose.gateway.lrpIP)"
  GW_CIDR="$(yget networking.lanExpose.lanCIDR)"
  GW_EXCL_IPS="$(yget networking.lanExpose.gateway.subnetExcludeIps)"
  GW_EXT_SUBNET="$(yget networking.lanExpose.externalSubnet)"; GW_EXT_SUBNET="${GW_EXT_SUBNET:-external}"
  GW_PREFIX="${GW_CIDR##*/}" # e.g. 192.0.2.0/24 -> 24, for external-gw-addr
  if [ "$DRY_RUN" != 1 ] && ! $KUBECTL get crd provider-networks.kubeovn.io >/dev/null 2>&1; then
    WARN "networking.lanExpose.gateway set but kube-ovn CRDs absent — skipping external gateway (kube-ovn must be the CNI)."
  else
    LOG "configuring kube-ovn external gateway: node $GW_NODE ($GW_IFACE), router $GW_ROUTER, LRP $GW_LRP"
    if [ "$DRY_RUN" = 1 ]; then
      printf '  + label node %s ovn.kubernetes.io/external-gw=true\n' "$GW_NODE"
      printf '  + apply ProviderNetwork/Vlan/Subnet %s (%s; excludeIps %s)\n' "$GW_EXT_SUBNET" "$GW_CIDR" "$GW_EXCL_IPS"
      printf '  + apply OvnEip ovn-cluster-external (lrp %s) + vpc.enableExternal + ovn-external-gw-config CM\n' "$GW_LRP"
    else
      # Only the gateway node bridges the LAN NIC; label it (the FIP pod-pinning
      # target) and exclude every other node from the underlay ProviderNetwork.
      $KUBECTL label node "$GW_NODE" ovn.kubernetes.io/external-gw=true --overwrite
      GW_EXCL_NODES=""
      for n in $($KUBECTL get nodes -o name | sed 's#node/##'); do
        [ "$n" = "$GW_NODE" ] && continue
        GW_EXCL_NODES="${GW_EXCL_NODES}    - ${n}"$'\n'
      done
      GW_EXCL_IPS_YAML=""
      IFS=',' read -ra _gwips <<<"$GW_EXCL_IPS"
      for ip in "${_gwips[@]}"; do
        GW_EXCL_IPS_YAML="${GW_EXCL_IPS_YAML}    - ${ip}"$'\n'
      done
      cat <<EOF | $KUBECTL apply -f -
apiVersion: kubeovn.io/v1
kind: ProviderNetwork
metadata: { name: $GW_EXT_SUBNET }
spec:
  defaultInterface: $GW_IFACE
  excludeNodes:
$GW_EXCL_NODES---
apiVersion: kubeovn.io/v1
kind: Vlan
metadata: { name: vlan0 }
spec: { id: 0, provider: $GW_EXT_SUBNET }
---
apiVersion: kubeovn.io/v1
kind: Subnet
metadata: { name: $GW_EXT_SUBNET }
spec:
  protocol: IPv4
  provider: ovn
  cidrBlock: $GW_CIDR
  gateway: $GW_ROUTER
  vlan: vlan0
  excludeIps:
$GW_EXCL_IPS_YAML---
apiVersion: kubeovn.io/v1
kind: OvnEip
metadata: { name: ovn-cluster-external }
spec: { externalSubnet: $GW_EXT_SUBNET, type: lrp, v4Ip: $GW_LRP }
EOF
      # enable-eip-snat=true means the default VPC's external gw is driven by this
      # ConfigMap path; enableExternal wires the LRP to the localnet.
      $KUBECTL patch vpc ovn-cluster --type merge -p '{"spec":{"enableExternal":true}}'
      cat <<EOF | $KUBECTL apply -f -
apiVersion: v1
kind: ConfigMap
metadata: { name: ovn-external-gw-config, namespace: kube-system }
data:
  enable-external-gw: "true"
  external-gw-nodes: "$GW_NODE"
  type: "centralized"
  external-gw-nic: "$GW_IFACE"
  external-gw-addr: "$GW_ROUTER/$GW_PREFIX"
EOF
    fi
  fi
fi

# ── 2a-web. traefik LAN exposure (networking.lanExpose.traefikIP) ──
# Pin traefik to the gateway node on :80/:443 as a ClusterIP annotated for the
# lan-expose operator, so every web app behind traefik is reachable from the LAN on
# one FIP (apps behind it can live anywhere). k3s reconciles this HelmChartConfig
# into the traefik release; the site IP comes from config so it survives a rebuild.
TRAEFIK_IP="$(yget networking.lanExpose.traefikIP)"
if [ "$(yget networking.lanExpose.enabled)" = "true" ] && [ -n "$TRAEFIK_IP" ]; then
  LOG "exposing traefik on $TRAEFIK_IP (ClusterIP + lan-expose, pinned to the gateway node)"
  if [ "$DRY_RUN" = 1 ]; then
    printf '  + apply HelmChartConfig/traefik (ClusterIP :80/:443, lan-ip %s)\n' "$TRAEFIK_IP"
  else
    cat <<EOF | $KUBECTL apply -f -
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata: { name: traefik, namespace: kube-system }
spec:
  valuesContent: |-
    service:
      type: ClusterIP
      annotations:
        openinfra.dev/lan-expose: "true"
        openinfra.dev/lan-ip: "$TRAEFIK_IP"
    ports:
      web:
        port: 80
        exposedPort: 80
      websecure:
        port: 443
        exposedPort: 443
    securityContext:
      capabilities:
        add:
          - NET_BIND_SERVICE
    nodeSelector:
      ovn.kubernetes.io/external-gw: "true"
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
  # Mixed-arch (arm64 control plane + amd64 workers): declare an amd64 runtime target so
  # virt-launcher/qemu can build + boot the x86 (q35) catalog on amd64 workers under an arm64 CP
  # (emulated machines + OVMF firmware). NOTE: ADMISSION is fixed separately by spec.architecture:
  # amd64 on the VM (emitted by the vm/vmimage compositions) — a q35 amd64 VMI admits on an arm64 CP
  # via KubeVirt's built-in amd64 defaults, with or without this patch (verified 2026-08-30). This
  # architectureConfiguration is the RUNTIME half that #45's actual Windows boot needed. Guarded on
  # aarch64 so an all-amd64 cluster's KubeVirt is left at its default. (#51)
  if [ "$(uname -m)" = "aarch64" ]; then
    LOG "arm64 control plane — enabling amd64 architectureConfiguration (virt-launcher runtime for x86 VMs on amd64 workers)"
    RUN "$KUBECTL patch kubevirt kubevirt -n kubevirt --type=merge -p '{\"spec\":{\"configuration\":{\"architectureConfiguration\":{\"amd64\":{\"machineType\":\"q35\",\"emulatedMachines\":[\"q35*\",\"pc-q35*\"],\"ovmfPath\":\"/usr/share/OVMF\"}}}}}'"
  fi
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
# scripts. Multus changes the cluster CNI (delegates to Cilium), hence opt-in.
if [ "$(yget networking.vmLan.enabled)" = "true" ]; then
  VMLAN_IFACE="$(yget networking.vmLan.interface)"; VMLAN_IFACE="${VMLAN_IFACE:-eno1}"
  MULTUS_VERSION="v4.1.0"; CNI_PLUGINS_VERSION="v1.5.1"
  # Cilium + k3s' containerd use the UPSTREAM CNI defaults (/opt/cni/bin, /etc/cni/net.d),
  # NOT k3s' own dirs. Multus, its plugins, and its config MUST live there or Multus is
  # bypassed (containerd talks straight to Cilium) and NADs never attach — the regression
  # that silently broke VM direct-LAN networking when Cilium replaced flannel.
  CNI_BIN="/opt/cni/bin"
  CNI_CONF="/etc/cni/net.d"
  LOG "VM direct-LAN networking: Multus + macvlan/macvtap (parent NIC: $VMLAN_IFACE)…"
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
        - { name: bin, hostPath: { path: ${CNI_BIN} } }
EOF
    # 2. Multus (thick) as the PRIMARY CNI, delegating the default network to Cilium.
    #    Leave the upstream paths (/etc/cni/net.d + /opt/cni/bin) unchanged — that is where
    #    Cilium writes its config and containerd looks, so Multus auto-detects Cilium as the
    #    cluster master and sits in front of it. (Rewriting these to k3s' dirs is what
    #    bypassed Multus after the Cilium migration; do NOT sed them.)
    curl -sfL "https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/${MULTUS_VERSION}/deployments/multus-daemonset-thick.yml" \
      | $KUBECTL apply -f - || WARN "Multus install failed"
    # Two hardening patches to the upstream Multus DS, both learned the hard way:
    #  1) ATOMIC shim install (copy to a temp name, then rename over the target). A plain
    #     `cp` truncates the existing binary in place → fails "Text file busy" (ETXTBSY) if
    #     a stuck multus-shim is running during a re-roll, wedging the node's CNI (init
    #     BackOffs, daemon never restarts). rename() over a busy binary is safe.
    #  2) RAISE the daemon's memory limit. Upstream ships 50Mi — fine when Multus is bypassed,
    #     but as the PRIMARY CNI on a busy node (many concurrent CNI ADDs from CronJobs/backups)
    #     50Mi OOMKills the daemon (exit 137) → it crash-loops → new pods stick in
    #     ContainerCreating with "CmdAdd (shim): timed out". 512Mi gives headroom.
    $KUBECTL -n kube-system patch ds kube-multus-ds --type=json \
      -p='[{"op":"replace","path":"/spec/template/spec/initContainers/0/command","value":["sh","-c","cp -f /usr/src/multus-cni/bin/multus-shim /host/opt/cni/bin/.multus-shim.new && mv -f /host/opt/cni/bin/.multus-shim.new /host/opt/cni/bin/multus-shim"]},{"op":"replace","path":"/spec/template/spec/containers/0/resources","value":{"requests":{"cpu":"100m","memory":"64Mi"},"limits":{"cpu":"1","memory":"512Mi"}}}]' 2>/dev/null || WARN "multus init/resources hardening patch failed"
    $KUBECTL -n kube-system rollout status ds/kube-multus-ds --timeout=180s || WARN "Multus not ready yet"
    # 3. The macvlan NetworkAttachmentDefinition (no IPAM -> guest DHCP).
    cat <<EOF | $KUBECTL apply -f - || WARN "NAD create failed"
apiVersion: k8s.cni.cncf.io/v1
kind: NetworkAttachmentDefinition
metadata: { name: openinfra-lan, namespace: default }
spec:
  config: '{ "cniVersion": "0.3.1", "type": "macvlan", "master": "${VMLAN_IFACE}", "mode": "bridge", "ipam": {} }'
EOF
    # 3b. macvtap — the SUPPORTED direct-LAN mode (network=macvtap). Unlike bridge/macvlan
    #     (a macvlan sub-iface can't be a KubeVirt bridge port), macvtap gives the VM a real
    #     LAN presence + its own DHCP lease. A device plugin exposes the LAN NIC as
    #     macvtap.network.kubevirt.io/<iface>; the macvtap-cni binary installs into ${CNI_BIN};
    #     a NAD + a KubeVirt binding plugin wire it to kind: VirtualMachine network=macvtap.
    cat <<EOF | $KUBECTL apply -f - || WARN "macvtap device-plugin config failed"
apiVersion: v1
kind: ConfigMap
metadata: { name: macvtap-deviceplugin-config, namespace: default }
data:
  DP_MACVTAP_CONF: '[ { "name": "${VMLAN_IFACE}", "lowerDevice": "${VMLAN_IFACE}", "mode": "bridge", "capacity": 50 } ]'
EOF
    cat <<EOF | $KUBECTL apply -f - || WARN "macvtap-cni install failed"
apiVersion: apps/v1
kind: DaemonSet
metadata: { name: macvtap-cni, namespace: default, labels: { name: macvtap-cni } }
spec:
  selector: { matchLabels: { name: macvtap-cni } }
  template:
    metadata: { labels: { name: macvtap-cni } }
    spec:
      hostNetwork: true
      hostPID: true
      priorityClassName: system-node-critical
      nodeSelector: { openinfra.dev/vm-lan: "true" }
      tolerations: [ { operator: Exists } ]
      containers:
        - name: macvtap-cni
          command: ["/macvtap-deviceplugin", "-v", "3", "-logtostderr"]
          envFrom: [ { configMapRef: { name: macvtap-deviceplugin-config } } ]
          image: quay.io/kubevirt/macvtap-cni:latest
          securityContext: { privileged: true }
          volumeMounts: [ { name: deviceplugin, mountPath: /var/lib/kubelet/device-plugins } ]
          readinessProbe:
            exec: { command: ["sh","-c","ls /var/lib/kubelet/device-plugins/macvtap.network.kubevirt.io* >/dev/null 2>&1"] }
            initialDelaySeconds: 5
            periodSeconds: 10
      initContainers:
        - name: install-cni
          command: ["cp", "/macvtap-cni", "/host/cni/macvtap"]   # into ${CNI_BIN}
          image: quay.io/kubevirt/macvtap-cni:latest
          securityContext: { privileged: true }
          volumeMounts: [ { name: cni, mountPath: /host/cni, mountPropagation: Bidirectional } ]
      volumes:
        - { name: deviceplugin, hostPath: { path: /var/lib/kubelet/device-plugins } }
        - { name: cni, hostPath: { path: ${CNI_BIN} } }
EOF
    cat <<EOF | $KUBECTL apply -f - || WARN "macvtap NAD create failed"
apiVersion: k8s.cni.cncf.io/v1
kind: NetworkAttachmentDefinition
metadata:
  name: openinfra-lan-macvtap
  namespace: default
  annotations: { k8s.v1.cni.cncf.io/resourceName: macvtap.network.kubevirt.io/${VMLAN_IFACE} }
spec:
  config: '{ "cniVersion": "0.3.1", "name": "openinfra-lan-macvtap", "type": "macvtap", "mtu": 1500 }'
EOF
    # Register the macvtap binding plugin on the KubeVirt CR (GA/no feature gate in KubeVirt
    # >=1.5). 'add' if spec.configuration.network is absent, else 'merge' to preserve siblings.
    $KUBECTL patch kubevirt kubevirt -n kubevirt --type=json \
      -p='[{"op":"add","path":"/spec/configuration/network","value":{"binding":{"macvtap":{"domainAttachmentType":"tap"}}}}]' >/dev/null 2>&1 \
      || $KUBECTL patch kubevirt kubevirt -n kubevirt --type=merge \
      -p='{"spec":{"configuration":{"network":{"binding":{"macvtap":{"domainAttachmentType":"tap"}}}}}}' >/dev/null 2>&1 \
      || WARN "macvtap binding registration failed (is KubeVirt installed? components.virtualization)"
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
    -e "s#__EXCLUDE__#${EXCLUDE_GLOB}#g" \
    "${REPO_DIR}/platform/root-app.yaml" | $KUBECTL apply -f -
fi

# ── 4a. kourier LAN exposure (networking.lanExpose.kourierIP) ──
# Kourier's Envoy binds 8080/8443 and is knative-operator-managed, so (unlike traefik)
# it can't be cheaply rebound to :80/:443. Instead switch it to ClusterIP, set the
# Function domain to <ip>.sslip.io, and front it with a tiny nginx-stream forwarder
# pinned to the gateway node + LAN-exposed via the operator — the "LAN LoadBalancer"
# for kourier. Runs after the app-of-apps so KnativeServing (ArgoCD-managed) can exist;
# if it hasn't converged yet it warns and skips — just re-run install.sh (idempotent).
KOURIER_IP="$(yget networking.lanExpose.kourierIP)"
if [ "$(yget networking.lanExpose.enabled)" = "true" ] && [ -n "$KOURIER_IP" ]; then
  if [ "$DRY_RUN" = 1 ]; then
    LOG "exposing kourier (Knative Functions) on $KOURIER_IP"
    printf '  + patch KnativeServing (ingress.kourier.service-type ClusterIP, domain %s.sslip.io)\n' "$KOURIER_IP"
    printf '  + apply kourier-lan-fwd forwarder + kourier-lan Service (lan-ip %s)\n' "$KOURIER_IP"
  elif ! $KUBECTL -n knative-serving get knativeserving knative-serving >/dev/null 2>&1; then
    WARN "networking.lanExpose.kourierIP set but KnativeServing not present yet — skipping kourier exposure. Re-run install.sh once the serverless component has converged."
  else
    LOG "exposing kourier (Knative Functions) on $KOURIER_IP (ClusterIP + sslip.io domain + LAN forwarder)"
    $KUBECTL patch knativeserving knative-serving -n knative-serving --type merge \
      -p "{\"spec\":{\"ingress\":{\"kourier\":{\"service-type\":\"ClusterIP\"}},\"config\":{\"domain\":{\"${KOURIER_IP}.sslip.io\":\"\"}}}}"
    cat <<EOF | $KUBECTL apply -f -
apiVersion: v1
kind: ConfigMap
metadata: { name: kourier-lan-fwd, namespace: knative-serving }
data:
  nginx.conf: |
    events {}
    stream {
      resolver 10.43.0.10 valid=30s;
      server { listen 80;  proxy_pass kourier.knative-serving.svc.cluster.local:80; }
      server { listen 443; proxy_pass kourier.knative-serving.svc.cluster.local:443; }
    }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: kourier-lan-fwd, namespace: knative-serving }
spec:
  replicas: 1
  selector: { matchLabels: { app.kubernetes.io/name: kourier-lan-fwd } }
  template:
    metadata: { labels: { app.kubernetes.io/name: kourier-lan-fwd } }
    spec:
      nodeSelector: { ovn.kubernetes.io/external-gw: "true" }
      containers:
        - name: nginx
          image: nginx:alpine
          ports: [ { containerPort: 80 }, { containerPort: 443 } ]
          volumeMounts: [ { name: conf, mountPath: /etc/nginx/nginx.conf, subPath: nginx.conf } ]
          resources:
            requests: { cpu: 10m, memory: 16Mi }
            limits: { cpu: 200m, memory: 64Mi }
      volumes: [ { name: conf, configMap: { name: kourier-lan-fwd } } ]
---
apiVersion: v1
kind: Service
metadata:
  name: kourier-lan
  namespace: knative-serving
  annotations:
    openinfra.dev/lan-expose: "true"
    openinfra.dev/lan-ip: "$KOURIER_IP"
spec:
  type: ClusterIP
  selector: { app.kubernetes.io/name: kourier-lan-fwd }
  ports:
    - { name: http,  port: 80,  targetPort: 80 }
    - { name: https, port: 443, targetPort: 443 }
EOF
  fi
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
