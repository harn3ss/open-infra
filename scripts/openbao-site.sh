#!/usr/bin/env bash
# OpenBao's site values, written into the cluster (docs/openbao.md). install.sh runs this when
# components.openbao is true, from config.yaml's openbao section; it is safe to re-run.
#
#   scripts/openbao-site.sh <unseal host address> <its CA SHA-256 fingerprint> <member nodes>
#
#   address      https://<IPv4 address>:<port>, the "address, for the cluster" line the unseal host
#                (scripts/openbao-unseal-host.ps1) prints
#   fingerprint  its "CA SHA-256 fingerprint" line (colons and letter case do not matter)
#   nodes        the three member nodes, comma-separated, on three different physical machines
#
# In namespace openbao it writes:
#   - ConfigMap openbao-unseal-host (ca.pem): the unseal host's CA certificate, fetched from the host and
#     written only when its SHA-256 fingerprint is the one given. A mismatch changes nothing and fails.
#   - EndpointSlice openbao-unseal-host: Service openbao-unseal-host (platform/security/openbao.yaml)
#     then reaches the unseal host at that address.
# and labels each member node openinfra.dev/openbao=true. It never reads or writes Secret openbao-seal,
# and it never removes a label: moving a member is a procedure (docs/openbao.md).
#
# KUBECTL (default kubectl) and DRY_RUN=1 (print what would change, change nothing) are honoured.
set -euo pipefail
KUBECTL="${KUBECTL:-kubectl}"
DRY_RUN="${DRY_RUN:-0}"
NS=openbao
LABEL=openinfra.dev/openbao
log()  { printf '\033[1;36m[openbao]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[openbao]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[openbao]\033[0m %s\n' "$*" >&2; exit 1; }

[ $# -eq 3 ] || die "usage: $0 <unseal host address> <CA SHA-256 fingerprint> <member nodes>"
addr="${1%/}"
want="$(printf %s "$2" | tr -d ': ' | tr '[:lower:]' '[:upper:]')"
nodes="$(printf %s "$3" | tr -d ' ')"

[[ "$addr" =~ ^https://([0-9]{1,3}(\.[0-9]{1,3}){3}):([0-9]{1,5})$ ]] \
  || die "openbao.unsealHost.address must be https://<IPv4 address>:<port>, as the unseal host prints it (got '$addr')"
ip="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[3]}"
[[ "$want" =~ ^[0-9A-F]{64}$ ]] \
  || die "openbao.unsealHost.caFingerprint must be a SHA-256 fingerprint: 64 hex digits, colons allowed"
[ -n "$nodes" ] || die "openbao.nodes is empty: name three nodes on three different physical machines"

# Every node named must exist, and sit on a solid-state disk (the members require one).
count=0
for n in ${nodes//,/ }; do
  $KUBECTL get node "$n" >/dev/null 2>&1 || die "openbao.nodes names '$n', which is not a node of this cluster"
  class="$($KUBECTL get node "$n" -o jsonpath='{.metadata.labels.openinfra\.dev/disk-class}')"
  case "$class" in
    nvme|sata-ssd) ;;
    *) warn "node $n has disk class '${class:-unmeasured}': a member is placed only on nvme or sata-ssd nodes" ;;
  esac
  count=$((count + 1))
done
[ "$count" -ge 3 ] || warn "openbao.nodes names $count node(s): the three members need three different physical machines"

# 1. The unseal host's CA, pinned to the fingerprint. TLS is not trusted for this fetch; the fingerprint is.
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
have_ca=0
$KUBECTL -n "$NS" get configmap openbao-unseal-host >/dev/null 2>&1 && have_ca=1
if curl -fsS --max-time 10 -k "$addr/v1/pki/ca/pem" -o "$tmp/ca.pem" 2>"$tmp/err"; then
  [ "$(grep -c -- '-----BEGIN CERTIFICATE-----' "$tmp/ca.pem")" = 1 ] \
    || die "the unseal host at $addr did not answer with one CA certificate: nothing changed"
  got="$(sed '/-----/d' "$tmp/ca.pem" | base64 -d | sha256sum | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]')"
  [ "$got" = "$want" ] \
    || die "the unseal host at $addr presented a CA whose SHA-256 fingerprint is not openbao.unsealHost.caFingerprint: nothing changed"
  # The members dial the Service and check the name openbao-unseal-host: the host's certificate must hold it.
  curl -fsS --max-time 10 --cacert "$tmp/ca.pem" --resolve "openbao-unseal-host:$port:$ip" \
      -o /dev/null "https://openbao-unseal-host:$port/v1/sys/seal-status" \
    || die "the unseal host's certificate is not valid for the name openbao-unseal-host under that CA: nothing changed"
  if [ "$DRY_RUN" = 1 ]; then
    printf '  + apply ConfigMap %s/openbao-unseal-host (the unseal host CA, fingerprint verified)\n' "$NS"
  else
    $KUBECTL get namespace "$NS" >/dev/null 2>&1 || $KUBECTL create namespace "$NS" >/dev/null
    $KUBECTL -n "$NS" create configmap openbao-unseal-host --from-file=ca.pem="$tmp/ca.pem" \
      --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null
    log "the unseal host's CA is verified and recorded (configmap/openbao-unseal-host)"
  fi
elif [ "$have_ca" = 1 ]; then
  warn "the unseal host at $addr did not answer ($(head -c 200 "$tmp/err")); kept the CA already recorded"
else
  warn "the unseal host at $addr did not answer ($(head -c 200 "$tmp/err")) and no CA is recorded yet:"
  warn "  the members cannot start until it answers and install.sh runs again"
fi

# 2. Where the unseal host is.
if [ "$DRY_RUN" = 1 ]; then
  printf '  + apply EndpointSlice %s/openbao-unseal-host -> %s:%s\n' "$NS" "$ip" "$port"
else
  $KUBECTL get namespace "$NS" >/dev/null 2>&1 || $KUBECTL create namespace "$NS" >/dev/null
  cat <<EOF | $KUBECTL apply -f - >/dev/null
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: openbao-unseal-host
  namespace: $NS
  labels:
    kubernetes.io/service-name: openbao-unseal-host
    endpointslice.kubernetes.io/managed-by: openinfra-install
addressType: IPv4
ports:
  - { name: https, port: $port, protocol: TCP }
endpoints:
  - addresses: ["$ip"]
    conditions: { ready: true }
EOF
  log "Service openbao-unseal-host reaches the unseal host at $ip:$port"
fi

# 3. The member nodes. A labelled node that is no longer listed keeps its label (and its member).
for n in ${nodes//,/ }; do
  if [ "$DRY_RUN" = 1 ]; then printf '  + label node %s %s=true\n' "$n" "$LABEL"
  else $KUBECTL label node "$n" "$LABEL=true" --overwrite >/dev/null; fi
done
for n in $($KUBECTL get nodes -l "$LABEL=true" -o jsonpath='{.items[*].metadata.name}'); do
  case ",$nodes," in
    *",$n,"*) ;;
    *) warn "node $n is labelled $LABEL=true but not in openbao.nodes: a member there stays; to move it, see docs/openbao.md" ;;
  esac
done
[ "$DRY_RUN" = 1 ] || log "member nodes labelled $LABEL=true: ${nodes//,/, }"

# 4. The seal token is the operator's to create; only its presence is checked.
$KUBECTL -n "$NS" get secret openbao-seal -o name >/dev/null 2>&1 \
  || warn "no secret $NS/openbao-seal yet: create it from the unseal host's output (docs/openbao.md); the members wait for it"
