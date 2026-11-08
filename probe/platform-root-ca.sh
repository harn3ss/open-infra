#!/usr/bin/env bash
# Probe: the platform root CA guests and clients trust is the one that signs, and it can vouch only for
# the names it should.
#
# The root is published for VM guests in the EnvironmentConfig openinfra-platform-ca by the
# platform-ca-publisher. Two shapes, told apart by the openinfra-ca ClusterIssuer:
#   - CA-type (the root signs): the root is cert-manager Certificate openinfra-root-ca
#     (platform/networking/cluster-ca-root.yaml). Asserted: the issuer signs with the Secret the root
#     Certificate writes; the published root is that Certificate's current certificate; its permitted names
#     are exactly the Certificate's spec (cert-manager does not re-issue the root when only its
#     nameConstraints change, so the two can drift).
#   - OpenBao (openbao.platformCAs: true; docs/openbao.md, "The platform's CAs"): the issuer signs through an
#     OpenBao intermediate and the root is offline. Asserted: no root Certificate and no CA Secret is named
#     by the issuer; the published root is the one recorded when the CAs moved (ConfigMap
#     cert-manager/openinfra-roots); each certificate's chain carries a CA intermediate the root signed.
# In both: the published root is a self-signed CA certificate with a CRITICAL name-constraints extension and
# no excluded subtrees, and every Certificate openinfra-ca issued in the platform namespaces verifies
# against it (openssl verify, which also enforces the name constraints).
#
# Read-only, public data only (Certificates, CertificateRequests, the EnvironmentConfig): no Secret is
# read. Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   ./probe/platform-root-ca.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
ROOT_NS="${ROOT_NS:-cert-manager}"
ROOT_CERT="${ROOT_CERT:-openinfra-root-ca}"
ISSUER="${ISSUER:-openinfra-ca}"
PLATFORM_NAMESPACES="${PLATFORM_NAMESPACES:-open-infra-aws-shim open-infra-ecr}"

log()  { printf '▸ %s\n' "$*"; }
ok()   { printf '  ✓ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for t in kubectl jq openssl; do command -v "$t" >/dev/null || inconclusive "$t is required"; done
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

# CIDR -> the address/netmask form openssl prints for an IP name constraint.
cidr_mask() {
  local ip="${1%/*}" bits="${1#*/}" mask="" i n
  for i in 1 2 3 4; do
    if [ "$bits" -ge 8 ]; then n=255; bits=$((bits - 8)); else n=$(( (256 - (1 << (8 - bits))) % 256 )); bits=0; fi
    mask="${mask:+$mask.}$n"
  done
  printf '%s/%s\n' "$ip" "$mask"
}

ci="$(kubectl get clusterissuer "$ISSUER" -o json 2>/dev/null)" || inconclusive "no ClusterIssuer $ISSUER"
MODE=ca
[ -n "$(printf '%s' "$ci" | jq -r '.spec.vault.path // empty')" ] && MODE=openbao

if [ "$MODE" = openbao ]; then
log "the issuer and the offline root"
printf '%s' "$ci" | jq -e 'any(.status.conditions[]?; .type == "Ready" and .status == "True")' >/dev/null || fail "$ISSUER is not Ready"
[ -z "$(printf '%s' "$ci" | jq -r '.spec.ca.secretName // empty')" ] || fail "$ISSUER names a CA Secret as well as OpenBao"
ok "$ISSUER signs through OpenBao ($(printf '%s' "$ci" | jq -r .spec.vault.path))"
if kubectl -n "$ROOT_NS" get certificate "$ROOT_CERT" >/dev/null 2>&1; then
  fail "Certificate $ROOT_NS/$ROOT_CERT still exists: cert-manager would keep the root's key in a Secret"
fi
ok "no root Certificate: the root is offline"
kubectl -n "$ROOT_NS" get configmap openinfra-roots -o jsonpath='{.data.platformRootCA}' > "$W/current.pem" 2>/dev/null || true
grep -q 'BEGIN CERTIFICATE' "$W/current.pem" || fail "no ConfigMap $ROOT_NS/openinfra-roots (the roots recorded when the CAs moved)"
else
log "the root Certificate and its issuer"
crt="$(kubectl -n "$ROOT_NS" get certificate "$ROOT_CERT" -o json 2>/dev/null)" || inconclusive "no Certificate $ROOT_NS/$ROOT_CERT"
printf '%s' "$crt" | jq -e 'any(.status.conditions[]?; .type == "Ready" and .status == "True")' >/dev/null \
  || fail "$ROOT_NS/$ROOT_CERT is not Ready"
rev="$(printf '%s' "$crt" | jq -r '.status.revision // 0')"
uid="$(printf '%s' "$crt" | jq -r .metadata.uid)"
secret="$(printf '%s' "$crt" | jq -r .spec.secretName)"
signs="$(kubectl get clusterissuer "$ISSUER" -o jsonpath='{.spec.ca.secretName}')"
[ "$signs" = "$secret" ] || fail "$ISSUER signs with Secret $signs, but $ROOT_CERT writes $secret"
ok "$ISSUER signs with $secret, the Secret $ROOT_CERT (revision $rev) writes"

kubectl -n "$ROOT_NS" get certificaterequests -o json \
  | jq -r --arg uid "$uid" --arg rev "$rev" '[.items[]
      | select(any(.metadata.ownerReferences[]?; .uid == $uid))
      | select((.metadata.annotations["cert-manager.io/certificate-revision"] // "") == $rev)
      | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))
      | .status.certificate // empty] | if length == 1 then .[0] else empty end' \
  | base64 -d > "$W/current.pem" 2>/dev/null || true
grep -q 'BEGIN CERTIFICATE' "$W/current.pem" || fail "no issued CertificateRequest for $ROOT_CERT revision $rev"
fi

log "the published root (EnvironmentConfig openinfra-platform-ca)"
kubectl get environmentconfig openinfra-platform-ca -o jsonpath='{.data.platformRootCA}' > "$W/published.pem" 2>/dev/null || true
grep -q 'BEGIN CERTIFICATE' "$W/published.pem" || fail "openinfra-platform-ca carries no root CA (is the platform-ca-publisher running?)"
[ "$(grep -c 'BEGIN CERTIFICATE' "$W/published.pem")" = 1 ] || fail "openinfra-platform-ca carries more than one certificate"
[ "$(openssl x509 -in "$W/published.pem" -outform DER | sha256sum)" = "$(openssl x509 -in "$W/current.pem" -outform DER | sha256sum)" ] \
  || fail "the published root is not the current root ($([ "$MODE" = ca ] && echo "$ROOT_CERT revision $rev" || echo "ConfigMap openinfra-roots"))"
ok "it is the current root ($([ "$MODE" = ca ] && echo "$ROOT_CERT's current certificate" || echo "the one recorded when the CAs moved"))"
openssl x509 -in "$W/published.pem" -noout -ext basicConstraints | grep -q 'CA:TRUE' || fail "the published root is not a CA certificate"
openssl verify -CAfile "$W/published.pem" "$W/published.pem" >/dev/null 2>&1 || fail "the published root is not self-signed"
nc="$(openssl x509 -in "$W/published.pem" -noout -ext nameConstraints 2>/dev/null)"
printf '%s\n' "$nc" | head -1 | grep -q 'Name Constraints: critical' || fail "the published root has no CRITICAL name-constraints extension"
printf '%s\n' "$nc" | grep -q 'Excluded:' && fail "the published root has excluded subtrees the spec does not ask for"
printf '%s\n' "$nc" | sed -n 's/^ *\(DNS\|IP\):/\1:/p' | sort > "$W/have.txt"
if [ "$MODE" = openbao ]; then
  [ -s "$W/have.txt" ] || fail "the published root permits no names"
  ok "critical name constraints, permitted: $(tr '\n' ' ' < "$W/have.txt")"
else
{
  printf '%s' "$crt" | jq -r '.spec.nameConstraints.permitted.dnsDomains[]? | "DNS:" + .'
  printf '%s' "$crt" | jq -r '.spec.nameConstraints.permitted.ipRanges[]?' | while read -r c; do printf 'IP:%s\n' "$(cidr_mask "$c")"; done
} | sort > "$W/want.txt"
[ -s "$W/want.txt" ] || fail "$ROOT_CERT's spec has no permitted name constraints"
diff -u "$W/want.txt" "$W/have.txt" >&2 || fail "the published root's permitted names differ from $ROOT_CERT's spec (renew the root to apply a constraints change)"
ok "critical name constraints, permitted exactly: $(tr '\n' ' ' < "$W/have.txt")"
fi

log "platform certificates issued by $ISSUER"
n=0
for ns in $PLATFORM_NAMESPACES; do
  kubectl -n "$ns" get certificates -o json > "$W/certs.json" 2>/dev/null || inconclusive "cannot list Certificates in $ns"
  kubectl -n "$ns" get certificaterequests -o json > "$W/reqs.json" 2>/dev/null || inconclusive "cannot list CertificateRequests in $ns"
  for c in $(jq -r --arg iss "$ISSUER" '.items[] | select(.spec.issuerRef.name == $iss and (.spec.issuerRef.kind // "") == "ClusterIssuer") | .metadata.name' "$W/certs.json"); do
    last="$(jq -c --arg c "$c" '[.items[]
        | select(.metadata.annotations["cert-manager.io/certificate-name"] == $c)
        | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))]
      | sort_by(.metadata.annotations["cert-manager.io/certificate-revision"] // "0" | tonumber) | last // empty' "$W/reqs.json")"
    [ -n "$last" ] || fail "$ns/$c has no issued CertificateRequest"
    printf '%s' "$last" | jq -r '.status.ca // empty' | base64 -d > "$W/ca.pem" 2>/dev/null || true
    printf '%s' "$last" | jq -r '.status.certificate // empty' | base64 -d > "$W/leaf.pem" 2>/dev/null || true
    [ "$(openssl x509 -in "$W/ca.pem" -outform DER 2>/dev/null | sha256sum)" = "$(openssl x509 -in "$W/published.pem" -outform DER | sha256sum)" ] \
      || fail "$ns/$c was signed by another root (the publisher renews it within one run; re-run then)"
    # The chain after the leaf (an OpenBao intermediate) is untrusted: only the root is trusted.
    openssl verify -CAfile "$W/published.pem" -untrusted "$W/leaf.pem" "$W/leaf.pem" >/dev/null 2>&1 \
      || fail "$ns/$c does not verify against the published root: $(openssl verify -CAfile "$W/published.pem" -untrusted "$W/leaf.pem" "$W/leaf.pem" 2>&1 | tail -1)"
    if [ "$MODE" = openbao ]; then
      awk '/BEGIN CERTIFICATE/{n++} n==2' "$W/leaf.pem" > "$W/int.pem"
      grep -q 'BEGIN CERTIFICATE' "$W/int.pem" || fail "$ns/$c carries no intermediate: it was not signed through OpenBao"
      openssl x509 -in "$W/int.pem" -noout -ext basicConstraints | grep -q 'CA:TRUE' || fail "$ns/$c's intermediate is not a CA"
      openssl verify -CAfile "$W/published.pem" "$W/int.pem" >/dev/null 2>&1 || fail "$ns/$c's intermediate was not signed by the root"
      ok "$ns/$c verifies, through \"$(openssl x509 -in "$W/int.pem" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= *//p')\""
    else
      ok "$ns/$c is signed by the root and verifies"
    fi
    n=$((n + 1))
  done
done
[ "$n" -gt 0 ] || inconclusive "no Certificate issued by $ISSUER in $PLATFORM_NAMESPACES"
printf '✓ PASS — the published platform root is the root that signs, name-constrained as specified, and all %d platform certificates verify against it\n' "$n"
