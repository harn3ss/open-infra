#!/usr/bin/env bash
# Probe: the platform root CA guests and clients trust is the one that signs, and it can vouch only for
# the names it should.
#
# The root (cert-manager Certificate openinfra-root-ca, platform/networking/cluster-ca.yaml) is published
# for VM guests in the EnvironmentConfig openinfra-platform-ca by the platform-ca-publisher. Asserted:
#   - the published root is a self-signed CA certificate carrying a CRITICAL name-constraints extension
#     whose permitted DNS domains and IP ranges are exactly the root Certificate's spec (cert-manager
#     does not re-issue the root when only its nameConstraints change, so the two can drift);
#   - it is the root Certificate's current certificate (its CertificateRequest for the current revision);
#   - the openinfra-ca ClusterIssuer signs with the Secret the root Certificate writes;
#   - every Certificate openinfra-ca issued in the platform namespaces was signed by that root, and its
#     certificate verifies against it (openssl verify, which also enforces the name constraints).
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

log "the published root (EnvironmentConfig openinfra-platform-ca)"
kubectl get environmentconfig openinfra-platform-ca -o jsonpath='{.data.platformRootCA}' > "$W/published.pem" 2>/dev/null || true
grep -q 'BEGIN CERTIFICATE' "$W/published.pem" || fail "openinfra-platform-ca carries no root CA (is the platform-ca-publisher running?)"
[ "$(grep -c 'BEGIN CERTIFICATE' "$W/published.pem")" = 1 ] || fail "openinfra-platform-ca carries more than one certificate"
[ "$(openssl x509 -in "$W/published.pem" -outform DER | sha256sum)" = "$(openssl x509 -in "$W/current.pem" -outform DER | sha256sum)" ] \
  || fail "the published root is not $ROOT_CERT's current certificate (revision $rev)"
ok "it is $ROOT_CERT's current certificate"
openssl x509 -in "$W/published.pem" -noout -ext basicConstraints | grep -q 'CA:TRUE' || fail "the published root is not a CA certificate"
openssl verify -CAfile "$W/published.pem" "$W/published.pem" >/dev/null 2>&1 || fail "the published root is not self-signed"
nc="$(openssl x509 -in "$W/published.pem" -noout -ext nameConstraints 2>/dev/null)"
printf '%s\n' "$nc" | head -1 | grep -q 'Name Constraints: critical' || fail "the published root has no CRITICAL name-constraints extension"
printf '%s\n' "$nc" | grep -q 'Excluded:' && fail "the published root has excluded subtrees the spec does not ask for"
printf '%s\n' "$nc" | sed -n 's/^ *\(DNS\|IP\):/\1:/p' | sort > "$W/have.txt"
{
  printf '%s' "$crt" | jq -r '.spec.nameConstraints.permitted.dnsDomains[]? | "DNS:" + .'
  printf '%s' "$crt" | jq -r '.spec.nameConstraints.permitted.ipRanges[]?' | while read -r c; do printf 'IP:%s\n' "$(cidr_mask "$c")"; done
} | sort > "$W/want.txt"
[ -s "$W/want.txt" ] || fail "$ROOT_CERT's spec has no permitted name constraints"
diff -u "$W/want.txt" "$W/have.txt" >&2 || fail "the published root's permitted names differ from $ROOT_CERT's spec (renew the root to apply a constraints change)"
ok "critical name constraints, permitted exactly: $(tr '\n' ' ' < "$W/have.txt")"

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
    openssl verify -CAfile "$W/published.pem" "$W/leaf.pem" >/dev/null 2>&1 \
      || fail "$ns/$c does not verify against the published root: $(openssl verify -CAfile "$W/published.pem" "$W/leaf.pem" 2>&1 | tail -1)"
    ok "$ns/$c is signed by the root and verifies"
    n=$((n + 1))
  done
done
[ "$n" -gt 0 ] || inconclusive "no Certificate issued by $ISSUER in $PLATFORM_NAMESPACES"
printf '✓ PASS — the published platform root is the root that signs, name-constrained as specified, and all %d platform certificates verify against it\n' "$n"
