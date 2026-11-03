#!/usr/bin/env bash
# Compatibility probe for the aws-shim ACM surface.
#
# A stack's AWS::CertificateManager::Certificate is the TLS certificate of the CloudFront distribution in
# the same stack (its kind: StaticSite's cert-manager certificate). With the real AWS CLI this lists the
# stacks' certificates, describes one (ISSUED, its domain, the distribution it is in use by), reads it with
# get-certificate (a PEM certificate and chain, and never a private key), and checks the negatives: an
# unknown ARN is ResourceNotFoundException, a request ACM would serve that the shim does not is refused,
# and a caller without the stack read gets AccessDeniedException.
#
# It reads a certificate a stack already has (PROBE_CERTIFICATE_ARN, or the first ListCertificates
# answers); probe/aws-shim-cfn-cloudfront.sh deploys such a stack and reads its certificate the same way.
#
# On-demand. Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-acm.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

CREATED_KEYS=(); CREATED_USERS=(); WORK="$(mktemp -d)"
cleanup() {
  for s in "${CREATED_KEYS[@]:-}";  do [ -n "$s" ] && kubectl -n "$SHIM_NS" delete secret "$s" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }
mint_key() { # owner group -> MK_AK / MK_SK
  local owner="$1" group="$2"
  local ak="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  local sk; sk="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "${owner}", namespace: "${USERS_NS}" }
spec: { displayName: "${owner}", groups: ["${group}"], source: local }
YAML
  CREATED_USERS+=("$owner")
  local name; name="$(secret_name "$ak")"
  kubectl -n "$SHIM_NS" create secret generic "$name" \
    --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  CREATED_KEYS+=("$name")
  MK_AK="$ak"; MK_SK="$sk"  # globals: mint_key must run in THIS shell so CREATED_* reach cleanup
}
acm() { local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager acm "$@"; }

SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
log "seeding a reader principal (openinfra:readers) + access key"
mint_key "acm-probe-$SFX" "readers"; AK="$MK_AK"; SK="$MK_SK"
sleep 2

log "aws acm list-certificates"
acm "$AK" "$SK" list-certificates --output json >"$WORK/list.json" 2>&1 || fail "list-certificates: $(head -c 300 "$WORK/list.json")"
ARN="${PROBE_CERTIFICATE_ARN:-$(python3 -c 'import json,sys; l=json.load(open(sys.argv[1]))["CertificateSummaryList"]; print(l[0]["CertificateArn"] if l else "")' "$WORK/list.json")}"
[ -n "$ARN" ] || inconclusive "no stack certificate to read (deploy one — probe/aws-shim-cfn-cloudfront.sh does — or set PROBE_CERTIFICATE_ARN)"
log "  ✓ listed; reading $ARN"

log "aws acm describe-certificate"
acm "$AK" "$SK" describe-certificate --certificate-arn "$ARN" --output json >"$WORK/desc.json" 2>&1 \
  || fail "describe-certificate: $(head -c 300 "$WORK/desc.json")"
python3 - "$WORK/desc.json" "$ARN" <<'PY' || fail "describe-certificate: $(head -c 400 "$WORK/desc.json")"
import json, sys
c = json.load(open(sys.argv[1]))["Certificate"]
assert c["CertificateArn"] == sys.argv[2], c
assert c["DomainName"] and c["DomainName"] in c["SubjectAlternativeNames"], c
assert c["Status"] in ("ISSUED", "PENDING_VALIDATION"), c["Status"]
assert all(":distribution/" in a for a in c.get("InUseBy", [])), c.get("InUseBy")
PY
STATUS="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["Certificate"]["Status"])' "$WORK/desc.json")"
log "  ✓ described ($STATUS)"

if [ "$STATUS" = ISSUED ]; then
  log "aws acm get-certificate: the certificate and chain, never a key"
  acm "$AK" "$SK" get-certificate --certificate-arn "$ARN" --output json >"$WORK/get.json" 2>&1 \
    || fail "get-certificate: $(head -c 300 "$WORK/get.json")"
  grep -q 'BEGIN CERTIFICATE' "$WORK/get.json" || fail "get-certificate answered no PEM certificate"
  if grep -q 'PRIVATE KEY' "$WORK/get.json"; then fail "get-certificate answered a PRIVATE KEY"; fi
  log "  ✓ PEM certificate + chain; no private key"
else
  ERR="$(acm "$AK" "$SK" get-certificate --certificate-arn "$ARN" 2>&1 >/dev/null || true)"
  printf '%s' "$ERR" | grep -q RequestInProgressException || fail "get-certificate of a certificate not yet issued: $ERR"
  log "  ✓ not yet issued: RequestInProgressException"
fi

log "negatives"
MISSING="${ARN%/*}/00000000-0000-0000-0000-000000000000"
ERR="$(acm "$AK" "$SK" describe-certificate --certificate-arn "$MISSING" 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q ResourceNotFoundException || fail "describe-certificate of an unknown ARN: $ERR"
ERR="$(acm "$AK" "$SK" request-certificate --domain-name "probe-$SFX.example.test" 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q InvalidAction || fail "request-certificate should be refused (a certificate is created with its stack): $ERR"
mint_key "acm-probe-nobody-$SFX" "nobody"; NAK="$MK_AK"; NSK="$MK_SK"
sleep 2
ERR="$(acm "$NAK" "$NSK" describe-certificate --certificate-arn "$ARN" 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q AccessDenied || fail "a caller with no platform role described the certificate: $ERR"
log "  ✓ unknown ARN → ResourceNotFoundException; RequestCertificate refused; no stack read → AccessDenied"

echo
echo "✓ PASS — aws-shim ACM lists, describes and reads a stack's certificate (never its key), and refuses the rest."
