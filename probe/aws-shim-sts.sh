#!/usr/bin/env bash
# Compatibility probe for the aws-shim STS surface (design handoff §8).
#
# Fires a REAL AWS SDK call (`aws sts get-caller-identity`) at the shim and asserts it returns the
# CALLER's open-infra identity as an ARN the SDK can parse — plus the negative that earns the trust:
# a valid key ID with a wrong secret is rejected as SignatureDoesNotMatch. STS has no backend (it
# reflects the SigV4-proven principal), so this is a pure protocol/identity-faithfulness check.
#
# On-demand (needs the shim deployed). Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE
# (a prerequisite was missing). Mirrors probe/aws-shim-s3.sh.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-sts.sh
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
command -v kubectl >/dev/null || inconclusive "kubectl is required to seed the principal + key"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

CREATED_KEYS=(); CREATED_USERS=()
cleanup() {
  for s in "${CREATED_KEYS[@]:-}";  do [ -n "$s" ] && kubectl -n "$SHIM_NS" delete secret "$s" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
}
trap cleanup EXIT

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }
mint_key() { # owner group -> "AK SK"
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
  printf '%s %s' "$ak" "$sk"
}
awsq() { local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager "$@"; }

log "seeding a principal + access key"
read -r AK SK <<<"$(mint_key "sts-probe" "readers")"
[ -n "$AK" ] && [ -n "$SK" ] || inconclusive "failed to mint a key"
sleep 2

log "sts get-caller-identity (expect our open-infra ARN)"
OUT="$(awsq "$AK" "$SK" sts get-caller-identity 2>&1)" || fail "get-caller-identity failed: $OUT"
echo "$OUT" | grep -q 'user/sts-probe' || fail "ARN did not identify the caller (user/sts-probe): $OUT"
echo "$OUT" | grep -q '"UserId": "sts-probe"' || fail "UserId not the caller: $OUT"
log "  ✓ identity reflected: $(echo "$OUT" | sed -n 's/.*"Arn": "\(.*\)".*/\1/p')"

log "negative: a valid key ID with a WRONG secret must be rejected"
if awsq "$AK" "wrong-secret-not-the-real-one" sts get-caller-identity >/tmp/sts-neg 2>&1; then
  fail "a wrong-signature STS request was ACCEPTED (authentication theater!)"
fi
grep -qi 'SignatureDoesNotMatch\|403\|Forbidden' /tmp/sts-neg || fail "wrong secret not rejected as SignatureDoesNotMatch: $(cat /tmp/sts-neg)"
log "  ✓ rejected as SignatureDoesNotMatch"

echo
echo "✓ PASS — aws-shim STS reflects the caller's identity and rejects a bad signature."
