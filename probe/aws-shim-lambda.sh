#!/usr/bin/env bash
# Compatibility probe for the aws-shim Lambda surface (design handoff §8).
#
# Deploys a throwaway kind: Function (an HTTP echo), then fires a REAL AWS SDK call
# (`aws lambda invoke`) at the shim and asserts the function's response comes back — proving the
# Lambda Invoke → Knative Function path end to end — plus the negative: a wrong secret is rejected.
#
# On-demand (needs the shim + Knative Serving). Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-lambda.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
FN_NS="${FUNCTIONS_NAMESPACE:-default}"
FN_NAME="${PROBE_FUNCTION:-probe-echo}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
kubectl get ksvc >/dev/null 2>&1 || inconclusive "Knative Serving is not installed (kind: Function needs it)"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

CREATED_KEYS=(); CREATED_USERS=(); MADE_FN=""
cleanup() {
  [ -n "$MADE_FN" ] && kubectl -n "$FN_NS" delete function.openinfra.dev "$FN_NAME" --ignore-not-found >/dev/null 2>&1 || true
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

# --- Deploy a throwaway echo Function (kind: Function → Knative). mendhak/http-https-echo listens
#     on 8080 (the Function default) and returns the request as JSON, so we can see our payload. ---
log "deploying a throwaway kind: Function (${FN_NAME}) — an HTTP echo"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: openinfra.dev/v1
kind: Function
metadata: { name: "${FN_NAME}", namespace: "${FN_NS}" }
spec: { image: "mendhak/http-https-echo:37", port: 8080, expose: false }
YAML
MADE_FN=1
log "waiting for the Knative service to be ready"
kubectl -n "$FN_NS" wait --for=condition=Ready ksvc/"$FN_NAME" --timeout=180s >/dev/null 2>&1 \
  || inconclusive "Function ${FN_NAME} did not become Ready (Knative)"

log "seeding a principal + access key"
read -r AK SK <<<"$(mint_key "lambda-probe" "powerusers")"
[ -n "$AK" ] && [ -n "$SK" ] || inconclusive "failed to mint a key"
sleep 2

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"; cleanup' EXIT
MARKER="lambda-probe-$RANDOM$RANDOM"
log "aws lambda invoke ${FN_NAME} (payload carries a marker; echo must return it)"
awsq "$AK" "$SK" lambda invoke --function-name "$FN_NAME" \
  --payload "$(printf '{"marker":"%s"}' "$MARKER")" --cli-binary-format raw-in-base64-out \
  "$WORK/out.json" >/tmp/lambda-inv 2>&1 || fail "lambda invoke failed: $(cat /tmp/lambda-inv)"
grep -q "$MARKER" "$WORK/out.json" || fail "invoke response did not echo the payload marker; got: $(head -c 300 "$WORK/out.json")"
log "  ✓ function invoked; response returned through the shim"

log "negative: a valid key ID with a WRONG secret must be rejected"
if awsq "$AK" "wrong-secret" lambda invoke --function-name "$FN_NAME" --payload '{}' \
    --cli-binary-format raw-in-base64-out "$WORK/neg.json" >/tmp/lambda-neg 2>&1; then
  fail "a wrong-signature Lambda invoke was ACCEPTED (authentication theater!)"
fi
grep -qi 'InvalidSignature\|SignatureDoesNotMatch\|403\|Forbidden' /tmp/lambda-neg \
  || fail "wrong secret not rejected as a signature error: $(cat /tmp/lambda-neg)"
log "  ✓ rejected on a bad signature"

echo
echo "✓ PASS — aws-shim Lambda invokes a kind: Function and rejects a bad signature."
