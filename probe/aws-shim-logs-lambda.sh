#!/usr/bin/env bash
# Compatibility probe for CloudWatch Logs over a function's own output: what a Lambda function prints is
# in /aws/lambda/<function>, as on AWS.
#
# Deploys a throwaway kind: Function (an HTTP echo that prints each request it serves), invokes it with a
# marker through `aws lambda invoke`, then finds the marker with real AWS CLI calls:
#   - describe-log-groups lists /aws/lambda/<function> (retentionInDays = the log store's);
#   - describe-log-streams names its stream as Lambda does (YYYY/MM/DD/[$LATEST]<id>);
#   - filter-log-events --filter-pattern <marker> and `aws logs tail` find the line;
#   - get-log-events reads the stream from its head;
#   - the group is read-only (put-log-events refused) and a JSON pattern is refused, never answered
#     unfiltered.
#
# On-demand (needs the shim, Knative Serving and the log store). Exit 0 = pass, 1 = a real failure,
# 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-logs-lambda.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
FN_NS="${FUNCTIONS_NAMESPACE:-default}"
SFX="$(head -c 3 /dev/urandom | od -An -tx1 | tr -d ' \n')"
FN_NAME="${PROBE_FUNCTION:-logs-probe-$SFX}"
GROUP="/aws/lambda/$FN_NAME"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
INGEST_WAIT="${INGEST_WAIT:-180}" # seconds for a printed line to reach the log store

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
kubectl get ksvc >/dev/null 2>&1 || inconclusive "Knative Serving is not installed (kind: Function needs it)"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

CREATED_KEYS=(); CREATED_USERS=(); MADE_FN=""; WORK="$(mktemp -d)"
cleanup() {
  rm -rf "$WORK"
  [ -n "$MADE_FN" ] && kubectl -n "$FN_NS" delete function.openinfra.dev "$FN_NAME" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  for s in "${CREATED_KEYS[@]:-}";  do [ -n "$s" ] && kubectl -n "$SHIM_NS" delete secret "$s" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
}
trap cleanup EXIT

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }
mint_key() { # owner group -> MK_AK MK_SK (globals: run in THIS shell so CREATED_* reach cleanup)
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
  MK_AK="$ak"; MK_SK="$sk"
}
awsq() { local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager "$@"; }

log "deploying a throwaway kind: Function (${FN_NAME}) — an HTTP echo that prints each request"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: openinfra.dev/v1
kind: Function
metadata: { name: "${FN_NAME}", namespace: "${FN_NS}" }
spec: { image: "mendhak/http-https-echo:37", port: 8080, expose: false }
YAML
MADE_FN=1
for _ in $(seq 1 60); do kubectl -n "$FN_NS" get ksvc "$FN_NAME" >/dev/null 2>&1 && break; sleep 2; done
kubectl -n "$FN_NS" get ksvc "$FN_NAME" >/dev/null 2>&1 || inconclusive "Function ${FN_NAME} ksvc was not created (composition did not reconcile in time)"
kubectl -n "$FN_NS" wait --for=condition=Ready ksvc/"$FN_NAME" --timeout=240s >/dev/null 2>&1 || inconclusive "Function ${FN_NAME} did not become Ready (Knative)"

mint_key "logs-probe-$SFX" "powerusers"; AK="$MK_AK"; SK="$MK_SK"
sleep 2

MARKER="logs-probe-marker-$SFX$RANDOM"
log "aws lambda invoke ${FN_NAME} with marker ${MARKER}"
awsq "$AK" "$SK" lambda invoke --function-name "$FN_NAME" --cli-binary-format raw-in-base64-out \
  --payload "{\"marker\":\"${MARKER}\"}" "$WORK/out.json" >"$WORK/inv.err" 2>&1 \
  || fail "lambda invoke failed: $(tr '\n' ' ' < "$WORK/inv.err")"
grep -q "$MARKER" "$WORK/out.json" || fail "the function did not answer with the marker: $(head -c 300 "$WORK/out.json")"

log "describe-log-groups --log-group-name-prefix ${GROUP}"
awsq "$AK" "$SK" logs describe-log-groups --log-group-name-prefix "$GROUP" --output json >"$WORK/groups.json" 2>"$WORK/err" \
  || fail "describe-log-groups: $(tr '\n' ' ' < "$WORK/err")"
python3 - "$WORK/groups.json" "$GROUP" <<'EOF' || fail "describe-log-groups does not list the function's group"
import json, sys
d = json.load(open(sys.argv[1]))
g = [x for x in d.get("logGroups", []) if x.get("logGroupName") == sys.argv[2]]
assert g and g[0].get("retentionInDays", 0) > 0 and g[0]["arn"].startswith("arn:aws:logs:"), d
EOF
log "  ✓ ${GROUP} is listed, with the log store's retention"

log "filter-log-events --filter-pattern ${MARKER} (waiting up to ${INGEST_WAIT}s for the line to reach the log store)"
found=""
for _ in $(seq 1 $(( INGEST_WAIT / 5 ))); do
  if awsq "$AK" "$SK" logs filter-log-events --log-group-name "$GROUP" --filter-pattern "$MARKER" --output json >"$WORK/filter.json" 2>"$WORK/err" \
     && grep -q "$MARKER" "$WORK/filter.json"; then found=1; break; fi
  sleep 5
done
[ -n "$found" ] || fail "filter-log-events did not find what the function printed: $(head -c 300 "$WORK/filter.json" 2>/dev/null) $(tr '\n' ' ' < "$WORK/err")"
STREAM="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["events"][0]["logStreamName"])' "$WORK/filter.json")"
printf '%s' "$STREAM" | grep -Eq '^[0-9]{4}/[0-9]{2}/[0-9]{2}/\[\$LATEST\][0-9a-f]{32}$' || fail "the stream is not named as Lambda names it: $STREAM"
log "  ✓ found, in stream $STREAM"

awsq "$AK" "$SK" logs describe-log-streams --log-group-name "$GROUP" --output json >"$WORK/streams.json" 2>"$WORK/err" \
  || fail "describe-log-streams: $(tr '\n' ' ' < "$WORK/err")"
grep -qF "$STREAM" "$WORK/streams.json" || fail "describe-log-streams does not list $STREAM"
awsq "$AK" "$SK" logs get-log-events --log-group-name "$GROUP" --log-stream-name "$STREAM" --start-from-head --output json >"$WORK/get.json" 2>"$WORK/err" \
  || fail "get-log-events: $(tr '\n' ' ' < "$WORK/err")"
grep -q "$MARKER" "$WORK/get.json" || fail "get-log-events from the head does not return the marker"
log "  ✓ describe-log-streams lists it and get-log-events reads it from the head"

awsq "$AK" "$SK" logs tail "$GROUP" --since 30m >"$WORK/tail.txt" 2>"$WORK/err" || fail "aws logs tail: $(tr '\n' ' ' < "$WORK/err")"
grep -q "$MARKER" "$WORK/tail.txt" || fail "aws logs tail does not show the marker"
log "  ✓ aws logs tail ${GROUP} shows it"

if awsq "$AK" "$SK" logs put-log-events --log-group-name "$GROUP" --log-stream-name "$STREAM" \
     --log-events "timestamp=$(date +%s000),message=forged" >/dev/null 2>"$WORK/err"; then
  fail "put-log-events into a function's own group was accepted (it is read-only)"
fi
grep -q "InvalidParameterException" "$WORK/err" || fail "put-log-events refusal: $(tr '\n' ' ' < "$WORK/err")"
if awsq "$AK" "$SK" logs filter-log-events --log-group-name "$GROUP" --filter-pattern '{ $.level = "ERROR" }' >/dev/null 2>"$WORK/err"; then
  fail "a JSON filter pattern was answered (it must be refused, never answered unfiltered)"
fi
log "  ✓ the group is read-only, and a JSON pattern is refused"

echo "✓ PASS — CloudWatch Logs serves a function's own output in /aws/lambda/<function>: listed, streams named as Lambda names them, found by filter-log-events, get-log-events and aws logs tail; read-only, unsupported patterns refused."
