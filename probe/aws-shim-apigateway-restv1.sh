#!/usr/bin/env bash
# Compatibility probe for the aws-shim API Gateway REST API (v1) surface (polyhedron#295, increment 1).
# Complements the HTTP-API v2 probe (aws-shim-apigateway.sh). Fires REAL AWS SDK calls (aws apigateway)
# at the control plane and REAL HTTP requests at the data plane, asserting end to end:
#   - CreateRestApi (seeds root) + CreateResource tree (/items, /items/{id}) + PutMethod + PutIntegration
#     (AWS_PROXY → a Lambda) + CreateDeployment (snapshot) + a stage pointing at it
#   - a REAL HTTP POST to /_apigw/<id>/<stage>/items/123 reaches the Lambda with a faithful **1.0 proxy
#     event** (httpMethod, path, pathParameters.id, query, body), and the Lambda's STRUCTURED
#     {statusCode,body} becomes the real HTTP response
#   - an **HTTP_PROXY** integration reverse-proxies to an http origin (the shim's REST v1 non-Lambda path)
# and the NEGATIVES ("prove the no"):
#   - a valid key ID with a WRONG secret on a management call → SignatureDoesNotMatch
#   - the #185 wiring fence: a principal that cannot invoke the Lambda is refused at PutIntegration
#
# The AWS_PROXY Lambda is a spec.code (python) handler that returns {statusCode,body=json(event)} — REST
# v1 payload format is 1.0, which REQUIRES a structured response, so a bare-echo public image cannot prove
# the response path (that is exactly the 1.0 rule). Self-contained otherwise.
#
# On-demand (needs a deployed shim + Knative + the API Gateway Postgres + the platform IAM). Exit 0 = pass,
# 1 = a real failure, 42 = INCONCLUSIVE.  SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-apigateway-restv1.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
FN_NS="${FUNCTIONS_NAMESPACE:-default}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v curl    >/dev/null || inconclusive "curl is required"
command -v python3 >/dev/null || inconclusive "python3 is required"
kubectl get ksvc >/dev/null 2>&1 || inconclusive "Knative Serving not installed"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

WORK="$(mktemp -d)"
CREATED_KEYS=(); CREATED_USERS=(); CREATED_POLICIES=(); CREATED_APIS=(); MADE_FN=""; MADE_CM=""
cleanup() {
  for a in "${CREATED_APIS[@]:-}"; do [ -n "$a" ] && AWS_ACCESS_KEY_ID="${WAK:-}" AWS_SECRET_ACCESS_KEY="${WSK:-}" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager apigateway delete-rest-api --rest-api-id "$a" >/dev/null 2>&1 || true; done
  [ -n "$MADE_FN" ] && kubectl -n "$FN_NS" delete function.openinfra.dev "$MADE_FN" --ignore-not-found >/dev/null 2>&1 || true
  [ -n "$MADE_CM" ] && kubectl -n "$FN_NS" delete configmap "$MADE_CM" --ignore-not-found >/dev/null 2>&1 || true
  for k in "${CREATED_KEYS[@]:-}";  do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for p in "${CREATED_POLICIES[@]:-}"; do [ -n "$p" ] && kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev "$p" --ignore-not-found >/dev/null 2>&1 || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }
mint_key() {
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
  kubectl -n "$SHIM_NS" create secret generic "$name" --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  CREATED_KEYS+=("$name")
  printf '%s %s' "$ak" "$sk"
}
agw() { local ak="$1" sk="$2"; shift 2; AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text apigateway "$@"; }

# --- 1. writer principal + a spec.code Lambda that returns a STRUCTURED 1.0 proxy response ---
log "seeding a writer principal + a spec.code echo Lambda (structured 1.0 response)"
read -r WAK WSK <<<"$(mint_key "agwv1-probe-$SFX" "powerusers")"
[ -n "$WAK" ] && [ -n "$WSK" ] || inconclusive "failed to mint a key"

MADE_CM="agwv1-handler-$SFX"
kubectl -n "$FN_NS" create configmap "$MADE_CM" --from-literal=app.py='import json
def handler(event, context):
    return {"statusCode": 200, "headers": {"Content-Type": "application/json"}, "body": json.dumps(event)}' >/dev/null || inconclusive "could not create handler ConfigMap"

FN="agwv1-echo-$SFX"
cat <<YAML | kubectl apply -f - >/dev/null || inconclusive "could not create the Function"
apiVersion: openinfra.dev/v1
kind: Function
metadata: { name: "${FN}", namespace: "${FN_NS}" }
spec:
  code: { runtime: python3.12, handler: app.handler, source: { configMap: "${MADE_CM}" } }
  expose: false
YAML
MADE_FN="$FN"
for _ in $(seq 1 60); do kubectl -n "$FN_NS" get ksvc "$FN" >/dev/null 2>&1 && break; sleep 2; done
kubectl -n "$FN_NS" get ksvc "$FN" >/dev/null 2>&1 || inconclusive "the Function's ksvc was not created"
kubectl -n "$FN_NS" wait --for=condition=Ready ksvc/"$FN" --timeout=180s >/dev/null 2>&1 || inconclusive "the Function did not become Ready"
sleep 2

# --- 2. control plane: RestApi + resource tree + method + AWS_PROXY integration + deployment/stage ---
log "create-rest-api + resource tree (/items/{id}) + put-method + put-integration (AWS_PROXY) + deploy"
API="$(agw "$WAK" "$WSK" create-rest-api --name "agwv1-probe-$SFX" --query id 2>/dev/null)" || inconclusive "create-rest-api failed — is SQS_PG_URI set?"
[ -n "$API" ] && [ "$API" != "None" ] || inconclusive "create-rest-api returned no id"
CREATED_APIS+=("$API")
ROOT="$(agw "$WAK" "$WSK" get-resources --rest-api-id "$API" --query 'items[0].id' 2>/dev/null)" || fail "get-resources failed"
[ -n "$ROOT" ] && [ "$ROOT" != "None" ] || fail "no root resource"
ITEMS="$(agw "$WAK" "$WSK" create-resource --rest-api-id "$API" --parent-id "$ROOT" --path-part items --query id 2>/dev/null)" || fail "create-resource items failed"
ITEM="$(agw "$WAK" "$WSK" create-resource --rest-api-id "$API" --parent-id "$ITEMS" --path-part '{id}' --query id 2>/dev/null)" || fail "create-resource {id} failed"
agw "$WAK" "$WSK" put-method --rest-api-id "$API" --resource-id "$ITEM" --http-method POST --authorization-type NONE >/dev/null 2>&1 || fail "put-method failed"
agw "$WAK" "$WSK" put-integration --rest-api-id "$API" --resource-id "$ITEM" --http-method POST \
  --type AWS_PROXY --integration-http-method POST \
  --uri "arn:aws:lambda:${REGION}:open-infra:function:${FN}" >/dev/null 2>&1 || fail "put-integration (AWS_PROXY) failed"
agw "$WAK" "$WSK" create-deployment --rest-api-id "$API" --stage-name prod >/dev/null 2>&1 || fail "create-deployment (+stage) failed"
log "  ✓ REST API $API deployed to stage 'prod'"

# --- 3. data plane: AWS_PROXY invoke → faithful 1.0 event → structured response becomes the body ---
log "REAL HTTP POST /prod/items/123 → the Lambda 1.0 proxy event → structured response"
BODY="$WORK/b"
CODE="$(curl -sS -o "$BODY" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"hello":"world"}' \
  "${ENDPOINT}/_apigw/${API}/prod/items/123?q=7" 2>/dev/null || true)"
[ "$CODE" = "200" ] || fail "invoke status '$CODE' want 200. body: $(head -c 400 "$BODY")"
python3 - "$BODY" <<'PY' || fail "the 1.0 proxy event the Lambda received was not faithful"
import json, sys
ev = json.load(open(sys.argv[1]))  # the handler returned {statusCode,body=json(event)}; writeProxyResponse made body the response
assert ev.get("version") == "1.0", f'version={ev.get("version")}'
assert ev.get("httpMethod") == "POST", f'httpMethod={ev.get("httpMethod")}'
assert ev.get("path") == "/items/123", f'path={ev.get("path")}'
assert (ev.get("pathParameters") or {}).get("id") == "123", f'pathParameters={ev.get("pathParameters")}'
assert json.loads(ev.get("body") or "{}").get("hello") == "world", f'body={ev.get("body")}'
rc = ev.get("requestContext", {})
assert rc.get("stage") == "prod", f'stage={rc.get("stage")}'
print("  ✓ 1.0 event faithful: path=/items/123, pathParameters.id=123, method=POST, stage=prod, body populated; structured response became the body")
PY

# --- 4. HTTP_PROXY integration: reverse-proxy to an http origin (the Function's cluster URL) ---
log "HTTP_PROXY integration reverse-proxies to an http origin"
PROXYRES="$(agw "$WAK" "$WSK" create-resource --rest-api-id "$API" --parent-id "$ROOT" --path-part ext --query id 2>/dev/null)" || fail "create-resource ext failed"
agw "$WAK" "$WSK" put-method --rest-api-id "$API" --resource-id "$PROXYRES" --http-method GET --authorization-type NONE >/dev/null 2>&1 || fail "put-method ext failed"
agw "$WAK" "$WSK" put-integration --rest-api-id "$API" --resource-id "$PROXYRES" --http-method GET \
  --type HTTP_PROXY --integration-http-method GET \
  --uri "http://${FN}.${FN_NS}.svc.cluster.local/" >/dev/null 2>&1 || fail "put-integration (HTTP_PROXY) failed"
agw "$WAK" "$WSK" create-deployment --rest-api-id "$API" --stage-name prod >/dev/null 2>&1 || fail "redeploy failed"
EXTCODE="$(curl -sS -o "$WORK/ext" -w '%{http_code}' "${ENDPOINT}/_apigw/${API}/prod/ext" 2>/dev/null || true)"
[ "$EXTCODE" = "200" ] || fail "HTTP_PROXY invoke status '$EXTCODE' want 200 (origin not reached). body: $(head -c 300 "$WORK/ext")"
log "  ✓ HTTP_PROXY reached the origin (200)"

# --- 5a. negative: wrong SigV4 secret on a management call ---
log "negative: a wrong secret on a management call must be rejected"
if agw "$WAK" "wrong-secret-xyz" get-rest-apis >/dev/null 2>"$WORK/n1"; then fail "a wrong secret was accepted"; fi
grep -qiE 'Signature|does not match' "$WORK/n1" || fail "wrong-secret error wrong: $(cat "$WORK/n1")"
log "  ✓ signature mismatch rejected"

# --- 5b. negative: the #185 wiring fence at PutIntegration ---
log "negative (#185): a principal that cannot invoke the Lambda must be refused when wiring it"
read -r NAK NSK <<<"$(mint_key "agwv1-probe-nolambda-$SFX" "powerusers")"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "agwv1-nolambda-$SFX", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::agwv1-probe-nolambda-$SFX"]
    statements:
      - { effect: Deny, actions: ["lambda:InvokeFunction"], resources: ["*"] }
YAML
CREATED_POLICIES+=("agwv1-nolambda-$SFX")
log "  waiting ~35s for the data-plane policy loader..."
sleep 35
NAPI="$(agw "$NAK" "$NSK" create-rest-api --name "agwv1-nolambda-$SFX" --query id 2>/dev/null)" || fail "#185: plain create-rest-api refused (over-blocked)"
{ [ -n "$NAPI" ] && [ "$NAPI" != "None" ]; } && CREATED_APIS+=("$NAPI") || fail "#185: no api id"
NROOT="$(agw "$NAK" "$NSK" get-resources --rest-api-id "$NAPI" --query 'items[0].id' 2>/dev/null)"
NR="$(agw "$NAK" "$NSK" create-resource --rest-api-id "$NAPI" --parent-id "$NROOT" --path-part x --query id 2>/dev/null)" || fail "#185: create-resource failed"
agw "$NAK" "$NSK" put-method --rest-api-id "$NAPI" --resource-id "$NR" --http-method POST --authorization-type NONE >/dev/null 2>&1 || fail "#185: put-method failed"
if agw "$NAK" "$NSK" put-integration --rest-api-id "$NAPI" --resource-id "$NR" --http-method POST \
    --type AWS_PROXY --integration-http-method POST \
    --uri "arn:aws:lambda:${REGION}:open-infra:function:${FN}" >/dev/null 2>"$WORK/n2"; then
  fail "#185 HOLE: a principal that cannot invoke ${FN} wired an AWS_PROXY integration to it"
fi
grep -qiE 'AccessDenied|not authorized to integrate|denied' "$WORK/n2" || fail "#185 denial error wrong: $(cat "$WORK/n2")"
log "  ✓ #185 fence holds for REST v1 (plain API allowed; unauthorized Lambda wiring refused)"

printf '\n✓ PASS — aws-shim API Gateway REST API (v1) is faithful: resource-tree control plane, deployment/stage, the runtime AWS_PROXY→Lambda proxy (faithful 1.0 event; structured response becomes the body), HTTP_PROXY origin proxying, and the auth + #185 wiring-fence boundaries.\n'
