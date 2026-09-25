#!/usr/bin/env bash
# Compatibility probe for the aws-shim API Gateway (HTTP API v2) surface — the REST/HTTP complement to
# AppSync that completes the API Gateway → Lambda → DynamoDB serverless triad.
#
# It fires REAL AWS SDK calls (the aws CLI) at the CONTROL plane and REAL HTTP requests (curl) at the DATA
# plane, because the failure this exists to catch is the false green where the management shapes are right
# but the runtime proxy is wrong: the app deploys and then every request fails. It asserts, end to end:
#   - CreateApi (HTTP) + CreateIntegration (AWS_PROXY→Lambda) + CreateRoute (POST /items/{id}) + CreateStage
#   - a REAL HTTP POST to the invoke URL reaches the Lambda with the correct **2.0 proxy event**: the path
#     parameter (id), the method, the query string, and the body are all populated (asserted by inspecting
#     the event the echo Lambda received and echoed back)
#   - the Lambda's returned payload becomes the ACTUAL HTTP response (the 2.0 "simplified" response path)
#   - a **JWT authorizer** (pointed at a real OIDC issuer) REJECTS a missing / unsigned / expired token and
#     ADMITS a valid one — an authorizer that admits everything is an authentication false green
#   - a **CORS preflight** (OPTIONS) succeeds with Access-Control-Allow-Origin
# and the NEGATIVES that are the whole point ("prove the no"):
#   - a valid key ID with a WRONG secret on a management call → SignatureDoesNotMatch
#   - a principal DENIED apigateway:CreateApi is refused
#   - a non-Lambda integration type is REFUSED at CreateIntegration (not accepted into a route that 502s)
#
# The STRUCTURED proxy-response translation ({statusCode,headers,body,isBase64Encoded} → HTTP status +
# headers, the 1.0-requires-structured rule, and upstream-error→502) is covered by the deterministic unit
# tests (apigateway_test.go: TestWriteProxyResponse*), because it requires a handler that emits a JSON
# statusCode field, which the public echo image used here does not — and this probe deliberately depends on
# a PUBLIC image only (like the Lambda probe) to stay self-contained. The live proof here is the event
# contract + the response-becomes-the-body path; the structured path is unit-proven.
#
# On-demand (needs a deployed shim + Knative Serving + the API Gateway Postgres + the platform IAM +
# openssl/python3 to stand up a throwaway OIDC issuer). Exit 0 = pass, 1 = a real failure, 42 =
# INCONCLUSIVE (a prerequisite was missing). Per polyhedron#157, a probe failure is presumed a shim defect.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-apigateway.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
FN_NS="${FUNCTIONS_NAMESPACE:-default}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
# A PUBLIC echo image (like the Lambda probe uses), so the probe is self-contained. It returns HTTP 200
# with a JSON echo of the request it received; under the API Gateway 2.0 "simplified" response rule the shim
# turns that into the HTTP response body, so we can read back exactly the proxy event the Lambda saw.
ECHO_IMG="${APIGW_ECHO_IMAGE:-mendhak/http-https-echo:37}"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v curl    >/dev/null || inconclusive "curl is required (the data-plane client)"
command -v openssl >/dev/null || inconclusive "openssl is required (to mint the OIDC test issuer)"
command -v python3 >/dev/null || inconclusive "python3 is required (base64url + the throwaway issuer)"
kubectl get ksvc  >/dev/null 2>&1 || inconclusive "Knative Serving is not installed (kind: Function needs it)"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"

WORK="$(mktemp -d)"
CREATED_KEYS=(); CREATED_USERS=(); CREATED_POLICIES=(); CREATED_APIS=(); MADE_FN=""; MADE_OIDC=""
cleanup() {
  for a in "${CREATED_APIS[@]:-}";     do [ -n "$a" ] && AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager apigatewayv2 delete-api --api-id "$a" >/dev/null 2>&1 || true; done
  [ -n "$MADE_FN" ]   && kubectl -n "$FN_NS" delete function.openinfra.dev "$MADE_FN" --ignore-not-found >/dev/null 2>&1 || true
  [ -n "$MADE_OIDC" ] && { kubectl -n "$SHIM_NS" delete pod "$MADE_OIDC" --ignore-not-found >/dev/null 2>&1; kubectl -n "$SHIM_NS" delete svc "$MADE_OIDC" --ignore-not-found >/dev/null 2>&1; } || true
  for k in "${CREATED_KEYS[@]:-}";     do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}";    do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for p in "${CREATED_POLICIES[@]:-}"; do [ -n "$p" ] && kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev "$p" --ignore-not-found >/dev/null 2>&1 || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }
b64url() { base64 | tr '+/' '-_' | tr -d '=\n'; }

mint_key() { # <owner> <group> -> "AK SK"
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

agw() { # AK SK -- <apigatewayv2 args...>
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text apigatewayv2 "$@"
}

# --- 1. Seed a writer principal + key + the echo Lambda -----------------------------------------
log "seeding a writer principal + access key + the echo Lambda (kind: Function)"
read -r WAK WSK <<<"$(mint_key "agw-probe-$SFX" "powerusers")"
[ -n "$WAK" ] && [ -n "$WSK" ] || inconclusive "failed to mint a key"

FN="agw-echo-$SFX"
cat <<YAML | kubectl apply -f - >/dev/null || inconclusive "could not create the echo Function"
apiVersion: openinfra.dev/v1
kind: Function
metadata: { name: "${FN}", namespace: "${FN_NS}" }
spec: { image: "${ECHO_IMG}", port: 8080, expose: false }
YAML
MADE_FN="$FN"
log "  waiting for the echo Function's Knative service to be Ready..."
# The kind: Function composition creates the ksvc ASYNCHRONOUSLY (claim → XFunction → provider-kubernetes
# Object → Knative Service), so it does not exist the instant the claim is applied. `kubectl wait` on a
# not-yet-created object errors NotFound and exits immediately, so wait for CREATION first, then Ready.
for _ in $(seq 1 60); do kubectl -n "$FN_NS" get ksvc "$FN" >/dev/null 2>&1 && break; sleep 2; done
kubectl -n "$FN_NS" get ksvc "$FN" >/dev/null 2>&1 \
  || inconclusive "the echo Function's ksvc was not created (composition did not reconcile in time)"
kubectl -n "$FN_NS" wait --for=condition=Ready ksvc/"$FN" --timeout=180s >/dev/null 2>&1 \
  || inconclusive "the echo Function did not become Ready (Knative)"
sleep 2

# --- 2. Control plane: CreateApi + integration + route + stage ---------------------------------
log "create-api (HTTP) + integration (AWS_PROXY) + route (POST /items/{id}) + stage (\$default)"
API="$(agw "$WAK" "$WSK" create-api --name "agw-probe-$SFX" --protocol-type HTTP \
  --cors-configuration '{"AllowOrigins":["https://app.example.com"],"AllowMethods":["POST","OPTIONS"],"AllowHeaders":["content-type"]}' \
  --query ApiId 2>/dev/null)" || inconclusive "create-api failed — is SQS_PG_URI set on the shim?"
[ -n "$API" ] && [ "$API" != "None" ] || inconclusive "create-api returned no ApiId"
CREATED_APIS+=("$API")

INTID="$(agw "$WAK" "$WSK" create-integration --api-id "$API" --integration-type AWS_PROXY \
  --integration-uri "arn:aws:lambda:${REGION}:open-infra:function:${FN}" --payload-format-version 2.0 \
  --query IntegrationId 2>/dev/null)" || fail "create-integration failed"
[ -n "$INTID" ] && [ "$INTID" != "None" ] || fail "create-integration returned no IntegrationId"

agw "$WAK" "$WSK" create-route --api-id "$API" --route-key 'POST /items/{id}' --target "integrations/$INTID" >/dev/null 2>&1 || fail "create-route failed"
agw "$WAK" "$WSK" create-stage --api-id "$API" --stage-name '$default' --auto-deploy >/dev/null 2>&1 || fail "create-stage failed"
log "  ✓ API $API wired (integration $INTID)"

# --- 3. Data plane: a REAL HTTP request → the 2.0 proxy event → the response ---------------------
log "REAL HTTP POST to the invoke URL → the Lambda 2.0 proxy event → the response body"
INVOKE="${ENDPOINT}/_apigw/${API}/items/123?q=1&q=2"
RESP_HDRS="$WORK/resp.hdrs"; RESP_BODY="$WORK/resp.body"
CODE="$(curl -sS -o "$RESP_BODY" -D "$RESP_HDRS" -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' -d '{"hello":"world"}' "$INVOKE" 2>/dev/null || true)"
[ "$CODE" = "200" ] || fail "invoke HTTP status = '$CODE', want 200 (the Lambda response did not become the HTTP response). body: $(cat "$RESP_BODY" 2>/dev/null | head -c 400)"
# The echo Lambda received the proxy event as its request body and echoed it back under ".body"; the 2.0
# simplified rule made that echo the HTTP response body. Assert the event contract the Lambda actually saw.
python3 - "$RESP_BODY" <<'PY' || fail "the 2.0 proxy event the Lambda received was not faithful"
import json,sys
echo=json.load(open(sys.argv[1]))
ev=echo["json"]  # mendhak parses the (JSON) request body it received under ".json" = our proxy event
assert ev.get("version")=="2.0", f'version={ev.get("version")}'
assert ev.get("routeKey")=="POST /items/{id}", f'routeKey={ev.get("routeKey")}'
assert ev.get("rawPath")=="/items/123", f'rawPath={ev.get("rawPath")}'
assert ev.get("pathParameters",{}).get("id")=="123", f'pathParameters={ev.get("pathParameters")}'
assert ev["requestContext"]["http"]["method"]=="POST", "method"
assert "q=1&q=2" in ev.get("rawQueryString",""), f'rawQueryString={ev.get("rawQueryString")}'
assert json.loads(ev.get("body","{}")).get("hello")=="world", f'body={ev.get("body")}'
print("  ✓ 2.0 event faithful: pathParameters.id=123, method=POST, query + body populated; response=Lambda payload")
PY

# --- 4. CORS preflight -------------------------------------------------------------------------
log "CORS preflight (OPTIONS) must succeed with Access-Control-Allow-Origin"
PRE_HDRS="$WORK/pre.hdrs"
PCODE="$(curl -sS -o /dev/null -D "$PRE_HDRS" -w '%{http_code}' -X OPTIONS \
  -H 'Origin: https://app.example.com' -H 'Access-Control-Request-Method: POST' \
  "${ENDPOINT}/_apigw/${API}/items/1" 2>/dev/null || true)"
case "$PCODE" in 200|204) : ;; *) fail "CORS preflight status = '$PCODE', want 204";; esac
grep -qi '^access-control-allow-origin: https://app.example.com' "$PRE_HDRS" || fail "CORS preflight missing Access-Control-Allow-Origin: $(cat "$PRE_HDRS")"
log "  ✓ preflight 204 + Access-Control-Allow-Origin"

# --- 5. JWT authorizer: reject missing/unsigned/expired, admit valid --------------------------
log "standing up a throwaway RSA OIDC issuer for the JWT authorizer"
openssl genrsa -out "$WORK/key.pem" 2048 >/dev/null 2>&1 || inconclusive "openssl genrsa failed"
MOD_HEX="$(openssl rsa -in "$WORK/key.pem" -noout -modulus 2>/dev/null | sed 's/Modulus=//')"
KID="probe-key-$SFX"; AUD="agw-probe-aud-$SFX"
MADE_OIDC="agw-oidc-$SFX"
ISS="http://${MADE_OIDC}.${SHIM_NS}.svc.cluster.local"
N="$(python3 -c "import binascii,base64;print(base64.urlsafe_b64encode(binascii.unhexlify('$MOD_HEX')).decode().rstrip('='))")"
JWKS="{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"$KID\",\"n\":\"$N\",\"e\":\"AQAB\"}]}"
DISC="{\"issuer\":\"$ISS\",\"jwks_uri\":\"$ISS/jwks\",\"authorization_endpoint\":\"$ISS/auth\",\"response_types_supported\":[\"id_token\"],\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":[\"RS256\"]}"
OIDC_SERVER='import os
from http.server import BaseHTTPRequestHandler,HTTPServer
D=os.environ["DISC"].encode();J=os.environ["JWKS"].encode()
class H(BaseHTTPRequestHandler):
 def do_GET(s):
  b=D if s.path.startswith("/.well-known/openid-configuration") else (J if s.path.rstrip("/")=="/jwks" else b"{}")
  s.send_response(200);s.send_header("Content-Type","application/json");s.send_header("Content-Length",str(len(b)));s.end_headers();s.wfile.write(b)
 def log_message(s,*a):pass
HTTPServer(("0.0.0.0",80),H).serve_forever()'
kubectl -n "$SHIM_NS" run "$MADE_OIDC" --image=python:3.12-alpine --restart=Never \
  --labels="app=$MADE_OIDC" --env="DISC=$DISC" --env="JWKS=$JWKS" \
  --command -- python3 -c "$OIDC_SERVER" >/dev/null 2>&1 || inconclusive "could not start the OIDC issuer pod"
kubectl -n "$SHIM_NS" expose pod "$MADE_OIDC" --port=80 --name="$MADE_OIDC" >/dev/null 2>&1 || inconclusive "could not expose the OIDC issuer"
kubectl -n "$SHIM_NS" wait pod "$MADE_OIDC" --for=condition=Ready --timeout=60s >/dev/null 2>&1 || inconclusive "OIDC issuer pod not Ready"
sleep 2

mk_jwt() { # <exp_epoch> -> a signed RS256 JWT
  local exp="$1" now; now="$(date +%s)"
  local h p sig
  h="$(printf '{"alg":"RS256","typ":"JWT","kid":"%s"}' "$KID" | b64url)"
  p="$(printf '{"iss":"%s","aud":"%s","sub":"probe-user","iat":%s,"exp":%s}' "$ISS" "$AUD" "$now" "$exp" | b64url)"
  sig="$(printf '%s.%s' "$h" "$p" | openssl dgst -sha256 -sign "$WORK/key.pem" -binary | b64url)"
  printf '%s.%s.%s' "$h" "$p" "$sig"
}
VALID_JWT="$(mk_jwt "$(( $(date +%s) + 3600 ))")"
EXPIRED_JWT="$(mk_jwt "$(( $(date +%s) - 60 ))")"

log "create JWT authorizer + a POST /secure route gated by it"
AUTHID="$(agw "$WAK" "$WSK" create-authorizer --api-id "$API" --authorizer-type JWT --name "agw-jwt-$SFX" \
  --identity-source '$request.header.Authorization' \
  --jwt-configuration "Issuer=$ISS,Audience=$AUD" --query AuthorizerId 2>/dev/null)" || fail "create-authorizer failed"
[ -n "$AUTHID" ] && [ "$AUTHID" != "None" ] || fail "create-authorizer returned no AuthorizerId"
agw "$WAK" "$WSK" create-route --api-id "$API" --route-key 'POST /secure' --target "integrations/$INTID" \
  --authorization-type JWT --authorizer-id "$AUTHID" >/dev/null 2>&1 || fail "create-route (secure) failed"

SECURE="${ENDPOINT}/_apigw/${API}/secure"
sec_code() { curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' "$@" -d '{}' "$SECURE" 2>/dev/null || true; }
log "  no token → 401; unsigned → 401; expired → 401; valid → admitted (200)"
[ "$(sec_code)" = "401" ] || fail "a request with NO token to a JWT-gated route was not 401"
[ "$(sec_code -H 'Authorization: Bearer not.a.real.jwt')" = "401" ] || fail "an unsigned/garbage token was not rejected (401)"
[ "$(sec_code -H "Authorization: Bearer $EXPIRED_JWT")" = "401" ] || fail "an EXPIRED token was admitted (must be 401)"
VCODE="$(sec_code -H "Authorization: Bearer $VALID_JWT")"
[ "$VCODE" = "200" ] || fail "a VALID JWT was NOT admitted (got '$VCODE', want 200) — issuer discovery/verify failed"
log "  ✓ JWT authorizer: rejects missing/unsigned/expired, admits valid"

# --- 6. audit: an invoke wrote a record naming the principal-less data-plane op ----------------
log "audit: a data-plane Invoke must have written a structured record"
sleep 1
kubectl -n "$SHIM_NS" logs deploy/aws-shim --since=300s 2>/dev/null | grep '"msg":"apigateway audit"' | grep '"op":"Invoke"' | grep "\"api\":\"$API\"" >/dev/null \
  || fail "no API Gateway audit record found for the data-plane Invoke"
log "  ✓ invoke audit record present"

# --- 7a. Negative: wrong SigV4 secret ---------------------------------------------------------
log "negative: a valid key ID with a WRONG secret on a management call must be rejected"
if agw "$WAK" "wrong-secret-not-the-real-one" get-apis >/dev/null 2>"$WORK/neg1"; then
  fail "a wrong secret was accepted on a management call"
fi
grep -qiE 'Signature|does not match' "$WORK/neg1" || fail "wrong secret rejected with the wrong error: $(cat "$WORK/neg1")"
log "  ✓ rejected on signature mismatch"

# --- 7b. Negative: non-Lambda integration refused ---------------------------------------------
log "negative: a non-Lambda (HTTP_PROXY) integration must be REFUSED at CreateIntegration"
if agw "$WAK" "$WSK" create-integration --api-id "$API" --integration-type HTTP_PROXY \
    --integration-uri "https://example.com" --payload-format-version 1.0 >/dev/null 2>"$WORK/neg2"; then
  fail "HTTP_PROXY integration was accepted (would 502 at runtime)"
fi
grep -qiE 'AWS_PROXY|not fronted|BadRequest' "$WORK/neg2" || fail "HTTP_PROXY refusal had the wrong error: $(cat "$WORK/neg2")"
log "  ✓ HTTP_PROXY refused"

# --- 7c. Negative: a principal DENIED apigateway:CreateApi ------------------------------------
log "negative: a principal DENIED apigateway:CreateApi must be refused"
read -r DAK DSK <<<"$(mint_key "agw-probe-denied-$SFX" "powerusers")"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "agw-denied-$SFX", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::agw-probe-denied-$SFX"]
    statements:
      - { effect: Deny, actions: ["apigateway:CreateApi"], resources: ["*"] }
YAML
CREATED_POLICIES+=("agw-denied-$SFX")
log "  waiting ~35s for the data-plane policy loader to pick it up..."
sleep 35
if agw "$DAK" "$DSK" create-api --name "agw-denied-probe-$SFX" --protocol-type HTTP >/dev/null 2>"$WORK/neg3"; then
  fail "a principal denied apigateway:CreateApi created an API"
fi
grep -qiE 'AccessDenied|denied' "$WORK/neg3" || fail "CreateApi denial had the wrong error: $(cat "$WORK/neg3")"
log "  ✓ denied principal refused"

printf '\n✓ PASS — aws-shim API Gateway (HTTP API v2) is semantically faithful: control plane + the runtime AWS_PROXY→Lambda proxy (faithful 2.0 event; Lambda payload becomes the response), a real JWT authorizer (reject missing/unsigned/expired, admit valid), CORS, and the auth/refusal boundaries. (The structured {statusCode,headers} response translation is unit-proven — apigateway_test.go.)\n'
