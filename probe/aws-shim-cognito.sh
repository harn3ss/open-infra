#!/usr/bin/env bash
# Compatibility probe for the aws-shim Cognito (user pools) surface (polyhedron#171).
#
# The token contract is the heart: InitiateAuth must return REAL, signed, JWKS-verifiable JWTs, or every
# downstream verification is theater. It asserts, over real round-trips:
#   - CreateUserPool (with a password policy) + CreateUserPoolClient (USER_PASSWORD_AUTH)
#   - the password policy is GENUINELY enforced at SignUp (a weak password → InvalidPasswordException)
#   - SignUp + AdminConfirmSignUp, then InitiateAuth returns tokens; a WRONG password → NotAuthorizedException
#   - the pool serves a JWKS + OIDC discovery document; and an **API Gateway JWT authorizer (#169) pointed at
#     the pool ADMITS the issued token** (the real cryptographic verification, end to end Cognito→API Gateway)
#     and REJECTS a garbage token
#   - GlobalSignOut GENUINELY invalidates: GetUser with the same access token afterward is rejected
# and the NEGATIVES:
#   - a control-plane call with a WRONG secret → SignatureDoesNotMatch
#   - a non-admin principal is DENIED AdminCreateUser
#
# On-demand (needs a deployed shim + Knative + the Cognito Postgres + a signing key + the API Gateway doorway).
# Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE. Per polyhedron#157, a probe failure is a shim defect.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-cognito.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
FN_NS="${FUNCTIONS_NAMESPACE:-default}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
ECHO_IMG="${APIGW_ECHO_IMAGE:-mendhak/http-https-echo:37}"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v curl    >/dev/null || inconclusive "curl is required"
command -v python3 >/dev/null || inconclusive "python3 is required"
kubectl get ksvc   >/dev/null 2>&1 || inconclusive "Knative Serving is not installed"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

CREATED_KEYS=(); CREATED_USERS=(); CREATED_POOLS=(); CREATED_APIS=(); MADE_FN=""
AAK=""; ASK=""
cog_admin() { AWS_ACCESS_KEY_ID="$AAK" AWS_SECRET_ACCESS_KEY="$ASK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text cognito-idp "$@"; }
cog_pub()   { AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --no-sign-request --output text cognito-idp "$@"; }
agw()       { AWS_ACCESS_KEY_ID="$AAK" AWS_SECRET_ACCESS_KEY="$ASK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text apigatewayv2 "$@"; }
cleanup() {
  for a in "${CREATED_APIS[@]:-}";  do [ -n "$a" ] && agw delete-api --api-id "$a" >/dev/null 2>&1 || true; done
  [ -n "$MADE_FN" ] && kubectl -n "$FN_NS" delete function.openinfra.dev "$MADE_FN" --ignore-not-found >/dev/null 2>&1 || true
  for p in "${CREATED_POOLS[@]:-}"; do [ -n "$p" ] && cog_admin delete-user-pool --user-pool-id "$p" >/dev/null 2>&1 || true; done
  for k in "${CREATED_KEYS[@]:-}"; do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
}
trap cleanup EXIT

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }
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
  kubectl -n "$SHIM_NS" create secret generic "$name" --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  CREATED_KEYS+=("$name")
  printf '%s %s' "$ak" "$sk"
}

# --- 1. Admin caller (control-plane) ------------------------------------------------------------
log "seeding an admin caller (openinfra:powerusers) + key"
read -r AAK ASK <<<"$(mint_key "cog-probe-admin-$SFX" "powerusers")"
[ -n "$AAK" ] && [ -n "$ASK" ] || inconclusive "failed to mint a key"
sleep 2

# --- 2. CreateUserPool (password policy) + client ----------------------------------------------
log "create-user-pool (password policy: min 8, upper+lower+number+symbol) + app client (USER_PASSWORD_AUTH)"
POOL="$(cog_admin create-user-pool --pool-name "cog-probe-$SFX" \
  --policies 'PasswordPolicy={MinimumLength=8,RequireUppercase=true,RequireLowercase=true,RequireNumbers=true,RequireSymbols=true}' \
  --query 'UserPool.Id' 2>"$PWD/.cog_cp")" || inconclusive "create-user-pool failed (SQS_PG_URI + signing key set?): $(cat "$PWD/.cog_cp" 2>/dev/null)"
[ -n "$POOL" ] && [ "$POOL" != "None" ] || inconclusive "create-user-pool returned no Id"
CREATED_POOLS+=("$POOL"); rm -f "$PWD/.cog_cp"
CLIENT="$(cog_admin create-user-pool-client --user-pool-id "$POOL" --client-name app --explicit-auth-flows USER_PASSWORD_AUTH --query 'UserPoolClient.ClientId' 2>/dev/null)"
[ -n "$CLIENT" ] && [ "$CLIENT" != "None" ] || fail "create-user-pool-client returned no ClientId"
log "  ✓ pool $POOL, client $CLIENT"

# --- 3. Password policy genuinely enforced at SignUp -------------------------------------------
log "negative: a weak password must be REFUSED at sign-up (password policy enforced)"
if cog_pub sign-up --client-id "$CLIENT" --username "weak-$SFX" --password "weak" >/dev/null 2>"$PWD/.cog_weak"; then
  fail "a weak password was accepted at sign-up (IA-5 false green)"
fi
grep -qiE 'InvalidPassword|policy|password' "$PWD/.cog_weak" || fail "weak-password refusal had the wrong error: $(cat "$PWD/.cog_weak")"
rm -f "$PWD/.cog_weak"
log "  ✓ weak password refused"

# --- 4. SignUp + confirm, then InitiateAuth ---------------------------------------------------
USERNAME="cog-user-$SFX"; PASSWORD="Sup3r!Secret9"
log "sign-up ${USERNAME} + admin-confirm-sign-up"
cog_pub sign-up --client-id "$CLIENT" --username "$USERNAME" --password "$PASSWORD" --user-attributes Name=email,Value="${USERNAME}@example.com" >/dev/null 2>&1 || fail "sign-up failed"
cog_admin admin-confirm-sign-up --user-pool-id "$POOL" --username "$USERNAME" >/dev/null 2>&1 || fail "admin-confirm-sign-up failed"

log "negative: a WRONG password must be rejected"
if cog_pub initiate-auth --client-id "$CLIENT" --auth-flow USER_PASSWORD_AUTH --auth-parameters "USERNAME=$USERNAME,PASSWORD=WrongPass1!" >/dev/null 2>"$PWD/.cog_wp"; then
  fail "a wrong password authenticated"
fi
grep -qiE 'NotAuthorized|Incorrect' "$PWD/.cog_wp" || fail "wrong-password rejection had the wrong error: $(cat "$PWD/.cog_wp")"
rm -f "$PWD/.cog_wp"

log "initiate-auth (USER_PASSWORD_AUTH) → real JWTs"
AUTH_JSON="$(mktemp)"
cog_pub initiate-auth --client-id "$CLIENT" --auth-flow USER_PASSWORD_AUTH --auth-parameters "USERNAME=$USERNAME,PASSWORD=$PASSWORD" --output json >"$AUTH_JSON" 2>/dev/null || fail "initiate-auth failed"
ID_TOKEN="$(python3 -c 'import sys,json;print(json.load(open(sys.argv[1]))["AuthenticationResult"]["IdToken"])' "$AUTH_JSON")"
ACCESS_TOKEN="$(python3 -c 'import sys,json;print(json.load(open(sys.argv[1]))["AuthenticationResult"]["AccessToken"])' "$AUTH_JSON")"
rm -f "$AUTH_JSON"
[ -n "$ID_TOKEN" ] && [ -n "$ACCESS_TOKEN" ] || fail "initiate-auth returned no tokens"
# assert the id-token claims (structure + iss + token_use)
python3 - "$ID_TOKEN" "$ENDPOINT" "$POOL" <<'PY' || fail "the id token claims are not faithful"
import sys,json,base64
def dec(seg): return json.loads(base64.urlsafe_b64decode(seg + "="*(-len(seg)%4)))
tok,ep,pool=sys.argv[1],sys.argv[2],sys.argv[3]
h,p,_=tok.split(".")
hdr,claims=dec(h),dec(p)
assert hdr["alg"]=="RS256", hdr
assert claims["token_use"]=="id", claims["token_use"]
assert claims["iss"].endswith("/cognito/"+pool), claims["iss"]
print("  ✓ id token: RS256, token_use=id, issuer names the pool")
PY

# --- 5. The pool serves JWKS + discovery ------------------------------------------------------
log "the pool serves a JWKS + OIDC discovery document (what verifiers fetch)"
curl -fsS -m 5 "${ENDPOINT}/cognito/${POOL}/.well-known/openid-configuration" 2>/dev/null | grep -q "jwks_uri" || fail "pool discovery document not served"
curl -fsS -m 5 "${ENDPOINT}/cognito/${POOL}/.well-known/jwks.json" 2>/dev/null | grep -q '"kty":"RSA"' || fail "pool JWKS not served"
log "  ✓ discovery + JWKS served"

# --- 6. An API Gateway JWT authorizer pointed at the pool ADMITS the token (crypto verification) --
log "deploying an echo Lambda + an HTTP API with a JWT authorizer pointed at the pool"
FN="cog-echo-$SFX"
cat <<YAML | kubectl apply -f - >/dev/null || inconclusive "could not create the echo Function"
apiVersion: openinfra.dev/v1
kind: Function
metadata: { name: "${FN}", namespace: "${FN_NS}" }
spec: { image: "${ECHO_IMG}", port: 8080, expose: false }
YAML
MADE_FN="$FN"
for _ in $(seq 1 60); do kubectl -n "$FN_NS" get ksvc "$FN" >/dev/null 2>&1 && break; sleep 2; done
kubectl -n "$FN_NS" wait --for=condition=Ready ksvc/"$FN" --timeout=180s >/dev/null 2>&1 || inconclusive "echo Function not Ready"
API="$(agw create-api --name "cog-api-$SFX" --protocol-type HTTP --query ApiId 2>/dev/null)" || inconclusive "create-api failed (is the API Gateway doorway present?)"
CREATED_APIS+=("$API")
INT="$(agw create-integration --api-id "$API" --integration-type AWS_PROXY --integration-uri "arn:aws:lambda:${REGION}:open-infra:function:${FN}" --payload-format-version 2.0 --query IntegrationId 2>/dev/null)"
ISS="${ENDPOINT%/}"; ISS="${ISS/localhost:4566/aws-shim.${SHIM_NS}.svc.cluster.local:4566}"   # issuer must be the in-cluster URL the shim can resolve
POOL_ISS="http://aws-shim.${SHIM_NS}.svc.cluster.local:4566/cognito/${POOL}"
AUTHID="$(agw create-authorizer --api-id "$API" --authorizer-type JWT --name cogjwt --identity-source '$request.header.Authorization' --jwt-configuration "Issuer=$POOL_ISS,Audience=$CLIENT" --query AuthorizerId 2>/dev/null)" || fail "create-authorizer failed"
agw create-route --api-id "$API" --route-key 'POST /secure' --target "integrations/$INT" --authorization-type JWT --authorizer-id "$AUTHID" >/dev/null 2>&1 || fail "create-route failed"
agw create-stage --api-id "$API" --stage-name '$default' --auto-deploy >/dev/null 2>&1 || fail "create-stage failed"
sleep 3
log "  API Gateway JWT authorizer must ADMIT the Cognito id token, and REJECT a garbage token"
SEC="${ENDPOINT}/_apigw/${API}/secure"
CODE_OK="$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $ID_TOKEN" -H 'content-type: application/json' -d '{}' "$SEC" 2>/dev/null || true)"
[ "$CODE_OK" = "200" ] || fail "the API Gateway JWT authorizer did NOT admit the Cognito token (got '$CODE_OK') — JWKS verification failed end to end"
CODE_BAD="$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'Authorization: Bearer not.a.real.token' -H 'content-type: application/json' -d '{}' "$SEC" 2>/dev/null || true)"
[ "$CODE_BAD" = "401" ] || fail "a garbage token was not rejected by the JWT authorizer (got '$CODE_BAD')"
log "  ✓ API Gateway JWT authorizer admits the Cognito token, rejects garbage (JWKS verified end to end)"

# --- 7. GlobalSignOut genuinely invalidates ---------------------------------------------------
log "get-user works, then global-sign-out must INVALIDATE the access token"
cog_pub get-user --access-token "$ACCESS_TOKEN" >/dev/null 2>"$PWD/.cog_gu" || fail "get-user failed before sign-out: $(cat "$PWD/.cog_gu" 2>/dev/null)"
rm -f "$PWD/.cog_gu"
cog_pub global-sign-out --access-token "$ACCESS_TOKEN" >/dev/null 2>&1 || fail "global-sign-out failed"
sleep 1
if cog_pub get-user --access-token "$ACCESS_TOKEN" >/dev/null 2>"$PWD/.cog_gu2"; then
  fail "the access token still worked AFTER global-sign-out (revocation not enforced — security defect)"
fi
grep -qiE 'NotAuthorized|revoked' "$PWD/.cog_gu2" || fail "post-sign-out rejection had the wrong error: $(cat "$PWD/.cog_gu2")"
rm -f "$PWD/.cog_gu2"
log "  ✓ global-sign-out invalidated the token"

# --- 8a. Negative: control-plane wrong secret -------------------------------------------------
log "negative: a control-plane call with a WRONG secret must be rejected"
if AWS_ACCESS_KEY_ID="$AAK" AWS_SECRET_ACCESS_KEY="wrong-not-the-real-secret" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager cognito-idp create-user-pool --pool-name "x-$SFX" >/dev/null 2>"$PWD/.cog_neg"; then
  fail "a wrong secret was accepted on a control-plane call"
fi
grep -qiE 'Signature|does not match' "$PWD/.cog_neg" || fail "wrong secret rejected with the wrong error: $(cat "$PWD/.cog_neg")"
rm -f "$PWD/.cog_neg"
log "  ✓ rejected on signature mismatch"

# --- 8b. Negative: a non-admin principal denied AdminCreateUser -------------------------------
log "negative: a non-admin principal must be DENIED AdminCreateUser"
read -r NAK NSK <<<"$(mint_key "cog-probe-nonadmin-$SFX" "readonly")"
if AWS_ACCESS_KEY_ID="$NAK" AWS_SECRET_ACCESS_KEY="$NSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager cognito-idp admin-create-user --user-pool-id "$POOL" --username "sneaky-$SFX" >/dev/null 2>"$PWD/.cog_na"; then
  fail "a non-admin principal performed AdminCreateUser"
fi
grep -qiE 'NotAuthorized|denied|AccessDenied' "$PWD/.cog_na" || fail "non-admin AdminCreateUser denial had the wrong error: $(cat "$PWD/.cog_na")"
rm -f "$PWD/.cog_na"
log "  ✓ non-admin denied AdminCreateUser"

printf '\n✓ PASS — aws-shim Cognito is semantically faithful: real RS256 JWTs verifiable against the pool JWKS (admitted end-to-end by an API Gateway JWT authorizer), password policy enforced, wrong password rejected, GlobalSignOut genuinely invalidates, and the control-plane vs end-user auth boundaries hold.\n'
