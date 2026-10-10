#!/usr/bin/env bash
# Compatibility probe for the aws-shim ECR PER-REPO data-plane authorization (the Docker registry
# bearer-token protocol, shim as token server). Proves the auth DECISIONS end-to-end against the
# live registry:
#   - the registry now does token auth (401 + WWW-Authenticate: Bearer realm=<shim /ecr/token>)
#   - GetAuthorizationToken returns a caller credential; /ecr/token mints a registry bearer scoped
#     to only what the caller may do
#   - an authorized caller (powerusers) gets a push-capable token → blob-upload init is accepted
#   - a read-only caller (readers) gets NO push scope → blob-upload init is denied, but a pull
#     (tags list) is allowed
#
# This is the "prove the no" for per-repo scoping: naming a repo is not enough; the caller's actual
# authority decides. On-demand; needs the shim + registry with ECR_TOKEN_AUTH on. Exit 0 = pass,
# 1 = a real failure, 42 = INCONCLUSIVE (a prerequisite was missing).
#
#   SHIM_ENDPOINT=http://localhost:4566 REG_ENDPOINT=http://localhost:5000 ./probe/aws-shim-ecr-perrepo.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REG="${REG_ENDPOINT:-http://ecr-registry.open-infra-ecr.svc.cluster.local:5000}"
REGION="${AWS_REGION:-us-east-1}"
REPO="${PROBE_REPO:-probe-perrepo-$$}"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws >/dev/null && command -v kubectl >/dev/null && command -v curl >/dev/null || inconclusive "need aws, kubectl, curl"
curl -fsS -m5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

CREATED_KEYS=(); CREATED_USERS=()
cleanup() {
  for s in "${CREATED_KEYS[@]:-}";  do [ -n "$s" ] && kubectl -n "$SHIM_NS" delete secret "$s" --ignore-not-found >/dev/null 2>&1 || true; done
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

# caller_cred <AK> <SK> -> the "AWS:<jwt>" credential GetAuthorizationToken hands back (decoded).
caller_cred() {
  local ak="$1" sk="$2"
  local t; t="$(AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text ecr get-authorization-token --query 'authorizationData[0].authorizationToken')"
  printf '%s' "$t" | base64 -d
}

# reg_token <cred> <scope> -> the registry bearer token for the scope (empty if none granted/denied).
reg_token() {
  local cred="$1" scope="$2"
  curl -s -u "$cred" "${ENDPOINT}/ecr/token?service=ecr-registry&scope=${scope}" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p'
}

# --- 1. the registry speaks token auth now ---
log "registry /v2/ should 401 with a Bearer realm pointing at the shim token endpoint"
HDRS="$(curl -sI -m 10 "${REG}/v2/" || true)"
echo "$HDRS" | grep -qiE "^HTTP/.* 401" || fail "registry /v2/ did not 401 (is token auth live?): $(echo "$HDRS" | head -1)"
echo "$HDRS" | grep -qi 'Www-Authenticate: *Bearer' || fail "registry did not advertise Bearer auth"
echo "$HDRS" | grep -qi '/ecr/token' || fail "the Bearer realm does not point at the shim token endpoint"
log "  ✓ token auth live, realm points at the shim"

# --- 2. an authorized (powerusers) caller gets a push-capable token + the registry accepts a push ---
log "seeding a powerusers (writer) + a readers (read-only) principal"
read -r PAK PSK <<<"$(mint_key "probe-ecr-writer" "powerusers")"
read -r RAK RSK <<<"$(mint_key "probe-ecr-reader" "readers")"
[ -n "$PAK" ] && [ -n "$RAK" ] || inconclusive "failed to mint keys"
sleep 2
PCRED="$(caller_cred "$PAK" "$PSK")"; RCRED="$(caller_cred "$RAK" "$RSK")"
case "$PCRED" in AWS:*) ;; *) fail "GetAuthorizationToken did not return an AWS:<token> credential (ECR_TOKEN_AUTH on?): $PCRED" ;; esac

log "writer: get a push token for ${REPO} and init a blob upload (expect accepted)"
PTOK="$(reg_token "$PCRED" "repository:${REPO}:pull,push")"
[ -n "$PTOK" ] || fail "writer got no registry token"
WCODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $PTOK" "${REG}/v2/${REPO}/blobs/uploads/")"
case "$WCODE" in 202|201) log "  ✓ authorized push accepted ($WCODE)";; *) fail "authorized writer push-init was not accepted: HTTP $WCODE";; esac

# --- 3. a read-only caller is DENIED push, ALLOWED pull (prove the no) ---
log "reader: a push token must carry NO push scope → push-init denied"
RTOK_PUSH="$(reg_token "$RCRED" "repository:${REPO}:pull,push")"
if [ -n "$RTOK_PUSH" ]; then
  RCODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $RTOK_PUSH" "${REG}/v2/${REPO}/blobs/uploads/")"
  case "$RCODE" in 401|403) log "  ✓ read-only push denied ($RCODE)";; *) fail "read-only push-init should be denied, got HTTP $RCODE";; esac
else
  log "  ✓ read-only caller was granted no token for a push scope"
fi

log "reader: pull is allowed (tags list returns 200, not 401)"
RTOK_PULL="$(reg_token "$RCRED" "repository:${REPO}:pull")"
[ -n "$RTOK_PULL" ] || fail "read-only caller got no pull token"
PCODE="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $RTOK_PULL" "${REG}/v2/${REPO}/tags/list")"
case "$PCODE" in 200|404) log "  ✓ read-only pull authorized ($PCODE — 404 = repo empty but access granted)";; 401|403) fail "read-only pull should be authorized, got HTTP $PCODE";; *) fail "unexpected pull status HTTP $PCODE";; esac

printf '\n✓ PASS — aws-shim ECR per-repo auth is faithful: token auth is live, push is granted only to callers authorized for it, and read-only callers pull but cannot push.\n'
