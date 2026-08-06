#!/usr/bin/env bash
# Compatibility probe for the aws-shim AppSync (GraphQL) surface (design handoff §8).
#
# Signs a REAL SigV4 GraphQL request (service `appsync`) and asserts it returns a GraphQL data
# response through the shim → Hasura engine, plus the negative: a wrong secret is rejected as 401
# UnauthorizedException. AppSync's data plane has no aws-CLI command, so this embeds a stdlib SigV4
# signer (python3 + urllib — no external deps), which is exactly how an IAM-auth GraphQL client signs.
#
# On-demand — needs the shim AND the GraphQL engine (`components.graphql`) with its admin secret
# wired into the shim namespace (see docs/aws-shim.md). Exit 0 = pass, 1 = a real failure,
# 42 = INCONCLUSIVE (engine not deployed/wired). Mirrors probe/aws-shim-s3.sh.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-appsync.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
HOSTHDR="${SHIM_HOST:-${ENDPOINT#http://}}"; HOSTHDR="${HOSTHDR#https://}"
REGION="${AWS_REGION:-us-east-1}"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v python3 >/dev/null || inconclusive "python3 is required (SigV4 signer)"
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

# A stdlib SigV4 signer for a GraphQL POST (service appsync). Prints "STATUS <code>\n<body>".
cat > "$WORK/sign.py" <<'PY'
import hashlib,hmac,datetime,os,urllib.request,urllib.error
ak,sk,host,ep=os.environ['AK'],os.environ['SK'],os.environ['HOST'],os.environ['EP']
region,service=os.environ.get('REGION','us-east-1'),'appsync'
body=os.environ.get('BODY','{"query":"{ __typename }"}')
now=datetime.datetime.now(datetime.timezone.utc); amz=now.strftime('%Y%m%dT%H%M%SZ'); ds=now.strftime('%Y%m%d')
ph=hashlib.sha256(body.encode()).hexdigest()
ch=f'content-type:application/json\nhost:{host}\nx-amz-content-sha256:{ph}\nx-amz-date:{amz}\n'
sh='content-type;host;x-amz-content-sha256;x-amz-date'
cr=f'POST\n/graphql\n\n{ch}\n{sh}\n{ph}'
scope=f'{ds}/{region}/{service}/aws4_request'
sts=f'AWS4-HMAC-SHA256\n{amz}\n{scope}\n'+hashlib.sha256(cr.encode()).hexdigest()
sign=lambda k,m:hmac.new(k,m.encode(),hashlib.sha256).digest()
kg=sign(sign(sign(sign(('AWS4'+sk).encode(),ds),region),service),'aws4_request')
sig=hmac.new(kg,sts.encode(),hashlib.sha256).hexdigest()
auth=f'AWS4-HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders={sh}, Signature={sig}'
req=urllib.request.Request(ep+'/graphql',data=body.encode(),method='POST',headers={
 'Content-Type':'application/json','X-Amz-Content-Sha256':ph,'X-Amz-Date':amz,'Authorization':auth})
try:
 r=urllib.request.urlopen(req,timeout=15); print('STATUS',r.status); print(r.read().decode()[:500])
except urllib.error.HTTPError as e:
 print('STATUS',e.code); print(e.read().decode()[:500])
PY

log "seeding a principal + access key"
read -r AK SK <<<"$(mint_key "appsync-probe" "powerusers")"
[ -n "$AK" ] && [ -n "$SK" ] || inconclusive "failed to mint a key"
sleep 2

log "signed GraphQL introspection ({ __typename }) through the shim → engine"
OUT="$(AK="$AK" SK="$SK" EP="$ENDPOINT" HOST="$HOSTHDR" BODY='{"query":"{ __typename }"}' python3 "$WORK/sign.py")"
echo "$OUT" | grep -q '^STATUS 502' && inconclusive "shim returned 502 — the GraphQL engine (components.graphql) is not deployed/wired"
echo "$OUT" | grep -q '^STATUS 200' || fail "GraphQL request did not return 200:\n$OUT"
echo "$OUT" | grep -q '"data"' || fail "GraphQL response had no data field (not a valid GraphQL result):\n$OUT"
log "  ✓ GraphQL data response through the full path: $(echo "$OUT" | tail -1)"

log "negative: a valid key ID with a WRONG secret must be rejected (401)"
NEG="$(AK="$AK" SK="wrong-secret" EP="$ENDPOINT" HOST="$HOSTHDR" python3 "$WORK/sign.py")"
echo "$NEG" | grep -q '^STATUS 401' || fail "wrong secret not rejected with 401:\n$NEG"
echo "$NEG" | grep -qi 'UnauthorizedException' || fail "401 body not the AppSync UnauthorizedException dialect:\n$NEG"
log "  ✓ rejected as 401 UnauthorizedException"

echo
echo "✓ PASS — aws-shim AppSync proxies a signed GraphQL query to the engine and rejects a bad signature."
