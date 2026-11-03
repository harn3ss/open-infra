#!/usr/bin/env bash
# Compatibility probe for the aws-shim AppSync (GraphQL) surface.
#
# Signs a REAL SigV4 GraphQL request (service `appsync`) and asserts the FRONT DOOR works: the
# request is authenticated + passes the coarse IAM gate + reaches the open-appsync engine, which
# answers with a GraphQL-shaped body — plus the negative: a wrong secret is rejected as 401
# UnauthorizedException. Data/resolver fidelity is open-appsync's OWN slice-1 probe, not this one.
# AppSync's data plane has no aws-CLI command, so this embeds a stdlib SigV4 signer (python3 +
# urllib — no external deps), which is exactly how an IAM-auth GraphQL client signs.
#
# On-demand — needs the shim AND the open-appsync engine (`components.openAppsync`). Exit 0 = pass,
# 1 = a real failure, 42 = INCONCLUSIVE (engine not deployed). Mirrors probe/aws-shim-s3.sh.
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
  MK_AK="$ak"; MK_SK="$sk"  # returned via globals: mint_key must run in THIS shell so CREATED_* reach cleanup
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
mint_key "appsync-probe" "powerusers"; AK="$MK_AK"; SK="$MK_SK"
[ -n "$AK" ] && [ -n "$SK" ] || inconclusive "failed to mint a key"
sleep 2

# This probe validates the FRONT DOOR: a signed GraphQL request is authenticated + passes the
# coarse IAM gate + reaches the open-appsync engine, which answers with a GraphQL-shaped body. It
# deliberately does NOT assert resolver/data fidelity — that is open-appsync's own slice-1 probe
# (VTL over a data source, run against real AppSync). Against the placeholder engine the body is an
# honest {errors:[NotImplemented]}; a real slice-1 engine returns {data}. Either is a valid GraphQL
# response and proves the shim path.
log "signed GraphQL request through the shim → open-appsync engine"
OUT="$(AK="$AK" SK="$SK" EP="$ENDPOINT" HOST="$HOSTHDR" BODY='{"query":"{ __typename }"}' python3 "$WORK/sign.py")"
echo "$OUT" | grep -q '^STATUS 502' && inconclusive "shim returned 502 — the open-appsync engine (components.openAppsync) is not deployed"
echo "$OUT" | grep -q '^STATUS 200' || fail "GraphQL request did not return 200:\n$OUT"
echo "$OUT" | grep -Eq '"data"|"errors"' || fail "response was not a GraphQL-shaped document (no data/errors):\n$OUT"
log "  ✓ signed request reached the engine and got a GraphQL response: $(echo "$OUT" | tail -1)"

log "negative: a valid key ID with a WRONG secret must be rejected (401)"
NEG="$(AK="$AK" SK="wrong-secret" EP="$ENDPOINT" HOST="$HOSTHDR" python3 "$WORK/sign.py")"
echo "$NEG" | grep -q '^STATUS 401' || fail "wrong secret not rejected with 401:\n$NEG"
echo "$NEG" | grep -qi 'UnauthorizedException' || fail "401 body not the AppSync UnauthorizedException dialect:\n$NEG"
log "  ✓ rejected as 401 UnauthorizedException"

# Management reads over a kind: GraphQLApi (the first in the cluster, or PROBE_GRAPHQL_API=<ns>/<name>),
# with the real AWS CLI.
command -v aws >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required for the management reads"
apiq() { AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager appsync "$@"; }
GQL="${PROBE_GRAPHQL_API:-$(kubectl get graphqlapis.openinfra.dev -A -o jsonpath='{.items[0].metadata.namespace}/{.items[0].metadata.name}' 2>/dev/null || true)}"
[ -n "$GQL" ] && [ "$GQL" != "/" ] || inconclusive "no kind: GraphQLApi in the cluster to read back"
API_ID="${GQL%%/*}.${GQL#*/}"
log "management reads of ${API_ID}: get-graphql-api, list-graphql-apis, schema, data sources, functions"
[ "$(apiq get-graphql-api --api-id "$API_ID" --query graphqlApi.apiId --output text 2>"$WORK/ga")" = "$API_ID" ] \
  || fail "get-graphql-api did not answer the API: $(cat "$WORK/ga")"
apiq list-graphql-apis --query 'graphqlApis[].apiId' --output text >"$WORK/la" 2>&1 || fail "list-graphql-apis: $(cat "$WORK/la")"
tr '\t' '\n' <"$WORK/la" | grep -qx "$API_ID" || fail "list-graphql-apis did not list ${API_ID}: $(head -c 300 "$WORK/la")"
apiq get-schema-creation-status --api-id "$API_ID" --query status --output text >"$WORK/sc" 2>&1 \
  || fail "get-schema-creation-status: $(cat "$WORK/sc")"
grep -Eqx 'SUCCESS|PROCESSING|NOT_APPLICABLE|FAILED' "$WORK/sc" || fail "get-schema-creation-status answered: $(cat "$WORK/sc")"
if [ "$(cat "$WORK/sc")" != NOT_APPLICABLE ]; then
  apiq get-introspection-schema --api-id "$API_ID" --format SDL "$WORK/schema.graphql" >/dev/null 2>"$WORK/is" \
    || fail "get-introspection-schema: $(cat "$WORK/is")"
  grep -q 'type ' "$WORK/schema.graphql" || fail "get-introspection-schema answered no SDL: $(head -c 300 "$WORK/schema.graphql")"
fi
apiq list-data-sources --api-id "$API_ID" >"$WORK/ds" 2>&1 || fail "list-data-sources: $(cat "$WORK/ds")"
DS="$(apiq list-data-sources --api-id "$API_ID" --query 'dataSources[0].name' --output text 2>/dev/null || true)"
if [ -n "$DS" ] && [ "$DS" != None ]; then
  [ "$(apiq get-data-source --api-id "$API_ID" --name "$DS" --query dataSource.name --output text 2>/dev/null)" = "$DS" ] \
    || fail "get-data-source did not answer ${DS}"
fi
apiq list-functions --api-id "$API_ID" >"$WORK/fn" 2>&1 || fail "list-functions: $(cat "$WORK/fn")"
if apiq get-data-source --api-id "$API_ID" --name "probe-missing-$RANDOM" >/dev/null 2>"$WORK/nd"; then
  fail "get-data-source of a data source that does not exist succeeded"
fi
grep -q NotFoundException "$WORK/nd" || fail "missing data source: $(cat "$WORK/nd")"
log "  ✓ the API, its schema, data sources and functions read back; a missing data source is NotFound"

echo
echo "✓ PASS — aws-shim AppSync proxies a signed GraphQL query to the engine, rejects a bad signature, and reads its API back."
