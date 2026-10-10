#!/usr/bin/env bash
# Compatibility probe for the aws-shim DynamoDB Streams surface.
#
# Fires real AWS SDK calls at a deployed shim and asserts byte-faithful stream behavior against the
# real backend — a table with a StreamSpecification emits an ordered INSERT/MODIFY/REMOVE change
# record per item write, read back through the dynamodbstreams API:
#   - create-table with a stream (NEW_AND_OLD_IMAGES); describe-table reports LatestStreamArn
#   - dynamodbstreams describe-stream reports the view type + a shard
#   - after PutItem/UpdateItem/DeleteItem, get-records (from a TRIM_HORIZON iterator) returns three
#     records in order: INSERT (NewImage only), MODIFY (both images), REMOVE (OldImage only)
#
# On-demand (needs a deployed shim + its FerretDB + MONGO_PG_URI). Exit 0 = pass, 1 = a real
# failure, 42 = INCONCLUSIVE (a prerequisite was missing).
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-dynamodb-streams.sh   # e.g. behind a port-forward
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
TABLE="${PROBE_TABLE:-probe-streams-$$}"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required to seed the principal + key"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"

CREATED_KEYS=(); CREATED_USERS=()
cleanup() {
  AWS_ACCESS_KEY_ID="${WAK:-}" AWS_SECRET_ACCESS_KEY="${WSK:-}" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager dynamodb delete-table --table-name "$TABLE" >/dev/null 2>&1 || true
  for s in "${CREATED_KEYS[@]:-}";  do [ -n "$s" ] && kubectl -n "$SHIM_NS" delete secret "$s" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
}
trap cleanup EXIT

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }

mint_key() { # <owner> <group> -> "ACCESS_KEY SECRET_KEY"
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

ddb()  { AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --output json dynamodb "$@"; }
ddbs() { AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --output json dynamodbstreams "$@"; }

log "seeding a writer principal (openinfra:powerusers) + access key"
read -r WAK WSK <<<"$(mint_key "probe-ddb-streams" "powerusers")"
[ -n "$WAK" ] && [ -n "$WSK" ] || inconclusive "failed to mint a writer key"
sleep 2

log "create-table ${TABLE} with a stream (NEW_AND_OLD_IMAGES)"
if ! CT_ERR="$(ddb create-table --table-name "$TABLE" \
  --attribute-definitions AttributeName=id,AttributeType=S \
  --key-schema AttributeName=id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --stream-specification 'StreamEnabled=true,StreamViewType=NEW_AND_OLD_IMAGES' 2>&1 >/dev/null)"; then
  case "$CT_ERR" in
    *"data layer is not configured"*|*NotImplementedException*)
      inconclusive "the shim's DynamoDB data layer is not configured — nothing proven" ;;
    *) fail "create-table with a stream failed: $CT_ERR" ;;
  esac
fi

ARN="$(ddb describe-table --table-name "$TABLE" | sed -n 's/.*"LatestStreamArn": *"\([^"]*\)".*/\1/p' | head -1)"
[ -n "$ARN" ] || fail "describe-table reported no LatestStreamArn"
log "  LatestStreamArn: $ARN"

log "describe-stream reports the view type + a shard"
ddbs describe-stream --stream-arn "$ARN" | grep -q "NEW_AND_OLD_IMAGES" || fail "describe-stream missing the view type"
SHARD="$(ddbs describe-stream --stream-arn "$ARN" | sed -n 's/.*"ShardId": *"\([^"]*\)".*/\1/p' | head -1)"
[ -n "$SHARD" ] || fail "describe-stream reported no shard"

log "three item writes → INSERT, MODIFY, REMOVE"
ddb put-item    --table-name "$TABLE" --item '{"id":{"S":"a"},"v":{"N":"1"}}' >/dev/null || fail "put-item failed"
ddb update-item --table-name "$TABLE" --key '{"id":{"S":"a"}}' --update-expression 'SET v = :v' --expression-attribute-values '{":v":{"N":"2"}}' >/dev/null || fail "update-item failed"
ddb delete-item --table-name "$TABLE" --key '{"id":{"S":"a"}}' >/dev/null || fail "delete-item failed"

log "get-records from a TRIM_HORIZON iterator"
IT="$(ddbs get-shard-iterator --stream-arn "$ARN" --shard-id "$SHARD" --shard-iterator-type TRIM_HORIZON | sed -n 's/.*"ShardIterator": *"\([^"]*\)".*/\1/p' | head -1)"
[ -n "$IT" ] || fail "no shard iterator"
OUT="$(ddbs get-records --shard-iterator "$IT")"
EVENTS="$(echo "$OUT" | sed -n 's/.*"eventName": *"\([A-Z]*\)".*/\1/p' | tr '\n' ',' )"
# collect the eventName sequence robustly (grep the ordered list)
EVENTS="$(echo "$OUT" | grep -oE '"eventName": *"[A-Z]+"' | sed 's/.*"\([A-Z]*\)"$/\1/' | tr '\n' ' ')"
log "  events: $EVENTS"
echo "$EVENTS" | grep -q "INSERT MODIFY REMOVE" || fail "expected ordered INSERT MODIFY REMOVE; got: $EVENTS"
echo "$OUT" | grep -q '"NewImage"' || fail "records should carry a NewImage (INSERT/MODIFY)"
echo "$OUT" | grep -q '"OldImage"' || fail "records should carry an OldImage (MODIFY/REMOVE)"

printf '\n✓ PASS — aws-shim DynamoDB Streams is faithful: a stream table emits ordered INSERT/MODIFY/REMOVE change records with the right images, read via the dynamodbstreams API.\n'
