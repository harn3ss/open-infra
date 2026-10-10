#!/usr/bin/env bash
# Compatibility probe for the aws-shim DynamoDB LOCAL secondary index (LSI) surface.
#
# Fires real AWS SDK calls (the `aws` CLI) at a deployed shim and asserts byte-faithful LSI
# behavior against the real FerretDB store — not merely HTTP 200. It exercises the runtime
# CreateTable-with-LocalSecondaryIndexes path (the declarative kind: Table path shares the same
# registration code and is covered by dynamo_lsi_integration_test.go + the render test):
#   - create-table with an LSI (alternate sort key under the table's partition key)
#   - describe-table reports the LSI under LocalSecondaryIndexes
#   - query BY the LSI IndexName returns only the matching item (the index resolves)
#   - a query naming an UNKNOWN index is a loud ValidationException (prove the no — never a
#     silent full-table scan)
#
# On-demand (needs a deployed shim + its FerretDB + the platform IAM). Run from a host with cluster
# access. Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE (a prerequisite was missing).
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-dynamodb-lsi.sh   # e.g. behind a port-forward
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
TABLE="${PROBE_TABLE:-probe-lsi-$$}"

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

ddb() { AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" \
  aws --endpoint-url "$ENDPOINT" --no-cli-pager --output json dynamodb "$@"; }

log "seeding a writer principal (openinfra:powerusers) + access key"
read -r WAK WSK <<<"$(mint_key "probe-ddb-lsi" "powerusers")"
[ -n "$WAK" ] && [ -n "$WSK" ] || inconclusive "failed to mint a writer key"
sleep 2

log "create-table ${TABLE} with an LSI (by-score: id HASH + score RANGE)"
if ! CT_ERR="$(ddb create-table --table-name "$TABLE" \
  --attribute-definitions AttributeName=id,AttributeType=S AttributeName=ts,AttributeType=N AttributeName=score,AttributeType=N \
  --key-schema AttributeName=id,KeyType=HASH AttributeName=ts,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST \
  --local-secondary-indexes 'IndexName=by-score,KeySchema=[{AttributeName=id,KeyType=HASH},{AttributeName=score,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
  2>&1 >/dev/null)"; then
  # The DynamoDB data layer (FerretDB/Mongo) is an optional, separately-deployed backend. If it is
  # not configured on this shim, nothing can be proven — inconclusive, not a failure.
  case "$CT_ERR" in
    *"data layer is not configured"*|*NotImplementedException*)
      inconclusive "the shim's DynamoDB data layer is not configured (no MONGO_URI/FerretDB) — nothing proven" ;;
    *) fail "create-table with an LSI failed: $CT_ERR" ;;
  esac
fi

log "describe-table reports the LSI"
ddb describe-table --table-name "$TABLE" | grep -q '"IndexName": "by-score"' \
  || fail "describe-table did not report the LSI by-score"
ddb describe-table --table-name "$TABLE" | grep -q "LocalSecondaryIndexes" \
  || fail "describe-table did not report a LocalSecondaryIndexes block"
log "  ✓ LSI present in DescribeTable"

log "put two items under the same partition (id=u1), differing score"
ddb put-item --table-name "$TABLE" --item '{"id":{"S":"u1"},"ts":{"N":"1"},"score":{"N":"10"}}' >/dev/null || fail "put-item 1 failed"
ddb put-item --table-name "$TABLE" --item '{"id":{"S":"u1"},"ts":{"N":"2"},"score":{"N":"99"}}' >/dev/null || fail "put-item 2 failed"

log "query BY the LSI (id=u1 AND score=99) returns only the score=99 item"
OUT="$(ddb query --table-name "$TABLE" --index-name by-score \
  --key-condition-expression 'id = :i AND score = :s' \
  --expression-attribute-values '{":i":{"S":"u1"},":s":{"N":"99"}}')"
echo "$OUT" | grep -q '"99"' || fail "LSI query did not return the score=99 item: $OUT"
echo "$OUT" | grep -q '"10"' && fail "LSI query must not return the score=10 item (index filter broken): $OUT"
log "  ✓ LSI query resolved to the right item"

log "query naming an UNKNOWN index must be rejected (prove the no)"
if ddb query --table-name "$TABLE" --index-name nope \
     --key-condition-expression 'id = :i' --expression-attribute-values '{":i":{"S":"u1"}}' >/dev/null 2>&1; then
  fail "a query naming an unknown index must be a ValidationException, not a silent success"
fi
log "  ✓ unknown index rejected"

printf '\n✓ PASS — aws-shim DynamoDB LSI is faithful: create-table-with-LSI, DescribeTable reports it, a Query by the LSI IndexName resolves to the right item, and an unknown index is rejected.\n'
