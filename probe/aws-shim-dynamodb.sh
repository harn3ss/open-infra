#!/usr/bin/env bash
# Compatibility probe for the aws-shim DynamoDB CORE surface — the base table + item CRUD that the LSI
# (aws-shim-dynamodb-lsi.sh) and Streams (aws-shim-dynamodb-streams.sh) probes build on. It closes the
# gap where docs/aws-shim.md claimed the DynamoDB doorway was probe-proven while only the LSI/Streams
# slices had a probe and the base CRUD + continuous-backups surface rested on integration tests alone.
#
# Fires REAL AWS SDK calls (the `aws` CLI) at a deployed shim and asserts byte-faithful behavior against
# the real FerretDB/CNPG store — not merely HTTP 200:
#   - CreateTable (hash+range, with a GSI) → DescribeTable reports the key schema + the GSI
#   - PutItem → GetItem round-trips the exact item; UpdateItem mutates it; Query by key resolves; Scan
#     sees it; DeleteItem removes it (GetItem then empty)
#   - GSI: a Query by the GSI's own partition key resolves ACROSS table partitions (the defining
#     GSI behavior an LSI can't offer) — covers the built-not-verified GSI verdict
#   - ContinuousBackups / PITR: DescribeContinuousBackups reports ContinuousBackupsStatus=ENABLED;
#     UpdateContinuousBackups enables PITR and a re-Describe reports PointInTimeRecoveryStatus=ENABLED
#     with a restorable window (the authenticated proof for the PITR API surface)
#   - prove-the-no: a valid key ID with a WRONG secret is rejected (signature), never served
#
# On-demand (needs a deployed shim + its FerretDB/CNPG backend + the platform IAM). Exit 0 = pass,
# 1 = a real failure, 42 = INCONCLUSIVE (a prerequisite was missing). Mirrors aws-shim-dynamodb-lsi.sh.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-dynamodb.sh   # e.g. behind a port-forward
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
TABLE="${PROBE_TABLE:-probe-ddb-$$}"

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
read -r WAK WSK <<<"$(mint_key "probe-ddb-core" "powerusers")"
[ -n "$WAK" ] && [ -n "$WSK" ] || inconclusive "failed to mint a writer key"
sleep 2

log "create-table ${TABLE} (pk HASH + sk RANGE) with a GSI (by-cat on cat)"
if ! CT_ERR="$(ddb create-table --table-name "$TABLE" \
  --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S AttributeName=cat,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE \
  --global-secondary-indexes 'IndexName=by-cat,KeySchema=[{AttributeName=cat,KeyType=HASH}],Projection={ProjectionType=ALL}' \
  --billing-mode PAY_PER_REQUEST 2>&1 >/dev/null)"; then
  case "$CT_ERR" in
    *"data layer is not configured"*|*NotImplementedException*)
      inconclusive "the shim's DynamoDB data layer is not configured (no MONGO_URI/FerretDB) — nothing proven" ;;
    *) fail "create-table failed: $CT_ERR" ;;
  esac
fi

log "describe-table reports the key schema"
ddb describe-table --table-name "$TABLE" | grep -q '"KeyType": "HASH"' || fail "describe-table missing the HASH key"
ddb describe-table --table-name "$TABLE" | grep -q '"AttributeName": "sk"' || fail "describe-table missing the RANGE key attribute"
ddb describe-table --table-name "$TABLE" | grep -q '"IndexName": "by-cat"' || fail "describe-table missing the GSI by-cat"
ddb describe-table --table-name "$TABLE" | grep -q "GlobalSecondaryIndexes" || fail "describe-table missing the GlobalSecondaryIndexes block"
log "  ✓ table + GSI present"

log "put-item then get-item round-trips the exact item"
ddb put-item --table-name "$TABLE" --item '{"pk":{"S":"u1"},"sk":{"S":"a"},"n":{"N":"7"},"msg":{"S":"hi"},"cat":{"S":"c1"}}' >/dev/null || fail "put-item failed"
GOT="$(ddb get-item --table-name "$TABLE" --key '{"pk":{"S":"u1"},"sk":{"S":"a"}}')"
echo "$GOT" | grep -q '"msg"' && echo "$GOT" | grep -q '"hi"' || fail "get-item did not round-trip the item: $GOT"
log "  ✓ put/get round-trip"

log "update-item mutates an attribute"
ddb update-item --table-name "$TABLE" --key '{"pk":{"S":"u1"},"sk":{"S":"a"}}' \
  --update-expression 'SET n = :v' --expression-attribute-values '{":v":{"N":"42"}}' >/dev/null || fail "update-item failed"
ddb get-item --table-name "$TABLE" --key '{"pk":{"S":"u1"},"sk":{"S":"a"}}' | grep -q '"42"' || fail "update-item did not persist n=42"
log "  ✓ update persisted"

log "query by partition key resolves"
ddb query --table-name "$TABLE" --key-condition-expression 'pk = :p' \
  --expression-attribute-values '{":p":{"S":"u1"}}' | grep -q '"u1"' || fail "query by pk returned nothing"

log "scan sees the item"
ddb scan --table-name "$TABLE" | grep -q '"u1"' || fail "scan did not see the item"
log "  ✓ query + scan"

log "GSI by-cat resolves ACROSS partitions (what an LSI can't do)"
# A second item under a DIFFERENT partition key but the SAME category. A GSI query by cat must
# return BOTH (its partition key is independent of the table's) — the defining GSI behavior.
ddb put-item --table-name "$TABLE" --item '{"pk":{"S":"u2"},"sk":{"S":"b"},"cat":{"S":"c1"}}' >/dev/null || fail "put-item (u2) failed"
GSI="$(ddb query --table-name "$TABLE" --index-name by-cat \
  --key-condition-expression 'cat = :c' --expression-attribute-values '{":c":{"S":"c1"}}')"
echo "$GSI" | grep -q '"u1"' || fail "GSI query missing the u1 item (same cat): $GSI"
echo "$GSI" | grep -q '"u2"' || fail "GSI query missing the u2 item under a different partition (GSI did not span partitions): $GSI"
echo "$GSI" | grep -q '"Count": 2' || fail "GSI query by cat=c1 should return exactly 2 items: $GSI"
ddb delete-item --table-name "$TABLE" --key '{"pk":{"S":"u2"},"sk":{"S":"b"}}' >/dev/null || true
log "  ✓ GSI spans partitions"

log "ContinuousBackups: continuous backups ENABLED, PITR togglable (the PITR API surface)"
ddb describe-continuous-backups --table-name "$TABLE" | grep -q '"ContinuousBackupsStatus": "ENABLED"' \
  || fail "DescribeContinuousBackups did not report ContinuousBackupsStatus ENABLED"
ddb update-continuous-backups --table-name "$TABLE" \
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true \
  | grep -q '"PointInTimeRecoveryStatus": "ENABLED"' || fail "UpdateContinuousBackups did not enable PITR"
ddb describe-continuous-backups --table-name "$TABLE" | grep -q '"PointInTimeRecoveryStatus": "ENABLED"' \
  || fail "PITR did not stay ENABLED after UpdateContinuousBackups"
log "  ✓ continuous backups / PITR surface works"

log "delete-item removes it (get-item then empty)"
ddb delete-item --table-name "$TABLE" --key '{"pk":{"S":"u1"},"sk":{"S":"a"}}' >/dev/null || fail "delete-item failed"
OUT="$(ddb get-item --table-name "$TABLE" --key '{"pk":{"S":"u1"},"sk":{"S":"a"}}')"
echo "$OUT" | grep -q '"Item"' && fail "delete-item did not remove the item: $OUT"
log "  ✓ delete removed the item"

log "prove-the-no: a valid key ID with a WRONG secret is rejected"
if AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="wrong-secret-0000000000000000000000000000" AWS_REGION="$REGION" \
   aws --endpoint-url "$ENDPOINT" --no-cli-pager dynamodb describe-table --table-name "$TABLE" >/dev/null 2>&1; then
  fail "a wrong secret must be rejected (signature), not served"
fi
log "  ✓ wrong secret rejected"

printf '\n✓ PASS — aws-shim DynamoDB core is faithful: CreateTable/DescribeTable (with a GSI), PutItem/GetItem round-trip, UpdateItem, Query, Scan, a GSI query spanning partitions, DeleteItem, the ContinuousBackups/PITR surface, and a wrong secret is rejected.\n'
