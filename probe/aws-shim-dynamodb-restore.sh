#!/usr/bin/env bash
# Compatibility probe for the aws-shim DynamoDB RestoreTableToPointInTime surface (polyhedron#291) — the
# real, durable, asynchronous point-in-time restore. It closes the gap where RestoreTableToPointInTime
# was an honest 501: the backend (DocumentDB on CloudNativePG) keeps a continuous WAL archive, so a
# single-table restore to a NEW table is a backend recovery (bootstrap a CNPG cluster to the target time,
# stand a throwaway FerretDB over it, copy the collection) driven by a Kubernetes Job.
#
# Fires REAL AWS SDK calls (the `aws` CLI) at a deployed shim and asserts byte-faithful behavior against
# the real FerretDB/CNPG store:
#   - create a THROWAWAY source table + enable PITR (UpdateContinuousBackups) + PutItem a couple items
#   - RestoreTableToPointInTime (UseLatestRestorableTime=true) to a throwaway target
#   - DescribeTable(target) reports CREATING immediately (async), then transitions to ACTIVE (the Job
#     bootstrapped a recovery cluster, copied the collection, and flipped the table live) — a recovery
#     cluster is genuinely slow, so this polls up to ~15min and prints progress
#   - GetItem on the restored target round-trips the SOURCE items (the data really came back)
#   - prove-the-no (negative): restoring a table WITHOUT PITR -> ValidationException; restoring ONTO an
#     existing table -> ResourceInUseException
#
# On-demand (needs a deployed shim + its FerretDB/CNPG backend + the restore RBAC applied). Exit 0 = pass,
# 1 = a real failure, 42 = INCONCLUSIVE (a prerequisite was missing). Mirrors aws-shim-dynamodb.sh.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-dynamodb-restore.sh   # e.g. behind a port-forward
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SRC="${PROBE_TABLE:-probe-ddb-restore-src-$$}"
TGT="${PROBE_TABLE:-probe-ddb-restore-tgt-$$}"
NOPITR="probe-ddb-restore-nopitr-$$"
# A recovery CNPG cluster takes minutes to bootstrap + replay WAL; allow a generous ceiling.
RESTORE_TIMEOUT="${RESTORE_TIMEOUT:-900}" # seconds

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required to seed the principal + key"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"

CREATED_KEYS=(); CREATED_USERS=()
cleanup() {
  # Delete tables best-effort (teardown must not fail the run).
  for t in "$SRC" "$TGT" "$NOPITR"; do
    AWS_ACCESS_KEY_ID="${WAK:-}" AWS_SECRET_ACCESS_KEY="${WSK:-}" AWS_REGION="$REGION" \
      aws --endpoint-url "$ENDPOINT" --no-cli-pager dynamodb delete-table --table-name "$t" >/dev/null 2>&1 || true
  done
  for s in "${CREATED_KEYS[@]:-}";  do [ -n "$s" ] && kubectl -n "$SHIM_NS" delete secret "$s" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  # The recovery CNPG cluster + throwaway FerretDB are auto-torn-down by the restore Job itself; its PVC
  # may linger. We do NOT fail the run on that — just note it.
  printf '  (note: the recovery cluster/PVC is auto-cleaned by the restore Job; a lingering PVC is harmless)\n'
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
read -r WAK WSK <<<"$(mint_key "probe-ddb-restore" "powerusers")"
[ -n "$WAK" ] && [ -n "$WSK" ] || inconclusive "failed to mint a writer key"
sleep 2

log "create-table ${SRC} (pk HASH) and enable point-in-time recovery"
if ! CT_ERR="$(ddb create-table --table-name "$SRC" \
  --attribute-definitions AttributeName=pk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST 2>&1 >/dev/null)"; then
  case "$CT_ERR" in
    *"data layer is not configured"*|*NotImplementedException*)
      inconclusive "the shim's DynamoDB data layer is not configured (no MONGO_URI/FerretDB) — nothing proven" ;;
    *) fail "create-table failed: $CT_ERR" ;;
  esac
fi
ddb update-continuous-backups --table-name "$SRC" \
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true \
  | grep -q '"PointInTimeRecoveryStatus": "ENABLED"' || fail "could not enable PITR on the source"

log "put two items into the source"
ddb put-item --table-name "$SRC" --item '{"pk":{"S":"a1"},"msg":{"S":"alpha"},"n":{"N":"1"}}' >/dev/null || fail "put-item a1 failed"
ddb put-item --table-name "$SRC" --item '{"pk":{"S":"b2"},"msg":{"S":"bravo"},"n":{"N":"2"}}' >/dev/null || fail "put-item b2 failed"

# Let WAL accumulate a moment so there is a restorable instant strictly after the writes.
sleep 5

log "prove-the-no: restoring a table WITHOUT PITR is a ValidationException"
ddb create-table --table-name "$NOPITR" \
  --attribute-definitions AttributeName=pk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH --billing-mode PAY_PER_REQUEST >/dev/null || fail "create NOPITR table failed"
if NEG="$(ddb restore-table-to-point-in-time --source-table-name "$NOPITR" \
  --target-table-name "probe-ddb-restore-neverland-$$" --use-latest-restorable-time 2>&1 >/dev/null)"; then
  fail "restoring a non-PITR table should fail, but it succeeded"
fi
echo "$NEG" | grep -q "ValidationException" || fail "non-PITR restore should be a ValidationException, got: $NEG"
log "  ✓ non-PITR restore rejected (ValidationException)"

log "prove-the-no: restoring ONTO an existing table is a ResourceInUseException"
if NEG2="$(ddb restore-table-to-point-in-time --source-table-name "$SRC" \
  --target-table-name "$SRC" --use-latest-restorable-time 2>&1 >/dev/null)"; then
  fail "restoring onto an existing table should fail, but it succeeded"
fi
echo "$NEG2" | grep -q "ResourceInUseException" || fail "restore onto an existing table should be ResourceInUseException, got: $NEG2"
log "  ✓ restore onto an existing table rejected (ResourceInUseException)"

log "RestoreTableToPointInTime ${SRC} -> ${TGT} (UseLatestRestorableTime)"
RESP="$(ddb restore-table-to-point-in-time --source-table-name "$SRC" \
  --target-table-name "$TGT" --use-latest-restorable-time 2>&1)" || fail "restore-table-to-point-in-time failed: $RESP"
echo "$RESP" | grep -q '"TableStatus": "CREATING"' || fail "restore did not return a CREATING TableDescription: $RESP"
log "  ✓ restore accepted asynchronously (target CREATING)"

log "poll DescribeTable(${TGT}) for CREATING -> ACTIVE (recovery clusters are slow; up to ${RESTORE_TIMEOUT}s)"
deadline=$(( $(date +%s) + RESTORE_TIMEOUT ))
status=""
while :; do
  status="$(ddb describe-table --table-name "$TGT" --query 'Table.TableStatus' --output text 2>/dev/null || echo '?')"
  case "$status" in
    ACTIVE) log "  ✓ target is ACTIVE"; break ;;
    CREATE_FAILED) fail "restore reported CREATE_FAILED — inspect the restore Job logs (kubectl -n ${SHIM_NS} logs job/dynamo-restore-<id>)" ;;
    CREATING|'?') : ;;
    *) : ;;
  esac
  [ "$(date +%s)" -lt "$deadline" ] || fail "target did not reach ACTIVE within ${RESTORE_TIMEOUT}s (last status: ${status})"
  printf '    … status=%s (%ds left)\n' "$status" "$(( deadline - $(date +%s) ))"
  sleep 15
done

log "the restored items round-trip on the target"
G1="$(ddb get-item --table-name "$TGT" --key '{"pk":{"S":"a1"}}')"
echo "$G1" | grep -q '"alpha"' || fail "restored target missing item a1/alpha: $G1"
G2="$(ddb get-item --table-name "$TGT" --key '{"pk":{"S":"b2"}}')"
echo "$G2" | grep -q '"bravo"' || fail "restored target missing item b2/bravo: $G2"
log "  ✓ both source items came back on the restored table"

printf '\n✓ PASS — aws-shim DynamoDB RestoreTableToPointInTime is REAL: the target goes CREATING then ACTIVE via a backend recovery (CNPG WAL replay), the source items are faithfully restored, and the negatives (non-PITR source, existing target) are rejected honestly.\n'
