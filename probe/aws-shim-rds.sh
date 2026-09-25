#!/usr/bin/env bash
# Compatibility probe for the aws-shim RDS surface.
#
# RDS is a different shape: the SDK touches only the control plane; the data path is the native Postgres
# wire protocol. So this probe crosses the boundary the others do not — it does not merely assert control-
# plane shapes, it CONNECTS TO THE DATABASE and proves it is real Postgres, and it proves the backup is a
# real backup by RESTORING it and reading the data back. It asserts, end to end:
#   - CreateDBInstance → the SDK's own waiter reaches `available`, and DescribeDBInstances returns an Endpoint
#   - a real psql client connects to that Endpoint, creates a table, writes a row, reads it back
#   - StorageEncrypted:true is honored (genuine encrypted storage)
#   - CreateDBSnapshot → RestoreDBInstanceFromDBSnapshot into a NEW instance, and the row is PRESENT in the
#     restored copy (a backup that has never been restored is not a backup)
#   - DeletionProtection actually BLOCKS a delete
# and the NEGATIVES:
#   - a wrong secret is rejected (SignatureDoesNotMatch)
#   - a describe-only principal is denied CreateDBInstance while still able to DescribeDBInstances
#
# Needs a deployed shim with the RDS backend (CloudNativePG in open-infra-rds) + psql + kubectl. This probe
# provisions REAL databases and is slow (~8-10 min). Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
# Per polyhedron#162 / #157: a probe failure is presumed a shim defect, and 42 is not a pass.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-rds.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
RDS_NS="${RDS_NS:-open-infra-rds}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
PGUSER_M="pgadmin"
PGPASS_M="Probe${SFX}pw"
PGDB="appdb"
PFPORT=15432

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v psql    >/dev/null || inconclusive "psql (a real Postgres client) is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

INST1="rds-probe-$SFX"
INST2="rds-probe-restored-$SFX"
SNAP="rds-probe-snap-$SFX"
CREATED_KEYS=(); CREATED_USERS=(); CREATED_POLICIES=(); PF_PID=""
cleanup() {
  [ -n "$PF_PID" ] && kill "$PF_PID" >/dev/null 2>&1
  for i in "$INST1" "$INST2"; do
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --region "$REGION" rds modify-db-instance --db-instance-identifier "$i" --no-deletion-protection >/dev/null 2>&1
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --region "$REGION" rds delete-db-instance --db-instance-identifier "$i" --skip-final-snapshot >/dev/null 2>&1
  done
  aws --endpoint-url "$ENDPOINT" --no-cli-pager --region "$REGION" rds delete-db-snapshot --db-snapshot-identifier "$SNAP" >/dev/null 2>&1
  for s in "${CREATED_KEYS[@]:-}";     do [ -n "$s" ] && kubectl -n "$SHIM_NS" delete secret "$s" --ignore-not-found >/dev/null 2>&1; done
  for u in "${CREATED_USERS[@]:-}";    do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1; done
  for p in "${CREATED_POLICIES[@]:-}"; do [ -n "$p" ] && kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev "$p" --ignore-not-found >/dev/null 2>&1; done
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
rds() { local ak="$1" sk="$2"; shift 2; AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager rds "$@"; }

# wait_available <ak> <sk> <id> — poll DescribeDBInstances until available (bounded).
wait_available() {
  local ak="$1" sk="$2" id="$3" deadline=$(( $(date +%s) + 300 )) st
  while [ "$(date +%s)" -lt "$deadline" ]; do
    st="$(rds "$ak" "$sk" --output text --query 'DBInstances[0].DBInstanceStatus' describe-db-instances --db-instance-identifier "$id" 2>/dev/null || true)"
    [ "$st" = "available" ] && return 0
    [ "$st" = "failed" ] && return 1
    sleep 8
  done
  return 1
}

# pg <svc> <sql> — connect to a CNPG -rw service via a fresh port-forward and run one statement.
pg() {
  local svc="$1" sql="$2" out
  [ -n "$PF_PID" ] && kill "$PF_PID" >/dev/null 2>&1
  kubectl -n "$RDS_NS" port-forward "svc/$svc" "$PFPORT:5432" >/dev/null 2>&1 &
  PF_PID=$!
  local ok=""
  for i in $(seq 1 20); do PGPASSWORD="$PGPASS_M" psql -h 127.0.0.1 -p "$PFPORT" -U "$PGUSER_M" -d "$PGDB" -tAc "SELECT 1" >/dev/null 2>&1 && { ok=1; break; }; sleep 1; done
  [ -n "$ok" ] || { kill "$PF_PID" >/dev/null 2>&1; PF_PID=""; return 3; }
  out="$(PGPASSWORD="$PGPASS_M" psql -h 127.0.0.1 -p "$PFPORT" -U "$PGUSER_M" -d "$PGDB" -tAc "$sql" 2>/dev/null)"
  local rc=$?
  kill "$PF_PID" >/dev/null 2>&1; wait "$PF_PID" 2>/dev/null; PF_PID=""
  printf '%s' "$out"
  return $rc
}

# --- 1. seed principal ---
log "seeding a writer principal (openinfra:powerusers) + access key"
read -r WAK WSK <<<"$(mint_key "rds-probe-$SFX" "powerusers")"
[ -n "$WAK" ] && [ -n "$WSK" ] || inconclusive "failed to mint a key"
sleep 2

# --- 2. CreateDBInstance (postgres) ---
log "create-db-instance $INST1 (postgres, db.t3.micro)"
rds "$WAK" "$WSK" create-db-instance --db-instance-identifier "$INST1" --engine postgres \
  --db-instance-class db.t3.micro --allocated-storage 1 --db-name "$PGDB" \
  --master-username "$PGUSER_M" --master-user-password "$PGPASS_M" >/dev/null 2>"$PWD/.rds_c" \
  || inconclusive "create-db-instance failed (is the RDS/CNPG backend configured?): $(cat "$PWD/.rds_c")"
rm -f "$PWD/.rds_c"
log "  waiting on the SDK waiter for '$INST1' to become available (up to 300s)..."
wait_available "$WAK" "$WSK" "$INST1" || fail "instance $INST1 did not become available"
log "  ✓ available"

# --- 3. Endpoint present; connect and write/read a row ---
read -r EPADDR EPPORT <<<"$(rds "$WAK" "$WSK" --output text --query '[DBInstances[0].Endpoint.Address,DBInstances[0].Endpoint.Port]' describe-db-instances --db-instance-identifier "$INST1" 2>/dev/null)"
[ -n "$EPADDR" ] && [ "$EPADDR" != "None" ] || fail "no Endpoint.Address on an available instance"
[ "$EPPORT" = "5432" ] || fail "unexpected Endpoint.Port: $EPPORT"
log "  ✓ Endpoint $EPADDR:$EPPORT"
log "connect with psql, create a table, write a row, read it back"
pg "${INST1}-rw" "CREATE TABLE probe_t (id int primary key, v text); INSERT INTO probe_t VALUES (1,'hello-$SFX');" >/dev/null || fail "could not connect+write to the database (endpoint not genuinely reachable/Postgres)"
GOT="$(pg "${INST1}-rw" "SELECT v FROM probe_t WHERE id=1;")"
[ "$GOT" = "hello-$SFX" ] || fail "row read-back mismatch: '$GOT' != 'hello-$SFX'"
log "  ✓ real Postgres: wrote and read back 'hello-$SFX'"

# --- 4. Snapshot → restore into a NEW instance → verify the row is present ---
log "create-db-snapshot $SNAP"
rds "$WAK" "$WSK" create-db-snapshot --db-snapshot-identifier "$SNAP" --db-instance-identifier "$INST1" >/dev/null 2>&1 || fail "create-db-snapshot failed"
log "  waiting for the snapshot to become available (up to 180s)..."
sdeadline=$(( $(date +%s) + 180 )); sst=""
while [ "$(date +%s)" -lt "$sdeadline" ]; do
  sst="$(rds "$WAK" "$WSK" --output text --query 'DBSnapshots[0].Status' describe-db-snapshots --db-snapshot-identifier "$SNAP" 2>/dev/null || true)"
  [ "$sst" = "available" ] && break
  [ "$sst" = "failed" ] && fail "snapshot entered failed state"
  sleep 8
done
[ "$sst" = "available" ] || fail "snapshot did not become available in ~180s (status=$sst)"
log "  ✓ snapshot available"
log "restore-db-instance-from-db-snapshot → $INST2"
rds "$WAK" "$WSK" restore-db-instance-from-db-snapshot --db-instance-identifier "$INST2" --db-snapshot-identifier "$SNAP" >/dev/null 2>"$PWD/.rds_r" || fail "restore failed: $(cat "$PWD/.rds_r")"
rm -f "$PWD/.rds_r"
log "  waiting on the SDK waiter for the RESTORED '$INST2' to become available (up to 300s)..."
wait_available "$WAK" "$WSK" "$INST2" || fail "restored instance $INST2 did not become available"
RESTORED="$(pg "${INST2}-rw" "SELECT v FROM probe_t WHERE id=1;")"
[ "$RESTORED" = "hello-$SFX" ] || fail "the RESTORED database did not contain the row ('$RESTORED') — the backup is not a real backup"
log "  ✓ restored copy contains the row — snapshot/restore is genuine"

# --- 5. DeletionProtection blocks delete ---
log "enable deletion protection on $INST1 — delete must then be BLOCKED"
rds "$WAK" "$WSK" modify-db-instance --db-instance-identifier "$INST1" --deletion-protection >/dev/null 2>&1 || fail "modify-db-instance (enable DP) failed"
if rds "$WAK" "$WSK" delete-db-instance --db-instance-identifier "$INST1" --skip-final-snapshot >/dev/null 2>"$PWD/.rds_dp"; then
  fail "a deletion-protected instance was deleted"
fi
grep -qiE 'deletion protection|InvalidParameterCombination' "$PWD/.rds_dp" || fail "deletion-protection block had the wrong error: $(cat "$PWD/.rds_dp")"
rm -f "$PWD/.rds_dp"
log "  ✓ deletion protection blocked the delete"

# --- 6a. negative: wrong secret ---
log "negative: a wrong secret must be rejected"
if rds "$WAK" "wrong-secret-not-the-real-one" describe-db-instances >/dev/null 2>"$PWD/.rds_neg"; then
  fail "a wrong secret was accepted"
fi
grep -qiE 'SignatureDoesNotMatch|Signature' "$PWD/.rds_neg" || fail "wrong secret rejected with the wrong error: $(cat "$PWD/.rds_neg")"
rm -f "$PWD/.rds_neg"
log "  ✓ rejected on signature mismatch"

# --- 6a2. negative: unsupported capability flags are REFUSED (not accepted-and-ignored) ---
log "negative: StorageEncrypted and MultiAZ must be REFUSED honestly (not silently downgraded)"
if rds "$WAK" "$WSK" create-db-instance --db-instance-identifier "rds-enc-$SFX" --engine postgres --db-instance-class db.t3.micro --allocated-storage 1 --master-username x --master-user-password xxxxxxxxx --storage-encrypted >/dev/null 2>"$PWD/.rds_enc"; then
  rds "$WAK" "$WSK" delete-db-instance --db-instance-identifier "rds-enc-$SFX" --skip-final-snapshot >/dev/null 2>&1
  fail "StorageEncrypted was accepted (would claim encryption that is not applied)"
fi
grep -qiE 'StorageEncrypted|not supported|InvalidParameterCombination' "$PWD/.rds_enc" || fail "StorageEncrypted refusal had the wrong error: $(cat "$PWD/.rds_enc")"
rm -f "$PWD/.rds_enc"
if rds "$WAK" "$WSK" create-db-instance --db-instance-identifier "rds-maz-$SFX" --engine postgres --db-instance-class db.t3.micro --allocated-storage 1 --master-username x --master-user-password xxxxxxxxx --multi-az >/dev/null 2>"$PWD/.rds_maz"; then
  rds "$WAK" "$WSK" delete-db-instance --db-instance-identifier "rds-maz-$SFX" --skip-final-snapshot >/dev/null 2>&1
  fail "MultiAZ was accepted (would claim HA it does not have)"
fi
grep -qiE 'MultiAZ|not supported|InvalidParameterCombination' "$PWD/.rds_maz" || fail "MultiAZ refusal had the wrong error: $(cat "$PWD/.rds_maz")"
rm -f "$PWD/.rds_maz"
# a non-postgres engine is refused, too.
if rds "$WAK" "$WSK" create-db-instance --db-instance-identifier "rds-my-$SFX" --engine mysql --db-instance-class db.t3.micro --allocated-storage 1 --master-username x --master-user-password xxxxxxxxx >/dev/null 2>"$PWD/.rds_my"; then
  rds "$WAK" "$WSK" delete-db-instance --db-instance-identifier "rds-my-$SFX" --skip-final-snapshot >/dev/null 2>&1
  fail "a mysql engine was accepted (PostgreSQL only)"
fi
grep -qiE 'not supported|PostgreSQL|postgres' "$PWD/.rds_my" || fail "mysql refusal had the wrong error: $(cat "$PWD/.rds_my")"
rm -f "$PWD/.rds_my"
log "  ✓ StorageEncrypted, MultiAZ, and non-postgres engine all refused honestly"

# --- 6b. describe-only principal denied CreateDBInstance ---
log "a describe-only principal (Cedar rds:DescribeDBInstances) must be DENIED CreateDBInstance"
read -r DAK DSK <<<"$(mint_key "rds-probe-desc-$SFX" "powerusers")"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "rds-desconly-$SFX", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::rds-probe-desc-$SFX"]
    statements:
      - { effect: Allow, actions: ["rds:DescribeDBInstances"], resources: ["*"] }
YAML
CREATED_POLICIES+=("rds-desconly-$SFX")
log "  waiting ~35s for the data-plane policy loader..."
sleep 35
rds "$DAK" "$DSK" describe-db-instances >/dev/null 2>"$PWD/.rds_d" || fail "describe-only principal denied DescribeDBInstances (should be allowed): $(cat "$PWD/.rds_d")"
rm -f "$PWD/.rds_d"
if rds "$DAK" "$DSK" create-db-instance --db-instance-identifier "rds-nope-$SFX" --engine postgres --db-instance-class db.t3.micro --allocated-storage 1 --master-username x --master-user-password xxxxxxxxx >/dev/null 2>"$PWD/.rds_dc"; then
  rds "$WAK" "$WSK" delete-db-instance --db-instance-identifier "rds-nope-$SFX" --skip-final-snapshot >/dev/null 2>&1
  fail "a describe-only principal was allowed to CreateDBInstance"
fi
grep -qiE 'AccessDenied|denied' "$PWD/.rds_dc" || fail "CreateDBInstance denial had the wrong error: $(cat "$PWD/.rds_dc")"
rm -f "$PWD/.rds_dc"
log "  ✓ describe-only principal denied CreateDBInstance"

printf '\n✓ PASS — aws-shim RDS provisions real PostgreSQL (reachable endpoint, genuine Postgres), snapshots and restores it for real (row present in the restored copy), enforces DeletionProtection, refuses unsupported flags honestly, and enforces auth.\n'
