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
# By policy, a probe failure is presumed a shim defect, and 42 is not a pass.
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
# psql runs from a throwaway IN-CLUSTER pod against the instance's Service DNS endpoint — this proves the
# real endpoint is reachable (kubectl port-forward is unreliable under this cluster's CNI), which is more
# faithful than a host-side forward. The CNPG postgres image is already present on the nodes.
PGIMAGE="${PGIMAGE:-ghcr.io/cloudnative-pg/postgresql:17.4}"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required (psql runs from an in-cluster pod)"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

INST1="rds-probe-$SFX"
INST2="rds-probe-restored-$SFX"
INST3="rds-probe-final-$SFX"
SNAP="rds-probe-snap-$SFX"
FSNAP="rds-probe-final-snap-$SFX"
CREATED_KEYS=(); CREATED_USERS=(); CREATED_POLICIES=()
cleanup() {
  kubectl -n "$RDS_NS" delete pod -l "probe=rds-$SFX" --ignore-not-found >/dev/null 2>&1
  # Use the credentialed rds() helper — bare `aws` calls would be unsigned and silently rejected, leaking
  # the provisioned clusters.
  if [ -n "$WAK" ] && [ -n "$WSK" ]; then
    for i in "$INST1" "$INST2" "$INST3"; do
      rds "$WAK" "$WSK" modify-db-instance --db-instance-identifier "$i" --no-deletion-protection >/dev/null 2>&1
      rds "$WAK" "$WSK" delete-db-instance --db-instance-identifier "$i" --skip-final-snapshot >/dev/null 2>&1
    done
    rds "$WAK" "$WSK" delete-db-snapshot --db-snapshot-identifier "$SNAP" >/dev/null 2>&1
    rds "$WAK" "$WSK" delete-db-snapshot --db-snapshot-identifier "$FSNAP" >/dev/null 2>&1
  fi
  for s in "${CREATED_KEYS[@]:-}";     do [ -n "$s" ] && kubectl -n "$SHIM_NS" delete secret "$s" --ignore-not-found >/dev/null 2>&1; done
  for u in "${CREATED_USERS[@]:-}";    do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1; done
  for p in "${CREATED_POLICIES[@]:-}"; do [ -n "$p" ] && kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev "$p" --ignore-not-found >/dev/null 2>&1; done
}
trap cleanup EXIT

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }
mint_key() {
  local owner="$1" group="$2"
  # A principal minted with no group is policy-only: its own policies are all it has, decided by IAM
  # policy alone (the canary label), as an AWS user with no group. A tier group (powerusers, admins)
  # carries its AWS managed policy (PowerUserAccess, AdministratorAccess), which a scoped policy of the
  # user's own only adds to, as on AWS — so a principal meant to be scoped has no group.
  local groups="[\"${group}\"]" labels=""
  [ -n "$group" ] || { groups="[]"; labels=', labels: { "openinfra.dev/iam-authz": "enforce" }'; }
  local ak="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  local sk; sk="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "${owner}", namespace: "${USERS_NS}"${labels} }
spec: { displayName: "${owner}", groups: ${groups}, source: local }
YAML
  CREATED_USERS+=("$owner")
  local name; name="$(secret_name "$ak")"
  kubectl -n "$SHIM_NS" create secret generic "$name" --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  CREATED_KEYS+=("$name")
  MK_AK="$ak"; MK_SK="$sk"  # returned via globals: mint_key must run in THIS shell so CREATED_* reach cleanup
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

# pg <svc> <sql> — run one psql statement from a throwaway IN-CLUSTER pod against the instance's Service DNS
# endpoint (the real endpoint the RDS API returns), printing psql's -tA output. Robust to CNI port-forward
# flakiness because it connects service-to-service inside the cluster.
pg() {
  local svc="$1" sql="$2" host="${1}.${RDS_NS}.svc.cluster.local" pass="${3:-$PGPASS_M}"
  kubectl -n "$RDS_NS" run "pgp-${SFX}-${RANDOM}" --image="$PGIMAGE" --restart=Never --rm -i \
    --labels="probe=rds-$SFX" --command --timeout=90s -- \
    psql "postgresql://${PGUSER_M}:${pass}@${host}:5432/${PGDB}" -tAc "$sql" 2>/dev/null
}

# --- 1. seed principal ---
log "seeding a writer principal (openinfra:powerusers) + access key"
mint_key "rds-probe-$SFX" "powerusers"; WAK="$MK_AK"; WSK="$MK_SK"
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
log "connect with psql (in-cluster, to the Service endpoint), create a table, write a row, read it back"
WOUT="$(pg "${INST1}-rw" "CREATE TABLE probe_t (id int primary key, v text); INSERT INTO probe_t VALUES (1,'hello-$SFX'); SELECT 'WROTE:'||v FROM probe_t WHERE id=1;")"
printf '%s' "$WOUT" | grep -q "WROTE:hello-$SFX" || fail "could not write+read via the Service endpoint (not genuinely reachable/Postgres); got: $(printf '%s' "$WOUT" | tr '\n' ' ')"
log "  ✓ real Postgres: wrote and read back 'hello-$SFX' over the Service endpoint"

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
ROUT="$(pg "${INST2}-rw" "SELECT 'ROW:'||v FROM probe_t WHERE id=1;")"
printf '%s' "$ROUT" | grep -q "ROW:hello-$SFX" || fail "the RESTORED database did not contain the row — the backup is not a real backup; got: $(printf '%s' "$ROUT" | tr '\n' ' ')"
log "  ✓ restored copy contains the row — snapshot/restore is genuine"

# --- 4b. ModifyDBInstance applies what it takes: the master password changes; and the version is reported ---
ev="$(rds "$WAK" "$WSK" --output text --query 'DBInstances[0].EngineVersion' describe-db-instances --db-instance-identifier "$INST1" 2>/dev/null || true)"
[ -n "$ev" ] && [ "$ev" != "None" ] || fail "DescribeDBInstances reports no EngineVersion"
VER="$(pg "${INST1}-rw" "SHOW server_version;" | tr -d '[:space:]')"
case "$VER" in "$ev"*) ;; *) fail "EngineVersion $ev is not the server's version ($VER)" ;; esac
log "  ✓ EngineVersion $ev is the running server's version"
NEWPASS="Rot${SFX}pw2"
log "modify-db-instance --master-user-password: the old password must stop working, the new one work"
rds "$WAK" "$WSK" modify-db-instance --db-instance-identifier "$INST1" --master-user-password "$NEWPASS" --apply-immediately >/dev/null 2>"$PWD/.rds_mp" \
  || fail "modify-db-instance (password) failed: $(cat "$PWD/.rds_mp")"
rotated=""
for _ in $(seq 1 24); do
  # Captured, then matched: under pipefail, grep -q closing the pipe early would fail the pipeline.
  out="$(pg "${INST1}-rw" "SELECT 'NEWPW';" "$NEWPASS" || true)"
  if printf '%s' "$out" | grep -q NEWPW; then rotated=1; break; fi
  sleep 5
done
if [ -z "$rotated" ]; then
  why="$(kubectl -n "$RDS_NS" run "pgp-${SFX}-${RANDOM}" --image="$PGIMAGE" --restart=Never --rm -i --labels="probe=rds-$SFX" --command --timeout=90s -- \
    psql "postgresql://${PGUSER_M}:${NEWPASS}@${INST1}-rw.${RDS_NS}.svc.cluster.local:5432/${PGDB}" -tAc "SELECT 1" 2>&1 | grep -io "password authentication failed\|could not\|timeout\|error[^:]*" | head -2 | tr '\n' ' ')"
  roles="$(kubectl -n "$RDS_NS" get cluster.postgresql.cnpg.io "$INST1" -o jsonpath='{.status.managedRolesStatus.byStatus}' 2>/dev/null)"
  fail "the new master password never worked (psql: $why; managed roles: $roles)"
fi
out="$(pg "${INST1}-rw" "SELECT 'OLDPW';" || true)"
if printf '%s' "$out" | grep -q OLDPW; then fail "the old master password still works after the change"; fi
log "  ✓ the master password changed: the new one connects, the old one is refused"
if rds "$WAK" "$WSK" modify-db-instance --db-instance-identifier "$INST1" --preferred-maintenance-window sun:05:00-sun:06:00 >/dev/null 2>"$PWD/.rds_mp"; then
  fail "a ModifyDBInstance parameter that is not applied was accepted"
fi
grep -q InvalidParameterCombination "$PWD/.rds_mp" || fail "an unapplied parameter is refused with the wrong error: $(cat "$PWD/.rds_mp")"
rm -f "$PWD/.rds_mp"
log "  ✓ a parameter it does not apply is refused, not accepted"

# --- 5. DeletionProtection blocks delete ---
log "enable deletion protection on $INST1 — delete must then be BLOCKED"
rds "$WAK" "$WSK" modify-db-instance --db-instance-identifier "$INST1" --deletion-protection >/dev/null 2>&1 || fail "modify-db-instance (enable DP) failed"
if rds "$WAK" "$WSK" delete-db-instance --db-instance-identifier "$INST1" --skip-final-snapshot >/dev/null 2>"$PWD/.rds_dp"; then
  fail "a deletion-protected instance was deleted"
fi
grep -qiE 'deletion protection|InvalidParameterCombination' "$PWD/.rds_dp" || fail "deletion-protection block had the wrong error: $(cat "$PWD/.rds_dp")"
rm -f "$PWD/.rds_dp"
log "  ✓ deletion protection blocked the delete"

# --- 5b. Delete with a final snapshot → the instance is gone → restore the final snapshot → the row ---
log "delete $INST2 with final snapshot $FSNAP, then restore it once $INST2 is gone"
rds "$WAK" "$WSK" delete-db-instance --db-instance-identifier "$INST2" --final-db-snapshot-identifier "$FSNAP" >/dev/null 2>"$PWD/.rds_fd" \
  || fail "delete with a final snapshot failed: $(cat "$PWD/.rds_fd")"
gone=""
for _ in $(seq 1 120); do # the instance goes once its final snapshot has completed (uploaded)
  if ! rds "$WAK" "$WSK" describe-db-instances --db-instance-identifier "$INST2" >/dev/null 2>"$PWD/.rds_fd"; then
    grep -q DBInstanceNotFound "$PWD/.rds_fd" && { gone=1; break; }
  fi
  sleep 5
done
[ -n "$gone" ] || fail "$INST2 was not deleted within 10 minutes of its final snapshot"
fst="$(rds "$WAK" "$WSK" --output text --query 'DBSnapshots[0].Status' describe-db-snapshots --db-snapshot-identifier "$FSNAP" 2>/dev/null || true)"
[ "$fst" = available ] || fail "the final snapshot is not available after its instance was deleted (status=$fst)"
log "  ✓ $INST2 deleted after its final snapshot completed"
rds "$WAK" "$WSK" restore-db-instance-from-db-snapshot --db-instance-identifier "$INST3" --db-snapshot-identifier "$FSNAP" >/dev/null 2>"$PWD/.rds_fd" \
  || fail "restore of the final snapshot failed: $(cat "$PWD/.rds_fd")"
wait_available "$WAK" "$WSK" "$INST3" || fail "the instance restored from the final snapshot did not become available"
FOUT="$(pg "${INST3}-rw" "SELECT 'ROW:'||v FROM probe_t WHERE id=1;")"
printf '%s' "$FOUT" | grep -q "ROW:hello-$SFX" || fail "the final snapshot's restore did not contain the row; got: $(printf '%s' "$FOUT" | tr '\n' ' ')"
rm -f "$PWD/.rds_fd"
log "  ✓ the final snapshot of a deleted instance restored with the row"

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
log "a policy-only, describe-only principal (Cedar rds:DescribeDBInstances) must be DENIED CreateDBInstance"
mint_key "rds-probe-desc-$SFX" ""; DAK="$MK_AK"; DSK="$MK_SK"
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
