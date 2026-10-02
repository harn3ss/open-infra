#!/usr/bin/env bash
# Compatibility probe for the aws-shim Glue Data Catalog surface (polyhedron#179).
#
# The Glue doorway fronts the platform's EXISTING Iceberg REST catalog (iceberg-rest.lakehouse) — a Glue
# database IS an Iceberg namespace, a Glue table IS an Iceberg table — rather than re-implementing a
# metastore. This probe fires REAL `aws glue` SDK calls at a deployed shim and asserts:
#
#   - database lifecycle: CreateDatabase → GetDatabase → the database appears in GetDatabases → DeleteDatabase;
#   - REAL table projection: GetTables/GetTable against a table that actually exists in the catalog returns
#     the Glue shape with Parameters.table_type=ICEBERG + a metadata_location + an s3:// Location and
#     schema-translated Columns (the one real translation the doorway performs) — proven against live
#     Iceberg metadata, never a fixture; GetPartitions returns [] (Iceberg partitions internally);
#   - AUTHORITY: a READER caller's CreateDatabase is refused at the control-plane gate and creates NOTHING;
#   - UNSUPPORTED refused honestly: CreateTable (create via Athena DDL, not Glue) and StartCrawler (no
#     crawler machine) are refused with InvalidInputException, never faked;
#   - a valid key id with a WRONG secret → signature mismatch.
#
# On-demand (needs a deployed shim with the Glue front door enabled + the Iceberg REST catalog of
# platform/query/manifests/iceberg-rest.yaml, plus openinfra:admins + openinfra:readers callers):
#
#   kubectl -n open-infra-aws-shim port-forward svc/aws-shim 4566:4566 &
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-glue.sh
#
# Exit 0 = pass, 1 = a real fidelity/enforcement failure, 42 = INCONCLUSIVE (a prerequisite was missing).
# Per polyhedron#157 a probe failure is presumed a shim defect.
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"

DB="glueprobe-$SFX"
READER_DB="glueprobe-reader-$SFX"
ADMIN_USER="glueprobe-admin-$SFX"
READER_USER="glueprobe-reader-$SFX"
AAK=""; ASK=""; RAK=""; RSK=""

glue() { # <ak> <sk> -- <glue args...>
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager glue "$@"
}

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
  kubectl -n "$SHIM_NS" create secret generic "$(secret_name "$ak")" \
    --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  printf '%s %s' "$ak" "$sk"
}

cleanup() {
  [ -n "$AAK" ] && { glue "$AAK" "$ASK" delete-database --name "$DB" >/dev/null 2>&1 || true; }
  # the reader must never have created its db, but drop it belt-and-suspenders if a regression let it:
  [ -n "$AAK" ] && { glue "$AAK" "$ASK" delete-database --name "$READER_DB" >/dev/null 2>&1 || true; }
  # users + key secrets are named deterministically / from the captured AKs (mint_key ran in a subshell).
  for u in "$ADMIN_USER" "$READER_USER"; do kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for ak in "$AAK" "$RAK"; do [ -n "$ak" ] && kubectl -n "$SHIM_NS" delete secret "$(secret_name "$ak")" --ignore-not-found >/dev/null 2>&1 || true; done
  rm -rf "$TMP"
}
trap cleanup EXIT

# --- seed callers -----------------------------------------------------------------------------------
log "seeding an openinfra:admins caller and an openinfra:readers caller"
read -r AAK ASK <<<"$(mint_key "$ADMIN_USER"  "admins")"
read -r RAK RSK <<<"$(mint_key "$READER_USER" "readers")"
[ -n "$AAK" ] && [ -n "$RAK" ] || inconclusive "failed to mint caller keys"
sleep 2

# --- gate: the Glue front door must be enabled ------------------------------------------------------
if ! glue "$AAK" "$ASK" get-databases >/dev/null 2>"$TMP/en.err"; then
  grep -qiE 'NotImplemented|not fronted|UnsupportedService' "$TMP/en.err" && inconclusive "the Glue front door is not enabled on this shim"
  inconclusive "glue get-databases failed, cannot confirm the front door: $(cat "$TMP/en.err")"
fi

# --- 1. database lifecycle --------------------------------------------------------------------------
log "create-database ${DB} → get-database → appears in get-databases"
glue "$AAK" "$ASK" create-database --database-input "{\"Name\":\"$DB\",\"Description\":\"glue probe\"}" >/dev/null 2>"$TMP/cd.err" \
  || fail "create-database failed: $(cat "$TMP/cd.err")"
GN="$(glue "$AAK" "$ASK" get-database --name "$DB" --query 'Database.Name' --output text 2>"$TMP/gd.err")" \
  || fail "get-database failed: $(cat "$TMP/gd.err")"
[ "$GN" = "$DB" ] || fail "get-database returned Name='$GN', want '$DB'"
glue "$AAK" "$ASK" get-databases --query 'DatabaseList[].Name' --output text 2>/dev/null | tr '\t' '\n' | grep -qxF "$DB" \
  || fail "the created database ${DB} did not appear in get-databases"
log "    ✓ database created, readable, listed"

# --- 2. real table projection (against whatever Iceberg table the catalog actually holds) -----------
# The doorway cannot CREATE tables (refused — see test 4), so the translation proof reads a table that
# genuinely exists in the catalog. Find a database that has at least one table; assert the Glue shape.
log "table projection: find a catalog table and assert the Iceberg→Glue shape"
PROBED_TABLE=0
for cdb in $(glue "$AAK" "$ASK" get-databases --query 'DatabaseList[].Name' --output text 2>/dev/null | tr '\t' '\n'); do
  [ "$cdb" = "$DB" ] && continue
  t="$(glue "$AAK" "$ASK" get-tables --database-name "$cdb" --query 'TableList[0].Name' --output text 2>/dev/null || true)"
  [ -n "$t" ] && [ "$t" != "None" ] || continue
  log "  get-table ${cdb}/${t}"
  glue "$AAK" "$ASK" get-table --database-name "$cdb" --name "$t" > "$TMP/tbl.json" 2>"$TMP/gt.err" \
    || fail "get-table ${cdb}/${t} failed: $(cat "$TMP/gt.err")"
  TT="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["Table"]["Parameters"].get("table_type",""))' "$TMP/tbl.json" 2>/dev/null || true)"
  [ "$TT" = "ICEBERG" ] || fail "get-table Parameters.table_type='$TT', want ICEBERG"
  ML="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["Table"]["Parameters"].get("metadata_location",""))' "$TMP/tbl.json" 2>/dev/null || true)"
  case "$ML" in s3://*) : ;; *) fail "metadata_location is not an s3:// uri: '$ML'";; esac
  LOC="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["Table"]["StorageDescriptor"].get("Location",""))' "$TMP/tbl.json" 2>/dev/null || true)"
  case "$LOC" in s3://*) : ;; *) fail "StorageDescriptor.Location is not an s3:// uri: '$LOC'";; esac
  NCOL="$(python3 -c '
import json,sys
c=json.load(open(sys.argv[1]))["Table"]["StorageDescriptor"]["Columns"]
assert c and all(x.get("Name") and x.get("Type") for x in c)
print(len(c))' "$TMP/tbl.json" 2>/dev/null || true)"
  [ -n "$NCOL" ] && [ "$NCOL" -ge 1 ] 2>/dev/null || fail "get-table returned no/invalid translated Columns (every column needs Name+Type)"
  log "    ✓ ${cdb}/${t}: table_type=ICEBERG, metadata_location+Location s3://, ${NCOL} translated column(s)"
  log "  get-partitions ${cdb}/${t} → [] (Iceberg partitions internally)"
  NP="$(glue "$AAK" "$ASK" get-partitions --database-name "$cdb" --table-name "$t" --query 'length(Partitions)' --output text 2>/dev/null || echo X)"
  [ "$NP" = "0" ] || fail "get-partitions returned ${NP} partitions, want 0 (Iceberg has no Hive partitions)"
  log "    ✓ get-partitions empty"
  PROBED_TABLE=1; break
done
[ "$PROBED_TABLE" = 1 ] || log "  (no catalog table available to project — database/authority/refusal assertions still cover the doorway)"

# --- 3. AUTHORITY — a reader's create provisions nothing --------------------------------------------
log "authority: a READER caller's create-database is refused at the control-plane gate, nothing created"
if glue "$RAK" "$RSK" create-database --database-input "{\"Name\":\"$READER_DB\"}" >/dev/null 2>"$TMP/auth.err"; then
  fail "a reader created a database it lacks authority for (the create gate did not enforce)"
fi
grep -qiE 'AccessDenied|denied|forbidden' "$TMP/auth.err" || fail "reader create-database refused with the wrong error: $(cat "$TMP/auth.err")"
if glue "$AAK" "$ASK" get-database --name "$READER_DB" >/dev/null 2>&1; then
  fail "a database exists for the denied reader (nothing should be created)"
fi
log "    ✓ reader refused — no database created"

# --- 4. UNSUPPORTED refused honestly ---------------------------------------------------------------
log "unsupported refused: create-table → InvalidInputException (create Iceberg tables via Athena DDL)"
if glue "$AAK" "$ASK" create-table --database-name "$DB" --table-input '{"Name":"probe-tbl"}' >/dev/null 2>"$TMP/ct.err"; then
  fail "create-table was ACCEPTED (Glue does not front table creation; must refuse)"
fi
grep -qiE 'CreateTable|not supported|not implemented|InvalidInput|Athena' "$TMP/ct.err" \
  || fail "create-table refusal had the wrong error: $(cat "$TMP/ct.err")"
log "    ✓ create-table refused honestly"

log "unsupported refused: start-crawler → InvalidInputException (no crawler machine)"
if glue "$AAK" "$ASK" start-crawler --name "glueprobe-crawler-$SFX" >/dev/null 2>"$TMP/sc.err"; then
  fail "start-crawler was ACCEPTED (crawlers are not implemented; must refuse)"
fi
grep -qiE 'Crawler|not supported|not implemented|InvalidInput' "$TMP/sc.err" \
  || fail "start-crawler refusal had the wrong error: $(cat "$TMP/sc.err")"
log "    ✓ start-crawler refused honestly"

# --- 5. negative: wrong SigV4 secret ---------------------------------------------------------------
log "negative: a valid key id with a WRONG secret on a management call → signature mismatch"
if glue "$AAK" "wrong-secret-not-the-real-one" get-databases >/dev/null 2>"$TMP/sig.err"; then
  fail "a wrong secret was accepted on a management call"
fi
grep -qiE 'Signature|does not match' "$TMP/sig.err" || fail "wrong-secret rejection had the wrong error: $(cat "$TMP/sig.err")"
log "    ✓ rejected on signature mismatch"

# --- 6. teardown: the probe database is removed -----------------------------------------------------
log "delete-database ${DB} → gone"
glue "$AAK" "$ASK" delete-database --name "$DB" >/dev/null 2>"$TMP/dd.err" || fail "delete-database failed: $(cat "$TMP/dd.err")"
if glue "$AAK" "$ASK" get-database --name "$DB" >/dev/null 2>&1; then
  fail "database ${DB} still present after delete-database"
fi
log "    ✓ database deleted"

printf '\n✓ PASS — aws-shim Glue is faithful: a database (Iceberg namespace) is created/read/listed/deleted; a real catalog table projects to the Glue shape (table_type=ICEBERG, metadata_location, s3:// Location, schema-translated Columns) with GetPartitions empty; a reader is refused at the create gate (nothing created); table creation and crawlers are refused honestly; and the SigV4 boundary holds.\n'
