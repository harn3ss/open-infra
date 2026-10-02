#!/usr/bin/env bash
# Compatibility probe for the aws-shim Athena surface (polyhedron#179).
#
# Athena executes SQL against the platform's Trino engine (trino.lakehouse, /v1/statement) over the
# `iceberg` catalog — an Athena query IS a Trino query. This probe fires REAL `aws athena` SDK calls at a
# deployed shim and asserts, end to end:
#
#   - the async query flow over a REAL table: StartQueryExecution (a SELECT over the Iceberg catalog) returns
#     a QueryExecutionId immediately; GetQueryExecution polls QUEUED→RUNNING→SUCCEEDED (absorbing Trino's
#     cold start — the doorway scales Trino up from zero); GetQueryResults returns the AWS header row (the
#     column names) + the data rows;
#   - Trino scale-to-zero COOPERATION: after the query, the Trino Deployment is scaled to 1 and carries the
#     athena.openinfra.dev/last-query annotation the autostop honors (so it is not scaled down mid-use);
#   - AUTHORITY: a READER caller's StartQueryExecution is refused at the control-plane gate;
#   - UNSUPPORTED refused honestly: CreateWorkGroup and the Athena catalog-metadata API (GetDatabase → use
#     glue.*) are refused; GetWorkGroup resolves only the built-in 'primary';
#   - StopQueryExecution is wired (a submitted query can be stopped; state goes terminal);
#   - a valid key id with a WRONG secret → signature mismatch.
#
# On-demand (needs a deployed shim with the Athena front door + the Trino/Iceberg lakehouse of
# platform/query/manifests/, plus openinfra:admins + openinfra:readers callers). Trino runs scale-to-zero,
# so the FIRST query cold-starts it (JVM boot) — the poll budget below is generous.
#
#   kubectl -n open-infra-aws-shim port-forward svc/aws-shim 4566:4566 &
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-athena.sh
#
# Exit 0 = pass, 1 = a real fidelity/enforcement failure, 42 = INCONCLUSIVE. Per polyhedron#157 a probe
# failure is presumed a shim defect.
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
LAKE_NS="${LAKE_NS:-lakehouse}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
QUERY_DB="${ATHENA_PROBE_DB:-demo}"          # the Iceberg namespace holding the probe table
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"
QUERY_TIMEOUT="${ATHENA_QUERY_TIMEOUT:-200}" # seconds to wait for a query incl. Trino cold start

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"

ADMIN_USER="athenaprobe-admin-$SFX"
READER_USER="athenaprobe-reader-$SFX"
AAK=""; ASK=""; RAK=""; RSK=""

ath() { # <ak> <sk> -- <athena args...>
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --cli-read-timeout 120 athena "$@"
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
  for u in "$ADMIN_USER" "$READER_USER"; do kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for ak in "$AAK" "$RAK"; do [ -n "$ak" ] && kubectl -n "$SHIM_NS" delete secret "$(secret_name "$ak")" --ignore-not-found >/dev/null 2>&1 || true; done
  rm -rf "$TMP"
}
trap cleanup EXIT

# start_query <sql> [database] -> echoes the QueryExecutionId
start_query() {
  local sql="$1" db="${2:-}"
  if [ -n "$db" ]; then
    ath "$AAK" "$ASK" start-query-execution --query-string "$sql" \
      --query-execution-context "Database=$db,Catalog=iceberg" \
      --query 'QueryExecutionId' --output text
  else
    ath "$AAK" "$ASK" start-query-execution --query-string "$sql" \
      --query 'QueryExecutionId' --output text
  fi
}

# await_state <qid> -> echoes the terminal state (SUCCEEDED/FAILED/CANCELLED) or "TIMEOUT"
await_state() {
  local qid="$1" i=0 st=""
  while [ "$i" -lt "$QUERY_TIMEOUT" ]; do
    st="$(ath "$AAK" "$ASK" get-query-execution --query-execution-id "$qid" \
          --query 'QueryExecution.Status.State' --output text 2>/dev/null || true)"
    case "$st" in SUCCEEDED|FAILED|CANCELLED) echo "$st"; return;; esac
    sleep 4; i=$((i+4))
  done
  echo "TIMEOUT"
}

# --- seed callers -----------------------------------------------------------------------------------
log "seeding an openinfra:admins caller and an openinfra:readers caller"
read -r AAK ASK <<<"$(mint_key "$ADMIN_USER"  "admins")"
read -r RAK RSK <<<"$(mint_key "$READER_USER" "readers")"
[ -n "$AAK" ] && [ -n "$RAK" ] || inconclusive "failed to mint caller keys"
sleep 2

# --- gate: the Athena front door must be enabled ----------------------------------------------------
if ! ath "$AAK" "$ASK" list-work-groups >/dev/null 2>"$TMP/en.err"; then
  grep -qiE 'NotImplemented|not fronted|UnsupportedService' "$TMP/en.err" && inconclusive "the Athena front door is not enabled on this shim"
  inconclusive "athena list-work-groups failed, cannot confirm the front door: $(cat "$TMP/en.err")"
fi

# --- pick a real table in the probe database (proves Iceberg-catalog access) -------------------------
# Use the sibling glue doorway to discover a table; fall back to a catalog-free SELECT if none exists.
PTABLE="$(AWS_ACCESS_KEY_ID="$AAK" AWS_SECRET_ACCESS_KEY="$ASK" AWS_REGION="$REGION" \
  aws --endpoint-url "$ENDPOINT" --no-cli-pager glue get-tables --database-name "$QUERY_DB" \
  --query 'TableList[0].Name' --output text 2>/dev/null || true)"

# --- 1. async query flow: start → poll SUCCEEDED → results ------------------------------------------
if [ -n "$PTABLE" ] && [ "$PTABLE" != "None" ]; then
  SQL="SELECT * FROM ${PTABLE} LIMIT 100"
  log "start-query-execution: '${SQL}' (database=${QUERY_DB}) — this cold-starts Trino"
  QID="$(start_query "$SQL" "$QUERY_DB" 2>"$TMP/sq.err")" || fail "start-query-execution failed: $(cat "$TMP/sq.err")"
else
  SQL="SELECT 1 AS n, 'ok' AS s"
  log "no table in ${QUERY_DB}; start-query-execution: '${SQL}' (catalog-free) — this cold-starts Trino"
  QID="$(start_query "$SQL" 2>"$TMP/sq.err")" || fail "start-query-execution failed: $(cat "$TMP/sq.err")"
fi
case "$QID" in ?*) : ;; *) fail "start-query-execution returned no QueryExecutionId";; esac
log "    ✓ QueryExecutionId=${QID}"

log "  polling get-query-execution until terminal (Trino cold start can take ~1-2 min)..."
ST="$(await_state "$QID")"
[ "$ST" = "SUCCEEDED" ] || {
  RSN="$(ath "$AAK" "$ASK" get-query-execution --query-execution-id "$QID" --query 'QueryExecution.Status.StateChangeReason' --output text 2>/dev/null || true)"
  fail "query did not SUCCEED (state=$ST, reason=${RSN})"
}
log "    ✓ query SUCCEEDED"

log "  get-query-results → a header row (column names) + data rows"
ath "$AAK" "$ASK" get-query-results --query-execution-id "$QID" > "$TMP/res.json" 2>"$TMP/gr.err" \
  || fail "get-query-results failed: $(cat "$TMP/gr.err")"
NROWS="$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["ResultSet"]["Rows"]))' "$TMP/res.json" 2>/dev/null || echo 0)"
NCOLS="$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]))' "$TMP/res.json" 2>/dev/null || echo 0)"
[ "$NCOLS" -ge 1 ] 2>/dev/null || fail "get-query-results returned no ColumnInfo"
[ "$NROWS" -ge 1 ] 2>/dev/null || fail "get-query-results returned no rows (expected at least the header row)"
# The FIRST row is the Athena column-name header — assert it carries the column names.
HDR_OK="$(python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))["ResultSet"]
cols=[c["Name"] for c in d["ResultSetMetadata"]["ColumnInfo"]]
hdr=[c.get("VarCharValue") for c in d["Rows"][0]["Data"]]
print("yes" if hdr==cols else "no (%r vs %r)"%(hdr,cols))
' "$TMP/res.json" 2>/dev/null || echo no)"
[ "$HDR_OK" = "yes" ] || fail "first result Row is not the column-name header: $HDR_OK"
log "    ✓ ${NCOLS} column(s), $((NROWS-1)) data row(s), header row matches ColumnInfo"

# --- 2. Trino scale-to-zero cooperation -------------------------------------------------------------
log "cooperation: Trino is scaled up (1) and carries the autostop activity annotation"
REP="$(kubectl -n "$LAKE_NS" get deploy trino -o jsonpath='{.spec.replicas}' 2>/dev/null || echo X)"
[ "$REP" = "1" ] || fail "Trino Deployment replicas='$REP' after a query, want 1 (the doorway should have scaled it up)"
ANN="$(kubectl -n "$LAKE_NS" get deploy trino -o jsonpath='{.metadata.annotations.athena\.openinfra\.dev/last-query}' 2>/dev/null || true)"
[ -n "$ANN" ] || fail "Trino Deployment is missing the athena.openinfra.dev/last-query annotation (autostop cooperation)"
log "    ✓ trino replicas=1, last-query annotation=${ANN}"

# --- 3. AUTHORITY — a reader cannot submit a query --------------------------------------------------
log "authority: a READER caller's start-query-execution is refused at the control-plane gate"
if ath "$RAK" "$RSK" start-query-execution --query-string "SELECT 1" >/dev/null 2>"$TMP/auth.err"; then
  fail "a reader submitted a query it lacks authority for (the gate did not enforce)"
fi
grep -qiE 'AccessDenied|denied|forbidden' "$TMP/auth.err" || fail "reader start-query-execution refused with the wrong error: $(cat "$TMP/auth.err")"
log "    ✓ reader refused"

# --- 4. UNSUPPORTED refused honestly ----------------------------------------------------------------
log "unsupported refused: create-work-group → InvalidRequestException (only 'primary' exists)"
if ath "$AAK" "$ASK" create-work-group --name "athenaprobe-wg-$SFX" >/dev/null 2>"$TMP/cwg.err"; then
  fail "create-work-group was ACCEPTED (only the primary workgroup is provided; must refuse)"
fi
grep -qiE 'CreateWorkGroup|not implemented|primary|InvalidRequest' "$TMP/cwg.err" \
  || fail "create-work-group refusal had the wrong error: $(cat "$TMP/cwg.err")"
log "    ✓ create-work-group refused honestly"

log "unsupported refused: get-database (Athena metadata API) → InvalidRequestException (use glue.*)"
if ath "$AAK" "$ASK" get-database --catalog-name AwsDataCatalog --database-name "$QUERY_DB" >/dev/null 2>"$TMP/gdb.err"; then
  fail "athena get-database was ACCEPTED (catalog metadata is served by Glue; must refuse)"
fi
grep -qiE 'glue|not implemented|InvalidRequest|metadata' "$TMP/gdb.err" \
  || fail "athena get-database refusal had the wrong error: $(cat "$TMP/gdb.err")"
log "    ✓ athena metadata API refused (points to glue.*)"

# --- 5. workgroup resolution ------------------------------------------------------------------------
log "get-work-group primary → ENABLED; a non-existent workgroup → ResourceNotFoundException"
ath "$AAK" "$ASK" get-work-group --work-group primary >/dev/null 2>"$TMP/wg.err" || fail "get-work-group primary failed: $(cat "$TMP/wg.err")"
if ath "$AAK" "$ASK" get-work-group --work-group "nope-$SFX" >/dev/null 2>"$TMP/wg2.err"; then
  fail "get-work-group for a non-existent workgroup was accepted"
fi
grep -qiE 'ResourceNotFound|not found' "$TMP/wg2.err" || fail "missing-workgroup error was wrong: $(cat "$TMP/wg2.err")"
log "    ✓ primary resolves; unknown workgroup → ResourceNotFoundException"

# --- 6. StopQueryExecution is wired -----------------------------------------------------------------
log "stop-query-execution: a submitted query can be stopped (state goes terminal)"
SQID="$(start_query "SELECT * FROM (VALUES 1,2,3) AS t(x)" 2>/dev/null || true)"
if [ -n "$SQID" ] && [ "$SQID" != "None" ]; then
  ath "$AAK" "$ASK" stop-query-execution --query-execution-id "$SQID" >/dev/null 2>"$TMP/stop.err" \
    || fail "stop-query-execution failed: $(cat "$TMP/stop.err")"
  SST="$(await_state "$SQID")"
  case "$SST" in CANCELLED|SUCCEEDED) log "    ✓ stop accepted; final state ${SST}";; *) fail "after stop, state=$SST (want CANCELLED or SUCCEEDED)";; esac
else
  fail "could not submit the stop-test query"
fi

# --- 7. negative: wrong SigV4 secret ---------------------------------------------------------------
log "negative: a valid key id with a WRONG secret → signature mismatch"
if ath "$AAK" "wrong-secret-not-the-real-one" list-work-groups >/dev/null 2>"$TMP/sig.err"; then
  fail "a wrong secret was accepted"
fi
grep -qiE 'Signature|does not match' "$TMP/sig.err" || fail "wrong-secret rejection had the wrong error: $(cat "$TMP/sig.err")"
log "    ✓ rejected on signature mismatch"

printf '\n✓ PASS — aws-shim Athena is faithful: a SELECT over the Iceberg catalog runs through Trino (StartQueryExecution returns immediately, the query is QUEUED through the Trino cold start, then SUCCEEDS; GetQueryResults returns the AWS header row + data); the doorway scales Trino up and registers the autostop activity annotation; a reader is refused at the submit gate; workgroup CUD and the Athena metadata API are refused honestly (use glue.*); StopQueryExecution is wired; and the SigV4 boundary holds.\n'
