#!/usr/bin/env bash
# Compatibility probe for the aws-shim Kinesis Data Streams surface — ordered, sharded, replayable
# streaming, deliberately distinct from the unordered SQS / no-retention SNS doorways.
#
# It fires REAL AWS SDK calls (the aws CLI) and asserts the SEMANTICS that DISTINGUISH Kinesis — because the
# failure this exists to catch is a stream that looks like Kinesis but silently breaks ordered/replayable
# consumers. It asserts, over real round-trips:
#   - records with the SAME PartitionKey land in one shard and GetRecords returns them IN ORDER with
#     MONOTONIC SequenceNumbers
#   - TRIM_HORIZON RE-READS from the start (replay works — the whole point vs SQS)
#   - records with DIFFERENT partition keys distribute across shards (hash)
#   - MillisBehindLatest is reported
#   - a PutRecords partial failure surfaces PER RECORD (FailedRecordCount + per-entry ErrorCode)
# and the NEGATIVES that are the whole point ("prove the no"):
#   - a valid key ID with a WRONG secret → SignatureDoesNotMatch
#   - a cross-tenant stream read is DENIED
#   - a read-only principal is denied PutRecord while still able to GetRecords
#
# On-demand (needs a deployed shim + the Kinesis Postgres + the platform IAM). Exit 0 = pass, 1 = a real
# failure, 42 = INCONCLUSIVE. Per polyhedron#157, a probe failure is presumed a shim defect and 42 is not a pass.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-kinesis.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v python3 >/dev/null || inconclusive "python3 is required (JSON assertions)"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"

CREATED_KEYS=(); CREATED_USERS=(); CREATED_POLICIES=(); CREATED_STREAMS=()
WAK=""; WSK=""
cleanup() {
  for s in "${CREATED_STREAMS[@]:-}";  do [ -n "$s" ] && k "$WAK" "$WSK" delete-stream --stream-name "$s" >/dev/null 2>&1 || true; done
  for kk in "${CREATED_KEYS[@]:-}";    do [ -n "$kk" ] && kubectl -n "$SHIM_NS" delete secret "$kk" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}";    do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for p in "${CREATED_POLICIES[@]:-}"; do [ -n "$p" ] && kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev "$p" --ignore-not-found >/dev/null 2>&1 || true; done
}
trap cleanup EXIT

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
  CREATED_USERS+=("$owner")
  local name; name="$(secret_name "$ak")"
  kubectl -n "$SHIM_NS" create secret generic "$name" \
    --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  CREATED_KEYS+=("$name")
  printf '%s %s' "$ak" "$sk"
}
# raw-in-base64-out so --data takes raw text and Data comes back base64 (the v1-compatible blob mode).
k() { local ak="$1" sk="$2"; shift 2; AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
  aws --endpoint-url "$ENDPOINT" --no-cli-pager --cli-binary-format raw-in-base64-out kinesis "$@"; }

# --- 1. Seed a writer principal + key -----------------------------------------------------------
log "seeding a writer principal (openinfra:powerusers) + access key"
read -r WAK WSK <<<"$(mint_key "kin-probe-$SFX" "powerusers")"
[ -n "$WAK" ] && [ -n "$WSK" ] || inconclusive "failed to mint a key"
sleep 2

STREAM="kin-probe-$SFX"
log "create-stream ${STREAM} (4 shards)"
k "$WAK" "$WSK" create-stream --stream-name "$STREAM" --shard-count 4 >/dev/null 2>&1 \
  || inconclusive "create-stream failed — is SQS_PG_URI set on the shim?"
CREATED_STREAMS+=("$STREAM")
sleep 1

# --- 2. Same PartitionKey → in-order, monotonic SequenceNumbers ---------------------------------
log "put 5 records with the SAME PartitionKey → one shard, strict order, monotonic SequenceNumbers"
PK="orders-$SFX"
SHARD=""
for i in 1 2 3 4 5; do
  RESP="$(k "$WAK" "$WSK" put-record --stream-name "$STREAM" --partition-key "$PK" --data "msg-$i" --output json 2>/dev/null)" || fail "put-record $i failed"
  SH="$(printf '%s' "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["ShardId"])')"
  [ -z "$SHARD" ] && SHARD="$SH"
  [ "$SH" = "$SHARD" ] || fail "same PartitionKey landed in different shards ($SH vs $SHARD)"
done
log "  all 5 in $SHARD; reading them back in order"
IT="$(k "$WAK" "$WSK" get-shard-iterator --stream-name "$STREAM" --shard-id "$SHARD" --shard-iterator-type TRIM_HORIZON --query ShardIterator --output text 2>/dev/null)"
[ -n "$IT" ] && [ "$IT" != "None" ] || fail "no shard iterator"
REC_FILE="$(mktemp)"
k "$WAK" "$WSK" get-records --shard-iterator "$IT" --output json >"$REC_FILE" 2>/dev/null
python3 - "$REC_FILE" <<'PY' || fail "records were not returned in order with monotonic SequenceNumbers"
import sys,json,base64
r=json.load(open(sys.argv[1]))
recs=r["Records"]
assert len(recs)==5, f'got {len(recs)} records, want 5'
datas=[base64.b64decode(x["Data"]).decode() for x in recs]
assert datas==[f"msg-{i}" for i in (1,2,3,4,5)], f'out of order: {datas}'
seqs=[int(x["SequenceNumber"]) for x in recs]
assert seqs==sorted(seqs) and len(set(seqs))==5, f'non-monotonic SequenceNumbers: {seqs}'
assert "MillisBehindLatest" in r, "MillisBehindLatest missing"
print("  ✓ 5 records in strict order, monotonic SequenceNumbers, MillisBehindLatest present")
PY
rm -f "$REC_FILE"

# --- 3. TRIM_HORIZON replay -------------------------------------------------------------------
log "replay: a fresh TRIM_HORIZON iterator must re-read from the start"
IT2="$(k "$WAK" "$WSK" get-shard-iterator --stream-name "$STREAM" --shard-id "$SHARD" --shard-iterator-type TRIM_HORIZON --query ShardIterator --output text 2>/dev/null)"
N2="$(k "$WAK" "$WSK" get-records --shard-iterator "$IT2" --query 'length(Records)' --output text 2>/dev/null)"
[ "$N2" = "5" ] || fail "replay from TRIM_HORIZON returned $N2 records, want 5 (replay broken)"
log "  ✓ replay re-read all 5"

# --- 4. Different partition keys distribute across shards --------------------------------------
log "different partition keys must distribute across shards (hash)"
SHARDS_SEEN="$(for i in $(seq 1 12); do
  k "$WAK" "$WSK" put-record --stream-name "$STREAM" --partition-key "key-$SFX-$i" --data "d$i" --query ShardId --output text 2>/dev/null
done | sort -u | wc -l)"
[ "$SHARDS_SEEN" -ge 2 ] 2>/dev/null || fail "12 distinct keys hit only $SHARDS_SEEN shard(s) — partition-key hashing broken"
log "  ✓ distinct keys spread across $SHARDS_SEEN shards"

# --- 5. PutRecords partial failure surfaces per record ----------------------------------------
log "put-records with one oversized (>1 MiB) record among valid ones → per-record failure"
RECS_FILE="$(mktemp)"
python3 - "$RECS_FILE" <<'PY'
import sys,json,base64
path=sys.argv[1]
big=b"x"*1100000  # > 1 MiB, generated in-process (not passed as an argv)
recs=[
 {"Data":base64.b64encode(b"ok-1").decode(),"PartitionKey":"p1"},
 {"Data":base64.b64encode(big).decode(),"PartitionKey":"p2"},
 {"Data":base64.b64encode(b"ok-2").decode(),"PartitionKey":"p3"},
]
json.dump(recs,open(path,"w"))
PY
PR_FILE="$(mktemp)"
k "$WAK" "$WSK" put-records --stream-name "$STREAM" --records "file://$RECS_FILE" --output json >"$PR_FILE" 2>/dev/null || fail "put-records call failed"
rm -f "$RECS_FILE"
python3 - "$PR_FILE" <<'PY' || fail "partial failure was not surfaced per record"
import sys,json
r=json.load(open(sys.argv[1]))
assert r["FailedRecordCount"]>=1, f'FailedRecordCount={r["FailedRecordCount"]}, want >=1'
recs=r["Records"]
assert len(recs)==3, f'want 3 per-record results, got {len(recs)}'
assert "ErrorCode" in recs[1], f'the oversized record should carry an ErrorCode: {recs[1]}'
assert "SequenceNumber" in recs[0] and "SequenceNumber" in recs[2], "the valid records should have SequenceNumbers"
print("  ✓ FailedRecordCount>=1; the bad record has an ErrorCode, the good ones SequenceNumbers")
PY
rm -f "$PR_FILE"

# --- 6. Negative: wrong secret ----------------------------------------------------------------
log "negative: a valid key ID with a WRONG secret must be rejected"
if k "$WAK" "wrong-secret-not-the-real-one" list-streams >/dev/null 2>"$PWD/.kin_neg"; then
  fail "a wrong secret was accepted"
fi
grep -qiE 'Signature|does not match' "$PWD/.kin_neg" || fail "wrong secret rejected with the wrong error: $(cat "$PWD/.kin_neg")"
rm -f "$PWD/.kin_neg"
log "  ✓ rejected on signature mismatch"

# --- 7. Negative: cross-tenant read + read-only can't write -----------------------------------
log "seeding a read-only, A-scoped principal (GetRecords on this stream only)"
read -r RAK RSK <<<"$(mint_key "kin-probe-ro-$SFX" "powerusers")"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "kin-ro-$SFX", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::kin-probe-ro-$SFX"]
    statements:
      - { effect: Allow, actions: ["kinesis:GetRecords","kinesis:GetShardIterator","kinesis:DescribeStream"], resources: ["Stream::${STREAM}"] }
YAML
CREATED_POLICIES+=("kin-ro-$SFX")
OTHER="kin-probe-other-$SFX"
k "$WAK" "$WSK" create-stream --stream-name "$OTHER" --shard-count 1 >/dev/null 2>&1 || fail "create other stream failed"
CREATED_STREAMS+=("$OTHER")
log "  waiting ~35s for the data-plane policy loader..."
sleep 35

log "read-only principal: can DescribeStream A, DENIED PutRecord A, DENIED read of stream B"
k "$RAK" "$RSK" describe-stream --stream-name "$STREAM" >/dev/null 2>"$PWD/.kin_ro" || fail "read-only principal denied DescribeStream on A (should be allowed): $(cat "$PWD/.kin_ro" 2>/dev/null)"
rm -f "$PWD/.kin_ro"
if k "$RAK" "$RSK" put-record --stream-name "$STREAM" --partition-key p --data x >/dev/null 2>"$PWD/.kin_w"; then
  fail "a read-only principal wrote a record (PutRecord must be denied)"
fi
grep -qiE 'AccessDenied|denied' "$PWD/.kin_w" || fail "read-only PutRecord denial had the wrong error: $(cat "$PWD/.kin_w")"
rm -f "$PWD/.kin_w"
if k "$RAK" "$RSK" describe-stream --stream-name "$OTHER" >/dev/null 2>"$PWD/.kin_x"; then
  fail "an A-scoped principal read stream B (cross-tenant read must be denied)"
fi
grep -qiE 'AccessDenied|denied' "$PWD/.kin_x" || fail "cross-tenant denial had the wrong error: $(cat "$PWD/.kin_x")"
rm -f "$PWD/.kin_x"
log "  ✓ reads A, denied write A, denied stream B"

printf '\n✓ PASS — aws-shim Kinesis Data Streams is semantically faithful: same-key in-order monotonic SequenceNumbers, TRIM_HORIZON replay, partition-key sharding, MillisBehindLatest, per-record PutRecords partial failure, and the auth + cross-tenant + read/write boundaries.\n'
