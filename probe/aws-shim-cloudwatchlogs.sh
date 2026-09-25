#!/usr/bin/env bash
# Compatibility probe for the aws-shim CloudWatch Logs surface.
#
# Fires REAL AWS SDK calls at a deployed shim and asserts the SEMANTICS log clients + audit tooling depend
# on — the failure to catch is the silent one: an operator believes logs were stored (for AU-2/AU-11) that
# were not, or read-back that drops/reorders/mangles them. It asserts, over real round-trips:
#   - PutLogEvents then GetLogEvents returns BYTE-IDENTICAL messages with the ORIGINAL millisecond
#     timestamps, IN ORDER
#   - out-of-order events in a batch are REJECTED (InvalidParameterException), as AWS rejects them
#   - FilterLogEvents actually FILTERS (a matching term returns only matching events)
#   - GetLogEvents pagination TERMINATES (the forward token stabilizes) rather than looping forever
#   - retention set via PutRetentionPolicy is reported back TRUTHFULLY by DescribeLogGroups
# and the NEGATIVES:
#   - a wrong secret is rejected (SignatureDoesNotMatch)
#   - a WRITE-ONLY principal is DENIED GetLogEvents while still able to PutLogEvents
#   - a principal scoped to group A CANNOT read group B (cross-tenant log exposure is the risk)
#
# Needs a deployed shim with the CloudWatch Logs data layer (SQS_PG_URI) + the platform IAM. Exit 0 = pass,
# 1 = a real failure, 42 = INCONCLUSIVE. Per polyhedron#164 / #157: a probe failure is presumed a shim
# defect, and 42 is not a pass.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-cloudwatchlogs.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

GA="cwl-probe-a-$SFX"
GB="cwl-probe-b-$SFX"
STREAM="s1"
CREATED_KEYS=(); CREATED_USERS=(); CREATED_POLICIES=()
WAK=""; WSK=""
cleanup() {
  for g in "$GA" "$GB"; do [ -n "$g" ] && AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager logs delete-log-group --log-group-name "$g" >/dev/null 2>&1; done
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
logs() { local ak="$1" sk="$2"; shift 2; AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text logs "$@"; }

# --- 1. seed writer + create group/stream ---
log "seeding a writer principal (openinfra:powerusers) + access key"
read -r WAK WSK <<<"$(mint_key "cwl-probe-$SFX" "powerusers")"
[ -n "$WAK" ] && [ -n "$WSK" ] || inconclusive "failed to mint a key"
sleep 2
log "create-log-group $GA + create-log-stream $STREAM"
logs "$WAK" "$WSK" create-log-group --log-group-name "$GA" >/dev/null 2>"$PWD/.cwl_c" || inconclusive "create-log-group failed (data layer configured?): $(cat "$PWD/.cwl_c")"
rm -f "$PWD/.cwl_c"
logs "$WAK" "$WSK" create-log-stream --log-group-name "$GA" --log-stream-name "$STREAM" >/dev/null 2>&1 || fail "create-log-stream failed"

# --- 2. PutLogEvents → GetLogEvents byte-identical, original ms timestamps, in order ---
NOW="$(date +%s)000"
T1="$NOW"; T2="$((NOW+1))"; T3="$((NOW+2))"
M1="alpha-$SFX"; M2="ERROR beta-$SFX"; M3="gamma-$SFX"
log "put-log-events (3 events, chronological) then get-log-events --start-from-head"
logs "$WAK" "$WSK" put-log-events --log-group-name "$GA" --log-stream-name "$STREAM" \
  --log-events "timestamp=$T1,message=$M1" "timestamp=$T2,message=$M2" "timestamp=$T3,message=$M3" >/dev/null 2>"$PWD/.cwl_p" \
  || fail "put-log-events failed: $(cat "$PWD/.cwl_p")"
rm -f "$PWD/.cwl_p"
OUT="$(logs "$WAK" "$WSK" get-log-events --log-group-name "$GA" --log-stream-name "$STREAM" --start-from-head --query 'events[*].[timestamp,message]' 2>/dev/null)"
# Expect exactly 3 rows in order with identical timestamps + messages.
EXPECT="$(printf '%s\t%s\n%s\t%s\n%s\t%s' "$T1" "$M1" "$T2" "$M2" "$T3" "$M3")"
[ "$OUT" = "$EXPECT" ] || fail "get-log-events did not return byte-identical ordered events with original timestamps.
got:
$OUT
want:
$EXPECT"
log "  ✓ 3 events round-tripped byte-identical, original ms timestamps, in order"

# --- 3. out-of-order batch is rejected ---
log "put-log-events out of order — must be REJECTED (InvalidParameterException)"
if logs "$WAK" "$WSK" put-log-events --log-group-name "$GA" --log-stream-name "$STREAM" \
    --log-events "timestamp=$((NOW+50)),message=late" "timestamp=$NOW,message=early" >/dev/null 2>"$PWD/.cwl_oo"; then
  fail "an out-of-order batch was accepted (AWS rejects it)"
fi
grep -qiE 'chronological|InvalidParameter' "$PWD/.cwl_oo" || fail "out-of-order rejection had the wrong error: $(cat "$PWD/.cwl_oo")"
rm -f "$PWD/.cwl_oo"
log "  ✓ out-of-order batch rejected"

# --- 4. FilterLogEvents actually filters ---
log "filter-log-events --filter-pattern ERROR — must return ONLY the matching event"
FOUT="$(logs "$WAK" "$WSK" filter-log-events --log-group-name "$GA" --filter-pattern "ERROR" --query 'events[*].message' 2>/dev/null)"
[ "$FOUT" = "$M2" ] || fail "filter returned the wrong set (got '$FOUT', want '$M2')"
# an empty pattern returns everything (3 events)
ALLN="$(logs "$WAK" "$WSK" filter-log-events --log-group-name "$GA" --query 'length(events)' 2>/dev/null)"
[ "$ALLN" = "3" ] || fail "empty filter should return all 3 events, got $ALLN"
# an unsupported (JSON-selector) pattern is refused, not silently unfiltered
if logs "$WAK" "$WSK" filter-log-events --log-group-name "$GA" --filter-pattern '{ $.level = "ERROR" }' >/dev/null 2>"$PWD/.cwl_fp"; then
  fail "an unsupported JSON-selector filter pattern was accepted (would silently return unfiltered data)"
fi
grep -qiE 'not supported|InvalidParameter' "$PWD/.cwl_fp" || fail "unsupported-pattern refusal had the wrong error: $(cat "$PWD/.cwl_fp")"
rm -f "$PWD/.cwl_fp"
log "  ✓ filter matches ERROR only; empty pattern returns all; JSON-selector pattern refused"

# --- 5. GetLogEvents pagination terminates ---
log "get-log-events pagination must TERMINATE (forward token stabilizes)"
TOK=""; PREV="__none__"; iters=0; term=""
while [ "$iters" -lt 10 ]; do
  if [ -z "$TOK" ]; then
    TOK="$(logs "$WAK" "$WSK" get-log-events --log-group-name "$GA" --log-stream-name "$STREAM" --start-from-head --query 'nextForwardToken' 2>/dev/null)"
  else
    TOK="$(logs "$WAK" "$WSK" get-log-events --log-group-name "$GA" --log-stream-name "$STREAM" --start-from-head --next-token "$TOK" --query 'nextForwardToken' 2>/dev/null)"
  fi
  iters=$((iters+1))
  [ "$TOK" = "$PREV" ] && { term=1; break; }
  PREV="$TOK"
done
[ -n "$term" ] || fail "get-log-events pagination did not stabilize within 10 iterations (would infinite-loop a client)"
log "  ✓ pagination terminated after $iters iterations"

# --- 6. Retention reported truthfully ---
log "put-retention-policy 30d — describe-log-groups must report retentionInDays=30"
logs "$WAK" "$WSK" put-retention-policy --log-group-name "$GA" --retention-in-days 30 >/dev/null 2>&1 || fail "put-retention-policy failed"
RET="$(logs "$WAK" "$WSK" describe-log-groups --log-group-name-prefix "$GA" --query 'logGroups[0].retentionInDays' 2>/dev/null)"
[ "$RET" = "30" ] || fail "retention not reported truthfully: got '$RET', want 30"
# a non-allowed retention value is refused
if logs "$WAK" "$WSK" put-retention-policy --log-group-name "$GA" --retention-in-days 31 >/dev/null 2>"$PWD/.cwl_ret"; then
  fail "a non-allowed retention value (31) was accepted"
fi
grep -qiE 'allowed|InvalidParameter' "$PWD/.cwl_ret" || fail "bad-retention refusal had the wrong error: $(cat "$PWD/.cwl_ret")"
rm -f "$PWD/.cwl_ret"
log "  ✓ retention 30d reported truthfully; non-allowed value refused"

# --- 7a. negative: wrong secret ---
log "negative: a wrong secret must be rejected"
if logs "$WAK" "wrong-secret-not-the-real-one" describe-log-groups >/dev/null 2>"$PWD/.cwl_neg"; then
  fail "a wrong secret was accepted"
fi
grep -qiE 'SignatureDoesNotMatch|Signature' "$PWD/.cwl_neg" || fail "wrong secret rejected with the wrong error: $(cat "$PWD/.cwl_neg")"
rm -f "$PWD/.cwl_neg"
log "  ✓ rejected on signature mismatch"

# --- 7b/7c. fine-grained: write-only denied read; A-scoped can't read B ---
log "create a second group $GB (for cross-group isolation) + seed fine-grained principals"
logs "$WAK" "$WSK" create-log-group --log-group-name "$GB" >/dev/null 2>&1 || fail "create second group failed"
logs "$WAK" "$WSK" create-log-stream --log-group-name "$GB" --log-stream-name "$STREAM" >/dev/null 2>&1 || fail "create second stream failed"
logs "$WAK" "$WSK" put-log-events --log-group-name "$GB" --log-stream-name "$STREAM" --log-events "timestamp=$NOW,message=secret-b-$SFX" >/dev/null 2>&1 || fail "seed B failed"
read -r OAK OSK <<<"$(mint_key "cwl-probe-writeonly-$SFX" "powerusers")"
read -r AAK ASK <<<"$(mint_key "cwl-probe-ascoped-$SFX" "powerusers")"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "cwl-writeonly-$SFX", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::cwl-probe-writeonly-$SFX"]
    statements:
      - { effect: Allow, actions: ["logs:PutLogEvents","logs:CreateLogStream"], resources: ["*"] }
---
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "cwl-ascoped-$SFX", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::cwl-probe-ascoped-$SFX"]
    statements:
      - { effect: Allow, actions: ["logs:GetLogEvents","logs:FilterLogEvents"], resources: ["LogGroup::${GA}"] }
YAML
CREATED_POLICIES+=("cwl-writeonly-$SFX" "cwl-ascoped-$SFX")
log "  waiting ~35s for the data-plane policy loader..."
sleep 35
log "write-only principal: PutLogEvents allowed, GetLogEvents DENIED"
logs "$OAK" "$OSK" put-log-events --log-group-name "$GA" --log-stream-name "$STREAM" --log-events "timestamp=$((NOW+100)),message=wo-$SFX" >/dev/null 2>"$PWD/.cwl_w" || fail "write-only principal denied PutLogEvents (should be allowed): $(cat "$PWD/.cwl_w")"
rm -f "$PWD/.cwl_w"
if logs "$OAK" "$OSK" get-log-events --log-group-name "$GA" --log-stream-name "$STREAM" >/dev/null 2>"$PWD/.cwl_wr"; then
  fail "a write-only principal was allowed to GetLogEvents"
fi
grep -qiE 'AccessDenied|denied' "$PWD/.cwl_wr" || fail "write-only read denial had the wrong error: $(cat "$PWD/.cwl_wr")"
rm -f "$PWD/.cwl_wr"
log "  ✓ write-only principal can write, denied read"
log "A-scoped principal: can read $GA, DENIED $GB"
logs "$AAK" "$ASK" filter-log-events --log-group-name "$GA" >/dev/null 2>"$PWD/.cwl_a" || fail "A-scoped principal denied reading group A (should be allowed): $(cat "$PWD/.cwl_a")"
rm -f "$PWD/.cwl_a"
if logs "$AAK" "$ASK" filter-log-events --log-group-name "$GB" >/dev/null 2>"$PWD/.cwl_b"; then
  fail "an A-scoped principal read group B (cross-tenant log exposure)"
fi
grep -qiE 'AccessDenied|denied' "$PWD/.cwl_b" || fail "cross-group denial had the wrong error: $(cat "$PWD/.cwl_b")"
rm -f "$PWD/.cwl_b"
log "  ✓ A-scoped principal reads A, denied B"

printf '\n✓ PASS — aws-shim CloudWatch Logs stores + serves events faithfully (ordered byte-identical read-back, out-of-order rejection, real filtering, terminating pagination, truthful retention) and enforces auth + the write/read + per-group boundaries.\n'
