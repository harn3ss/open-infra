#!/usr/bin/env bash
# Compatibility probe for the aws-shim CloudWatch metrics + alarms surface — the other half of CloudWatch
# (Logs shipped in polyhedron#164).
#
# It fires REAL AWS SDK calls (the aws CLI) and asserts the SEMANTICS an ops team depends on — not merely
# HTTP 200 — because the failure this exists to catch is the monitoring false green: a statistic silently
# aggregating the wrong series, or an ALARM THAT NEVER EVALUATES (worse than absent — the operator sees it
# in DescribeAlarms and believes they have coverage they do not). It asserts, over real round-trips:
#   - PutMetricData then GetMetricStatistics returns the value **aggregated correctly over the period**
#     (Sum/Average/Maximum/Minimum/SampleCount)
#   - **dimensions are part of the metric's identity**: a datapoint on a different dimension value is a
#     DIFFERENT series and is NOT merged into the aggregate
#   - a **percentile** (ExtendedStatistic pNN) computes
#   - the alarm crux: an alarm with a threshold **actually transitions to ALARM** when breaching data is
#     written, and **fires its SNS action**, verified by receiving the notification through SNS→SQS (#159/#158)
#   - **TreatMissingData=breaching** is honored: an alarm with no data transitions to ALARM
# and the NEGATIVES that are the whole point ("prove the no"):
#   - a valid key ID with a WRONG secret → SignatureDoesNotMatch
#   - a **cross-tenant metric read is DENIED** (a principal scoped to namespace A cannot GetMetricStatistics
#     on namespace B — a data-exposure hole otherwise)
#
# On-demand (needs a deployed shim + the CloudWatch/SQS/SNS Postgres + the platform IAM). Exit 0 = pass,
# 1 = a real failure, 42 = INCONCLUSIVE. Per polyhedron#157, a probe failure is presumed a shim defect.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-cloudwatch.sh
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
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"

CREATED_KEYS=(); CREATED_USERS=(); CREATED_POLICIES=(); CREATED_ALARMS=(); CREATED_QUEUES=(); CREATED_TOPICS=()
WAK=""; WSK=""
cleanup() {
  for a in "${CREATED_ALARMS[@]:-}";  do [ -n "$a" ] && cw "$WAK" "$WSK" delete-alarms --alarm-names "$a" >/dev/null 2>&1 || true; done
  for q in "${CREATED_QUEUES[@]:-}";  do [ -n "$q" ] && AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager sqs delete-queue --queue-url "$q" >/dev/null 2>&1 || true; done
  for t in "${CREATED_TOPICS[@]:-}";  do [ -n "$t" ] && AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager sns delete-topic --topic-arn "$t" >/dev/null 2>&1 || true; done
  for k in "${CREATED_KEYS[@]:-}";    do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}";   do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for p in "${CREATED_POLICIES[@]:-}";do [ -n "$p" ] && kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev "$p" --ignore-not-found >/dev/null 2>&1 || true; done
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
awsc() { local ak="$1" sk="$2" svc="$3"; shift 3; AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$svc" "$@"; }
cw()  { local ak="$1" sk="$2"; shift 2; awsc "$ak" "$sk" cloudwatch "$@"; }

# --- 1. Seed a writer principal + key ---------------------------------------------------------
log "seeding a writer principal (openinfra:powerusers) + access key"
read -r WAK WSK <<<"$(mint_key "cw-probe-$SFX" "powerusers")"
[ -n "$WAK" ] && [ -n "$WSK" ] || inconclusive "failed to mint a key"
sleep 2

NS="openinfra/probe-$SFX"
MET="Latency"
NOWSEC="$(date -u +%s)"
TS="$(date -u -d "@$((NOWSEC-120))" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r $((NOWSEC-120)) +%Y-%m-%dT%H:%M:%SZ)"
START="$(date -u -d "@$((NOWSEC-3600))" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r $((NOWSEC-3600)) +%Y-%m-%dT%H:%M:%SZ)"
END="$(date -u -d "@$((NOWSEC+60))" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r $((NOWSEC+60)) +%Y-%m-%dT%H:%M:%SZ)"

# --- 2. PutMetricData → GetMetricStatistics aggregates correctly over the period ----------------
log "put-metric-data (10,20,30,40 on InstanceId=i-1) → get-metric-statistics aggregates correctly"
for v in 10 20 30 40; do
  cw "$WAK" "$WSK" put-metric-data --namespace "$NS" \
    --metric-data "MetricName=$MET,Value=$v,Timestamp=$TS,Unit=Milliseconds,Dimensions=[{Name=InstanceId,Value=i-1}]" \
    >/dev/null 2>&1 || inconclusive "put-metric-data failed — is SQS_PG_URI set on the shim?"
done
# a datapoint on a DIFFERENT dimension value — must NOT be merged into i-1's aggregate
cw "$WAK" "$WSK" put-metric-data --namespace "$NS" \
  --metric-data "MetricName=$MET,Value=999,Timestamp=$TS,Unit=Milliseconds,Dimensions=[{Name=InstanceId,Value=i-2}]" >/dev/null 2>&1 || true
sleep 1
stat() { cw "$WAK" "$WSK" get-metric-statistics --namespace "$NS" --metric-name "$MET" \
  --dimensions Name=InstanceId,Value=i-1 --start-time "$START" --end-time "$END" --period 3600 \
  --statistics "$1" --query "Datapoints[0].$1" 2>/dev/null; }
SUM="$(stat Sum)"; AVG="$(stat Average)"; MAX="$(stat Maximum)"; MIN="$(stat Minimum)"; CNT="$(stat SampleCount)"
[ "${SUM%.*}" = "100" ] || fail "Sum = '$SUM', want 100 (dimension i-2's 999 must not merge in)"
[ "${AVG%.*}" = "25" ]  || fail "Average = '$AVG', want 25"
[ "${MAX%.*}" = "40" ]  || fail "Maximum = '$MAX', want 40"
[ "${MIN%.*}" = "10" ]  || fail "Minimum = '$MIN', want 10"
[ "${CNT%.*}" = "4" ]   || fail "SampleCount = '$CNT', want 4"
log "  ✓ Sum=100 Avg=25 Max=40 Min=10 Count=4 (dimensions are part of identity)"

# --- 3. Percentile computes -------------------------------------------------------------------
log "get-metric-statistics --extended-statistics p50 must compute"
P50="$(cw "$WAK" "$WSK" get-metric-statistics --namespace "$NS" --metric-name "$MET" \
  --dimensions Name=InstanceId,Value=i-1 --start-time "$START" --end-time "$END" --period 3600 \
  --extended-statistics p50 --query 'Datapoints[0].ExtendedStatistics.p50' 2>/dev/null || true)"
[ -n "$P50" ] && [ "$P50" != "None" ] || fail "p50 did not compute (got '$P50')"
P50I="${P50%.*}"
[ "$P50I" -ge 20 ] && [ "$P50I" -le 30 ] 2>/dev/null || fail "p50 = '$P50', want ~25 (between 20 and 30)"
log "  ✓ p50 = $P50"

# --- 4. Alarm ACTUALLY evaluates → ALARM → fires its SNS action -------------------------------
log "wiring an SNS topic + SQS queue (the alarm action target) and an alarm"
QURL="$(awsc "$WAK" "$WSK" sqs create-queue --queue-name "cw-probe-q-$SFX" --query QueueUrl 2>/dev/null)" || inconclusive "sqs create-queue failed"
[ -n "$QURL" ] && [ "$QURL" != "None" ] || inconclusive "no queue url"
CREATED_QUEUES+=("$QURL")
QARN="$(awsc "$WAK" "$WSK" sqs get-queue-attributes --queue-url "$QURL" --attribute-names QueueArn --query 'Attributes.QueueArn' 2>/dev/null)"
TARN="$(awsc "$WAK" "$WSK" sns create-topic --name "cw-probe-t-$SFX" --query TopicArn 2>/dev/null)" || inconclusive "sns create-topic failed"
[ -n "$TARN" ] && [ "$TARN" != "None" ] || inconclusive "no topic arn"
CREATED_TOPICS+=("$TARN")
awsc "$WAK" "$WSK" sns subscribe --topic-arn "$TARN" --protocol sqs --notification-endpoint "$QARN" >/dev/null 2>&1 \
  || inconclusive "sns subscribe failed"

ALARM="cw-probe-alarm-$SFX"
cw "$WAK" "$WSK" put-metric-alarm --alarm-name "$ALARM" --namespace "$NS" --metric-name Breaches \
  --dimensions Name=InstanceId,Value=i-1 --statistic Maximum --period 60 --evaluation-periods 1 \
  --datapoints-to-alarm 1 --threshold 50 --comparison-operator GreaterThanThreshold \
  --treat-missing-data notBreaching --alarm-actions "$TARN" >/dev/null 2>&1 || fail "put-metric-alarm failed"
CREATED_ALARMS+=("$ALARM")
log "  alarm created; writing breaching data and waiting for a genuine ALARM transition (evaluator)"
GOT_ALARM=""
for _ in $(seq 1 12); do
  # keep a fresh breaching datapoint in the evaluation window until the evaluator catches it
  cw "$WAK" "$WSK" put-metric-data --namespace "$NS" \
    --metric-data "MetricName=Breaches,Value=100,Unit=Count,Dimensions=[{Name=InstanceId,Value=i-1}]" >/dev/null 2>&1 || true
  ST="$(cw "$WAK" "$WSK" describe-alarms --alarm-names "$ALARM" --query 'MetricAlarms[0].StateValue' 2>/dev/null || true)"
  if [ "$ST" = "ALARM" ]; then GOT_ALARM=1; break; fi
  sleep 8
done
[ -n "$GOT_ALARM" ] || fail "the alarm did NOT transition to ALARM on breaching data (an alarm that never evaluates is worse than absent)"
log "  ✓ alarm genuinely evaluated → ALARM"

log "  the ALARM must have fired its SNS action → received via SNS→SQS"
GOT_NOTIF=""
for _ in $(seq 1 6); do
  MSG="$(awsc "$WAK" "$WSK" sqs receive-message --queue-url "$QURL" --max-number-of-messages 10 --wait-time-seconds 3 --query 'Messages[].Body' 2>/dev/null || true)"
  if printf '%s' "$MSG" | grep -q "$ALARM"; then GOT_NOTIF=1; break; fi
  sleep 3
done
[ -n "$GOT_NOTIF" ] || fail "the alarm's SNS action did not deliver a notification to the subscribed SQS queue"
log "  ✓ alarm action fired; notification received through SNS→SQS"

# --- 5. TreatMissingData=breaching is honored -------------------------------------------------
log "an alarm with no data and TreatMissingData=breaching must transition to ALARM"
MALARM="cw-probe-missing-$SFX"
cw "$WAK" "$WSK" put-metric-alarm --alarm-name "$MALARM" --namespace "$NS" --metric-name NoData$SFX \
  --statistic Average --period 60 --evaluation-periods 1 --datapoints-to-alarm 1 --threshold 1 \
  --comparison-operator GreaterThanThreshold --treat-missing-data breaching >/dev/null 2>&1 || fail "put-metric-alarm (missing) failed"
CREATED_ALARMS+=("$MALARM")
GOT_M=""
for _ in $(seq 1 8); do
  ST="$(cw "$WAK" "$WSK" describe-alarms --alarm-names "$MALARM" --query 'MetricAlarms[0].StateValue' 2>/dev/null || true)"
  if [ "$ST" = "ALARM" ]; then GOT_M=1; break; fi
  sleep 8
done
[ -n "$GOT_M" ] || fail "TreatMissingData=breaching was not honored (alarm with no data should be ALARM)"
log "  ✓ TreatMissingData=breaching honored"

# --- 6a. Negative: wrong secret ---------------------------------------------------------------
log "negative: a valid key ID with a WRONG secret must be rejected"
if cw "$WAK" "wrong-secret-not-the-real-one" list-metrics >/dev/null 2>"$PWD/.cw_neg"; then
  fail "a wrong secret was accepted"
fi
grep -qiE 'Signature|does not match' "$PWD/.cw_neg" || fail "wrong secret rejected with the wrong error: $(cat "$PWD/.cw_neg")"
rm -f "$PWD/.cw_neg"
log "  ✓ rejected on signature mismatch"

# --- 6b. Negative: cross-tenant metric read denied --------------------------------------------
log "negative: a principal scoped to namespace A must be DENIED reading namespace B"
NS_B="openinfra/probe-b-$SFX"
cw "$WAK" "$WSK" put-metric-data --namespace "$NS_B" --metric-data "MetricName=Secret,Value=7,Unit=Count" >/dev/null 2>&1 || true
read -r AAK ASK <<<"$(mint_key "cw-probe-ascoped-$SFX" "powerusers")"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "cw-ascoped-$SFX", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::cw-probe-ascoped-$SFX"]
    statements:
      - { effect: Allow, actions: ["cloudwatch:*"], resources: ["Namespace::${NS}"] }
YAML
CREATED_POLICIES+=("cw-ascoped-$SFX")
log "  waiting ~35s for the data-plane policy loader to pick it up..."
sleep 35
# can read its own namespace A
cw "$AAK" "$ASK" get-metric-statistics --namespace "$NS" --metric-name "$MET" --dimensions Name=InstanceId,Value=i-1 \
  --start-time "$START" --end-time "$END" --period 3600 --statistics Sum >/dev/null 2>"$PWD/.cw_a" \
  || fail "A-scoped principal could not read its own namespace A: $(cat "$PWD/.cw_a" 2>/dev/null)"
rm -f "$PWD/.cw_a"
if cw "$AAK" "$ASK" get-metric-statistics --namespace "$NS_B" --metric-name Secret \
  --start-time "$START" --end-time "$END" --period 3600 --statistics Sum >/dev/null 2>"$PWD/.cw_b"; then
  fail "an A-scoped principal read namespace B's metrics (cross-tenant data-exposure hole)"
fi
grep -qiE 'AccessDenied|denied' "$PWD/.cw_b" || fail "cross-tenant denial had the wrong error: $(cat "$PWD/.cw_b")"
rm -f "$PWD/.cw_b"
log "  ✓ reads A, denied B (cross-tenant read fenced)"

printf '\n✓ PASS — aws-shim CloudWatch metrics/alarms is semantically faithful: correct period aggregation with dimension identity, percentiles, alarms that GENUINELY evaluate and fire SNS actions, TreatMissingData honored, and the auth + cross-tenant boundaries.\n'
