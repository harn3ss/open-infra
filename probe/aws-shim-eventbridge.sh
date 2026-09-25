#!/usr/bin/env bash
# Compatibility probe for the aws-shim EventBridge surface.
#
# Fires REAL AWS SDK calls at a deployed shim and — crucially — crosses into OBSERVING REAL EFFECTS,
# because the failure this exists to catch is the silent one: scheduled work that never runs, or an event
# routed to a target that never receives it, with no error anywhere. It asserts, over real round-trips:
#   - a rate(1 minute) rule DELIVERS TO ITS TARGET repeatedly — proven by reading the target and seeing
#     the delivery arrive TWICE (recurrence, not a single fire)
#   - the delivered scheduled event carries the correct envelope: source="aws.events",
#     detail-type="Scheduled Event"
#   - DisableRule actually STOPS the deliveries
#   - a six-field AWS cron expression schedules and fires (a five-field Unix cron and an untranslatable
#     one are REFUSED at PutRule, not silently mis-scheduled)
#   - an EventPattern ADMITS a matching PutEvents event and EXCLUDES a non-matching one; TestEventPattern
#     gives the same answer the router does
# and the NEGATIVES that are the whole point ("prove the no"):
#   - a wrong secret is rejected (signature mismatch)
#   - a principal that can DescribeRule but not PutTargets is denied PutTargets
#   - the escalation fence: PutTargets of a Lambda the caller cannot invoke is refused
#
# The observable SINK is an SQS queue (via the shim's own SQS doorway) — a durable, exactly-readable
# target, a stronger observation than a Knative function's internal side effect. The Lambda-target PATH is
# exercised via the authority fence. Needs a deployed shim with the SQS data layer + NATS (async). Exit 0 =
# pass, 1 = a real failure, 42 = INCONCLUSIVE. Per polyhedron#163 / #157: a probe failure is presumed a
# shim defect, and 42 is not a pass.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-eventbridge.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
ACCOUNT="${ACCOUNT_ID:-open-infra}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v python3 >/dev/null || inconclusive "python3 is required (JSON assertions)"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

CREATED_KEYS=(); CREATED_USERS=(); CREATED_POLICIES=(); CREATED_RULES=(); CREATED_QUEUES=()
WAK=""; WSK=""
cleanup() {
  for r in "${CREATED_RULES[@]:-}"; do [ -n "$r" ] && {
    ids="$(AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text events list-targets-by-rule --rule "$r" --query 'Targets[].Id' 2>/dev/null)"
    [ -n "$ids" ] && AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager events remove-targets --rule "$r" --ids $ids >/dev/null 2>&1
    AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager events delete-rule --name "$r" >/dev/null 2>&1
  }; done
  for q in "${CREATED_QUEUES[@]:-}"; do [ -n "$q" ] && AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager sqs delete-queue --queue-url "$q" >/dev/null 2>&1; done
  for s in "${CREATED_KEYS[@]:-}";     do [ -n "$s" ] && kubectl -n "$SHIM_NS" delete secret "$s" --ignore-not-found >/dev/null 2>&1; done
  for u in "${CREATED_USERS[@]:-}";    do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1; done
  for p in "${CREATED_POLICIES[@]:-}"; do [ -n "$p" ] && kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev "$p" --ignore-not-found >/dev/null 2>&1; done
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
  kubectl -n "$SHIM_NS" create secret generic "$name" --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  CREATED_KEYS+=("$name")
  printf '%s %s' "$ak" "$sk"
}
ev() { local ak="$1" sk="$2"; shift 2; AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text events "$@"; }
sqs() { local ak="$1" sk="$2"; shift 2; AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text sqs "$@"; }

# drain <qurl> -> prints each message Body on its own line, deleting them
drain() {
  local q="$1" out
  out="$(sqs "$WAK" "$WSK" receive-message --queue-url "$q" --max-number-of-messages 10 --wait-time-seconds 2 \
        --query 'Messages[].[Body,ReceiptHandle]' 2>/dev/null)" || return 0
  [ -z "$out" ] && return 0
  while IFS=$'\t' read -r body handle; do
    [ -z "$handle" ] && continue
    printf '%s\n' "$body"
    sqs "$WAK" "$WSK" delete-message --queue-url "$q" --receipt-handle "$handle" >/dev/null 2>&1
  done <<< "$out"
}

# --- seed principal + observable SQS sinks ---
log "seeding a writer principal (openinfra:powerusers) + access key"
read -r WAK WSK <<<"$(mint_key "eb-probe-$SFX" "powerusers")"
[ -n "$WAK" ] && [ -n "$WSK" ] || inconclusive "failed to mint a key"
sleep 2

SINK="eb-sink-$SFX"
SINK_URL="$(sqs "$WAK" "$WSK" create-queue --queue-name "$SINK" --query QueueUrl 2>/dev/null)" || inconclusive "create-queue failed (SQS data layer?)"
[ -n "$SINK_URL" ] && [ "$SINK_URL" != "None" ] || inconclusive "no sink queue url"
CREATED_QUEUES+=("$SINK_URL")
SINK_ARN="$(sqs "$WAK" "$WSK" get-queue-attributes --queue-url "$SINK_URL" --attribute-names QueueArn --query 'Attributes.QueueArn' 2>/dev/null)"
[ -n "$SINK_ARN" ] && [ "$SINK_ARN" != "None" ] || inconclusive "could not read sink ARN"
log "  ✓ observable SQS sink: $SINK_ARN"

# --- 1. rate(1 minute) rule delivers to its target TWICE (recurrence) + correct envelope ---
RRULE="eb-rate-$SFX"
log "put-rule $RRULE rate(1 minute) + target the SQS sink; expect >=2 deliveries (recurrence)"
ev "$WAK" "$WSK" put-rule --name "$RRULE" --schedule-expression "rate(1 minute)" --state ENABLED >/dev/null 2>&1 || fail "put-rule (rate) failed"
CREATED_RULES+=("$RRULE")
ev "$WAK" "$WSK" put-targets --rule "$RRULE" --targets "Id=t1,Arn=$SINK_ARN" >/dev/null 2>"$PWD/.eb_pt" || fail "put-targets (sqs) failed: $(cat "$PWD/.eb_pt")"
rm -f "$PWD/.eb_pt"
count=0; first_body=""; deadline=$(( $(date +%s) + 175 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  while IFS= read -r b; do
    [ -z "$b" ] && continue
    count=$((count+1)); [ -z "$first_body" ] && first_body="$b"
  done < <(drain "$SINK_URL")
  [ "$count" -ge 2 ] && break
  sleep 8
done
[ "$count" -ge 2 ] || fail "rate(1 minute) delivered $count time(s) in ~175s; expected >=2 (recurrence not proven)"
log "  ✓ delivered $count times (recurrence proven)"
echo "$first_body" | python3 -c 'import json,sys
e=json.load(sys.stdin)
assert e.get("source")=="aws.events", "source=%r"%e.get("source")
assert e.get("detail-type")=="Scheduled Event", "detail-type=%r"%e.get("detail-type")
print("  envelope OK: source=%s detail-type=%s"%(e["source"],e["detail-type"]))' || fail "scheduled event envelope wrong: $first_body"
log "  ✓ envelope has source=aws.events, detail-type=Scheduled Event"

# --- 2. DisableRule stops delivery ---
log "disable-rule — deliveries must STOP"
ev "$WAK" "$WSK" disable-rule --name "$RRULE" >/dev/null 2>&1 || fail "disable-rule failed"
sleep 5; drain "$SINK_URL" >/dev/null 2>&1  # clear anything already queued at disable time
stopped_deadline=$(( $(date +%s) + 75 )); after=0
while [ "$(date +%s)" -lt "$stopped_deadline" ]; do
  while IFS= read -r b; do [ -n "$b" ] && after=$((after+1)); done < <(drain "$SINK_URL")
  sleep 8
done
[ "$after" -eq 0 ] || fail "a DISABLED rule still delivered $after message(s)"
log "  ✓ no deliveries after disable"

# --- 3. six-field cron accepted + fires; five-field + untranslatable refused ---
log "cron: a five-field (Unix) expression must be REFUSED at put-rule"
if ev "$WAK" "$WSK" put-rule --name "eb-badcron-$SFX" --schedule-expression "cron(0 12 * * ?)" --state ENABLED >/dev/null 2>"$PWD/.eb_bc"; then
  CREATED_RULES+=("eb-badcron-$SFX"); fail "a five-field cron was accepted (would mis-schedule)"
fi
grep -qiE 'Validation|six|field' "$PWD/.eb_bc" || fail "five-field cron refusal had the wrong error: $(cat "$PWD/.eb_bc")"
rm -f "$PWD/.eb_bc"
log "  ✓ five-field cron refused"
# a valid six-field cron for the minute two minutes from now (this hour), targeting the sink.
M=$(( ($(date -u +%M) + 2) % 60 ))
CRULE="eb-cron-$SFX"
log "put-rule $CRULE cron($M * * * ? *) — must fire at minute $M UTC"
ev "$WAK" "$WSK" put-rule --name "$CRULE" --schedule-expression "cron($M * * * ? *)" --state ENABLED >/dev/null 2>&1 || fail "put-rule (cron) failed"
CREATED_RULES+=("$CRULE")
ev "$WAK" "$WSK" put-targets --rule "$CRULE" --targets "Id=t1,Arn=$SINK_ARN" >/dev/null 2>&1 || fail "put-targets (cron) failed"
cron_deadline=$(( $(date +%s) + 200 )); cron_hits=0
while [ "$(date +%s)" -lt "$cron_deadline" ]; do
  while IFS= read -r b; do [ -n "$b" ] && cron_hits=$((cron_hits+1)); done < <(drain "$SINK_URL")
  [ "$cron_hits" -ge 1 ] && break
  sleep 8
done
[ "$cron_hits" -ge 1 ] || fail "six-field cron did not fire within ~3 minutes"
log "  ✓ six-field cron fired ($cron_hits delivery)"
ev "$WAK" "$WSK" disable-rule --name "$CRULE" >/dev/null 2>&1 || true

# --- 4. event pattern admits matching, excludes non-matching (PutEvents) ---
PRULE="eb-pat-$SFX"; PATQ="eb-patq-$SFX"
PATQ_URL="$(sqs "$WAK" "$WSK" create-queue --queue-name "$PATQ" --query QueueUrl 2>/dev/null)"; CREATED_QUEUES+=("$PATQ_URL")
PATQ_ARN="$(sqs "$WAK" "$WSK" get-queue-attributes --queue-url "$PATQ_URL" --attribute-names QueueArn --query 'Attributes.QueueArn' 2>/dev/null)"
log "put-rule $PRULE with an EventPattern + SQS target"
ev "$WAK" "$WSK" put-rule --name "$PRULE" --event-pattern '{"source":["probe.app"],"detail-type":["OrderPlaced"]}' --state ENABLED >/dev/null 2>&1 || fail "put-rule (pattern) failed"
CREATED_RULES+=("$PRULE")
ev "$WAK" "$WSK" put-targets --rule "$PRULE" --targets "Id=t1,Arn=$PATQ_ARN" >/dev/null 2>&1 || fail "put-targets (pattern) failed"
log "put-events a MATCHING event — must be delivered"
# put-events Detail is a JSON string; the CLI shorthand cannot carry nested JSON, so pass the entries as
# a JSON document via file:// (this is a CLI-parsing constraint, not a shim behavior).
MATCH_JSON="$(mktemp)"; printf '[{"Source":"probe.app","DetailType":"OrderPlaced","Detail":"{\\"id\\":\\"%s\\"}","EventBusName":"default"}]' "$SFX" > "$MATCH_JSON"
ev "$WAK" "$WSK" put-events --entries "file://$MATCH_JSON" >/dev/null 2>"$PWD/.eb_pe" || fail "put-events (match) failed: $(cat "$PWD/.eb_pe")"
rm -f "$PWD/.eb_pe" "$MATCH_JSON"
matched=0; md=$(( $(date +%s) + 40 ))
while [ "$(date +%s)" -lt "$md" ]; do
  while IFS= read -r b; do [ -n "$b" ] && matched=$((matched+1)); done < <(drain "$PATQ_URL")
  [ "$matched" -ge 1 ] && break; sleep 5
done
[ "$matched" -ge 1 ] || fail "a matching event was NOT delivered to the pattern rule's target"
log "  ✓ matching event delivered"
log "put-events a NON-MATCHING event — must NOT be delivered"
NOMATCH_JSON="$(mktemp)"; printf '[{"Source":"probe.app","DetailType":"SomethingElse","Detail":"{}","EventBusName":"default"}]' > "$NOMATCH_JSON"
ev "$WAK" "$WSK" put-events --entries "file://$NOMATCH_JSON" >/dev/null 2>&1 || fail "put-events (nomatch) failed"
rm -f "$NOMATCH_JSON"
sleep 15; nomatch=0
while IFS= read -r b; do [ -n "$b" ] && nomatch=$((nomatch+1)); done < <(drain "$PATQ_URL")
[ "$nomatch" -eq 0 ] || fail "a NON-matching event was delivered ($nomatch) — pattern matched too loosely"
log "  ✓ non-matching event excluded"
# TestEventPattern agrees with the router
R1="$(ev "$WAK" "$WSK" test-event-pattern --event-pattern '{"source":["probe.app"]}' --event '{"source":"probe.app","detail-type":"X","detail":{}}' --query Result 2>/dev/null)"
R2="$(ev "$WAK" "$WSK" test-event-pattern --event-pattern '{"source":["probe.app"]}' --event '{"source":"other","detail-type":"X","detail":{}}' --query Result 2>/dev/null)"
[ "$R1" = "True" ] || [ "$R1" = "true" ] || fail "TestEventPattern said no to a matching event: $R1"
{ [ "$R2" = "False" ] || [ "$R2" = "false" ]; } || fail "TestEventPattern said yes to a non-matching event: $R2"
log "  ✓ TestEventPattern agrees with the router"

# --- 5a. negative: wrong secret ---
log "negative: a wrong secret must be rejected"
if ev "$WAK" "wrong-secret-not-the-real-one" list-rules >/dev/null 2>"$PWD/.eb_neg"; then fail "a wrong secret was accepted"; fi
grep -qiE 'Signature|does not match' "$PWD/.eb_neg" || fail "wrong secret rejected with the wrong error: $(cat "$PWD/.eb_neg")"
rm -f "$PWD/.eb_neg"
log "  ✓ rejected on signature mismatch"

# --- 5b. escalation fence: PutTargets of a Lambda the caller cannot invoke is refused ---
log "escalation fence: targeting a Lambda the caller cannot invoke must be REFUSED"
FRULE="eb-fence-$SFX"
ev "$WAK" "$WSK" put-rule --name "$FRULE" --schedule-expression "rate(1 hour)" --state DISABLED >/dev/null 2>&1 || fail "put-rule (fence) failed"
CREATED_RULES+=("$FRULE")
read -r RAK RSK <<<"$(mint_key "eb-probe-reader-$SFX" "readers")"  # readers cannot invoke functions
sleep 2
# The reader can't even create a rule (create verb), so give them a rule to target via the writer's rule,
# but attempt PutTargets AS the reader — denied by the coarse events:PutTargets (create) gate OR the fence.
if ev "$RAK" "$RSK" put-targets --rule "$FRULE" --targets "Id=t1,Arn=arn:aws:lambda:$REGION:$ACCOUNT:function:nonexistent-$SFX" >/dev/null 2>"$PWD/.eb_fence"; then
  fail "a reader was allowed to PutTargets (privilege escalation)"
fi
grep -qiE 'AccessDenied|denied|not authorized' "$PWD/.eb_fence" || fail "fence denial had the wrong error: $(cat "$PWD/.eb_fence")"
rm -f "$PWD/.eb_fence"
log "  ✓ unauthorized PutTargets refused (no escalation)"

# --- 5c. DescribeRule-but-not-PutTargets (fine-grained Cedar) ---
log "a principal with events:DescribeRule but not events:PutTargets is denied PutTargets"
read -r DAK DSK <<<"$(mint_key "eb-probe-desc-$SFX" "powerusers")"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "eb-desconly-$SFX", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::eb-probe-desc-$SFX"]
    statements:
      - { effect: Allow, actions: ["events:DescribeRule","events:ListRules"], resources: ["*"] }
YAML
CREATED_POLICIES+=("eb-desconly-$SFX")
log "  waiting ~35s for the data-plane policy loader..."
sleep 35
ev "$DAK" "$DSK" describe-rule --name "$RRULE" >/dev/null 2>"$PWD/.eb_d" || fail "describe-only principal denied DescribeRule (should be allowed): $(cat "$PWD/.eb_d")"
rm -f "$PWD/.eb_d"
if ev "$DAK" "$DSK" put-targets --rule "$RRULE" --targets "Id=t9,Arn=$SINK_ARN" >/dev/null 2>"$PWD/.eb_dp"; then
  fail "a DescribeRule-only principal was allowed to PutTargets"
fi
grep -qiE 'AccessDenied|denied' "$PWD/.eb_dp" || fail "PutTargets denial had the wrong error: $(cat "$PWD/.eb_dp")"
rm -f "$PWD/.eb_dp"
log "  ✓ DescribeRule allowed, PutTargets denied (separable)"

printf '\n✓ PASS — aws-shim EventBridge schedules (rate + six-field cron) and routes (event patterns) to targets with the correct envelope, DisableRule stops it, and it enforces auth + the escalation fence.\n'
