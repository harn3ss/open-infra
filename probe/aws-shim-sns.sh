#!/usr/bin/env bash
# Compatibility probe for the aws-shim SNS surface.
#
# Fires REAL AWS SDK calls (the aws CLI) at a deployed shim and asserts the SEMANTICS SNS applications
# depend on — above all the canonical pattern, an SNS topic fanning out to N SQS queues, delivered
# DURABLY (Publish must have persisted the message for every subscription, not fire-and-forget):
#   - a topic with TWO sqs subscriptions delivers to BOTH (fan-out actually fans out)
#   - the default WRAPPED envelope parses (its .Message is the published body) and RawMessageDelivery=true
#     changes the delivered body to the bare payload
#   - a subscription carrying a FilterPolicy is REFUSED (not accepted-and-ignored, which would deliver
#     filtered-out messages), and an http/https subscription is REFUSED (not accepted-and-never-delivered)
# and the two NEGATIVES:
#   - a valid key ID with a WRONG secret is rejected (SignatureDoesNotMatch)
#   - a PUBLISH-ONLY principal (granted sns:Publish via Cedar) is DENIED sns:Subscribe while still able
#     to Publish — Subscribe is independently authorizable (it points outbound delivery at a destination)
#
# On-demand (needs a deployed shim + its SQS/SNS Postgres + the platform IAM). Exit 0 = pass, 1 = a real
# failure, 42 = INCONCLUSIVE. Per polyhedron#159 / #157: a probe failure is presumed a shim defect; 42
# is not a pass.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-sns.sh
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

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v python3 >/dev/null || inconclusive "python3 is required (to parse the SNS envelope)"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

CREATED_KEYS=(); CREATED_USERS=(); CREATED_QUEUES=(); TOPIC=""; POLICY=""
WAK=""; WSK=""
cleanup() {
  [ -n "$TOPIC" ] && AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager sns delete-topic --topic-arn "$TOPIC" >/dev/null 2>&1 || true
  for q in "${CREATED_QUEUES[@]:-}"; do [ -n "$q" ] && AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager sqs delete-queue --queue-url "$q" >/dev/null 2>&1 || true; done
  [ -n "$POLICY" ] && kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev "$POLICY" --ignore-not-found >/dev/null 2>&1 || true
  for s in "${CREATED_KEYS[@]:-}";  do [ -n "$s" ] && kubectl -n "$SHIM_NS" delete secret "$s" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
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
aws_() { local ak="$1" sk="$2"; shift 2; AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$@"; }

# --- seed a writer + two queues + a topic ------------------------------------------------------
log "seeding a writer principal (openinfra:powerusers) + access key"
read -r WAK WSK <<<"$(mint_key "sns-probe-writer-$SFX" "powerusers")"
[ -n "$WAK" ] && [ -n "$WSK" ] || inconclusive "failed to mint a writer key"
sleep 2

log "create two SQS queues (fan-out targets) + an SNS topic"
QA="$(aws_ "$WAK" "$WSK" sqs create-queue --queue-name "sns-fanout-a-$SFX" --query QueueUrl 2>/dev/null)" || inconclusive "sqs create-queue A failed (is the data layer configured?)"
QB="$(aws_ "$WAK" "$WSK" sqs create-queue --queue-name "sns-fanout-b-$SFX" --query QueueUrl 2>/dev/null)" || inconclusive "sqs create-queue B failed"
CREATED_QUEUES+=("$QA" "$QB")
ARNA="$(aws_ "$WAK" "$WSK" sqs get-queue-attributes --queue-url "$QA" --attribute-names QueueArn --query 'Attributes.QueueArn' 2>/dev/null)"
ARNB="$(aws_ "$WAK" "$WSK" sqs get-queue-attributes --queue-url "$QB" --attribute-names QueueArn --query 'Attributes.QueueArn' 2>/dev/null)"
TOPIC="$(aws_ "$WAK" "$WSK" sns create-topic --name "sns-probe-$SFX" --query TopicArn 2>/dev/null)" || inconclusive "sns create-topic failed"
[ -n "$TOPIC" ] || inconclusive "no TopicArn returned"
log "  ✓ topic: $TOPIC"

# --- subscribe A (wrapped default) + B (raw) ---------------------------------------------------
log "subscribe queue A (wrapped default) and queue B (RawMessageDelivery=true)"
aws_ "$WAK" "$WSK" sns subscribe --topic-arn "$TOPIC" --protocol sqs --notification-endpoint "$ARNA" >/dev/null 2>&1 || fail "subscribe A failed"
aws_ "$WAK" "$WSK" sns subscribe --topic-arn "$TOPIC" --protocol sqs --notification-endpoint "$ARNB" --attributes RawMessageDelivery=true >/dev/null 2>&1 || fail "subscribe B (raw) failed"

# --- publish once; assert fan-out to BOTH, and the two body shapes -----------------------------
MSG="fanout-payload-$SFX"
log "publish once; assert BOTH queues receive, A wrapped and B raw"
aws_ "$WAK" "$WSK" sns publish --topic-arn "$TOPIC" --message "$MSG" >/dev/null 2>&1 || fail "publish failed"
sleep 1
BODYA="$(aws_ "$WAK" "$WSK" sqs receive-message --queue-url "$QA" --wait-time-seconds 3 --query 'Messages[0].Body' 2>/dev/null)"
BODYB="$(aws_ "$WAK" "$WSK" sqs receive-message --queue-url "$QB" --wait-time-seconds 3 --query 'Messages[0].Body' 2>/dev/null)"
[ -n "$BODYA" ] && [ "$BODYA" != "None" ] || fail "queue A did not receive the fan-out message"
[ -n "$BODYB" ] && [ "$BODYB" != "None" ] || fail "queue B did not receive the fan-out message"
# A: wrapped envelope — parse JSON, .Message must equal the published body.
INNER="$(printf '%s' "$BODYA" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("Message",""))' 2>/dev/null || true)"
[ "$INNER" = "$MSG" ] || fail "wrapped envelope .Message wrong (got '$INNER', want '$MSG'); body was: $BODYA"
# B: raw — the body IS the bare message.
[ "$BODYB" = "$MSG" ] || fail "raw delivery body wrong (got '$BODYB', want '$MSG')"
log "  ✓ fan-out to both; A wrapped (.Message correct), B raw (bare payload)"

# --- refusals (honest, not silent) -------------------------------------------------------------
log "a FilterPolicy subscription must be REFUSED (not accepted-and-ignored)"
if aws_ "$WAK" "$WSK" sns subscribe --topic-arn "$TOPIC" --protocol sqs --notification-endpoint "$ARNA" --attributes 'FilterPolicy={"k":["v"]}' >/dev/null 2>"$PWD/.sns_fp"; then
  fail "a FilterPolicy subscription was accepted (it would be silently ignored)"
fi
grep -qiE 'FilterPolicy|InvalidParameter' "$PWD/.sns_fp" || fail "FilterPolicy refusal had the wrong error: $(cat "$PWD/.sns_fp")"; rm -f "$PWD/.sns_fp"
log "  ✓ FilterPolicy refused"
log "an https subscription must be REFUSED (egress surface; not accepted-and-never-delivered)"
if aws_ "$WAK" "$WSK" sns subscribe --topic-arn "$TOPIC" --protocol https --notification-endpoint "https://example.com/hook" >/dev/null 2>"$PWD/.sns_http"; then
  fail "an https subscription was accepted (it would never deliver)"
fi
grep -qiE 'not supported|InvalidParameter' "$PWD/.sns_http" || fail "https refusal had the wrong error: $(cat "$PWD/.sns_http")"; rm -f "$PWD/.sns_http"
log "  ✓ https refused"

# --- negative: wrong secret --------------------------------------------------------------------
log "negative: a valid key ID with a WRONG secret must be rejected"
if aws_ "$WAK" "wrong-secret-not-the-real-one" sns publish --topic-arn "$TOPIC" --message x >/dev/null 2>"$PWD/.sns_neg"; then
  fail "a wrong secret was accepted"
fi
grep -qiE 'SignatureDoesNotMatch' "$PWD/.sns_neg" || fail "wrong secret rejected with the wrong error: $(cat "$PWD/.sns_neg")"; rm -f "$PWD/.sns_neg"
log "  ✓ rejected as SignatureDoesNotMatch"

# --- negative: publish-only principal denied Subscribe (fine-grained Cedar) --------------------
log "publish-only principal: granted sns:Publish via Cedar, must be DENIED sns:Subscribe"
read -r PAK PSK <<<"$(mint_key "sns-probe-pubonly-$SFX" "powerusers")"
POLICY="sns-pubonly-$SFX"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "${POLICY}", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::sns-probe-pubonly-$SFX"]
    statements:
      - { effect: Allow, actions: ["sns:Publish"], resources: ["*"] }
YAML
log "  waiting ~35s for the data-plane policy loader to pick it up..."
sleep 35
# Publish must be ALLOWED for the publish-only principal.
aws_ "$PAK" "$PSK" sns publish --topic-arn "$TOPIC" --message "pubonly-$SFX" >/dev/null 2>"$PWD/.sns_pub" \
  || fail "publish-only principal was denied Publish (should be allowed): $(cat "$PWD/.sns_pub")"
rm -f "$PWD/.sns_pub"
log "  ✓ publish-only principal CAN Publish"
# Subscribe must be DENIED (governed for sns, sns:Subscribe not granted).
if aws_ "$PAK" "$PSK" sns subscribe --topic-arn "$TOPIC" --protocol sqs --notification-endpoint "$ARNA" >/dev/null 2>"$PWD/.sns_sub"; then
  fail "a publish-only principal was allowed to Subscribe (Subscribe must be independently denied)"
fi
grep -qiE 'AuthorizationError|AccessDenied|denied' "$PWD/.sns_sub" || fail "Subscribe denial had the wrong error: $(cat "$PWD/.sns_sub")"; rm -f "$PWD/.sns_sub"
log "  ✓ publish-only principal DENIED Subscribe"

printf '\n✓ PASS — aws-shim SNS fans out durably to SQS (wrapped + raw), refuses FilterPolicy/https honestly, and authorizes Subscribe independently of Publish.\n'
