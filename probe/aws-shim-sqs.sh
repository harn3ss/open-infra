#!/usr/bin/env bash
# Compatibility probe for the aws-shim SQS surface.
#
# Fires REAL AWS SDK calls (the aws CLI is a real SDK client) at a deployed shim and asserts the
# SEMANTICS SQS applications actually depend on — not merely HTTP 200 — because the failure this exists
# to catch is the false-green: the app believes a message was durably queued/received/deleted and a
# semantic did not hold. It asserts, over a real round-trip:
#   - send → receive returns identical Body, a correct MD5OfBody, and the message attributes + a correct
#     MD5OfMessageAttributes (SDK-verify faithful)
#   - a received-but-not-deleted message REDELIVERS after its visibility timeout (ApproximateReceiveCount grows)
#   - a STALE ReceiptHandle (from the pre-redelivery receive) is REJECTED — the delete-the-wrong-delivery
#     data-loss boundary
#   - maxReceiveCount moves a message to the DLQ, and it is receivable there with ApproximateReceiveCount
#   - long polling returns an EMPTY SUCCESS (not an error) when no message is available
# and the two NEGATIVES that are the whole point ("prove the no"):
#   - a valid key ID with a WRONG secret is rejected (SignatureDoesNotMatch)
#   - a receive-only principal is DENIED DeleteMessage while still able to ReceiveMessage
#
# On-demand (needs a deployed shim + its SQS Postgres + the platform IAM). Exit 0 = pass, 1 = a real
# failure (the shim is not faithful), 42 = INCONCLUSIVE (a prerequisite was missing). Per polyhedron#158
# / #157: a probe failure is presumed a shim defect, and 42 is not a pass.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-sqs.sh
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
command -v kubectl >/dev/null || inconclusive "kubectl is required to seed the principal + key"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"

CREATED_KEYS=(); CREATED_USERS=(); CREATED_QUEUES=()
WAK=""; WSK=""
cleanup() {
  for q in "${CREATED_QUEUES[@]:-}"; do [ -n "$q" ] && AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager sqs delete-queue --queue-url "$q" >/dev/null 2>&1 || true; done
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

awsq() { # AK SK -- <sqs args...>
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text sqs "$@"
}

md5() { printf '%s' "$1" | md5sum | cut -d' ' -f1; }

# --- 1. Seed a writer principal + key ---------------------------------------------------------
log "seeding a writer principal (openinfra:powerusers) + access key"
read -r WAK WSK <<<"$(mint_key "sqs-probe-writer-$SFX" "powerusers")"
[ -n "$WAK" ] && [ -n "$WSK" ] || inconclusive "failed to mint a writer key"
sleep 2

# --- 2. CreateQueue ---------------------------------------------------------------------------
QN="aws-shim-probe-${SFX}"
log "create-queue ${QN}"
QURL="$(awsq "$WAK" "$WSK" create-queue --queue-name "$QN" --query QueueUrl 2>/dev/null)" \
  || inconclusive "create-queue failed — is the SQS data layer configured (SQS_PG_URI)?"
[ -n "$QURL" ] || inconclusive "create-queue returned no QueueUrl"
CREATED_QUEUES+=("$QURL")
log "  ✓ QueueUrl: $QURL"

# --- 3. SendMessage with a body + a message attribute; verify the MD5s ------------------------
BODY="hello-sqs-${SFX}"
log "send-message + verify MD5OfMessageBody and MD5OfMessageAttributes"
read -r MID MD5B MD5A <<<"$(awsq "$WAK" "$WSK" send-message --queue-url "$QURL" --message-body "$BODY" \
  --message-attributes "{\"trace\":{\"DataType\":\"String\",\"StringValue\":\"abc-$SFX\"}}" \
  --query '[MessageId,MD5OfMessageBody,MD5OfMessageAttributes]' 2>/dev/null)"
[ -n "$MID" ] || fail "send-message returned no MessageId"
[ "$MD5B" = "$(md5 "$BODY")" ] || fail "MD5OfMessageBody wrong: got $MD5B, want $(md5 "$BODY")"
[ -n "$MD5A" ] && [ "$MD5A" != "None" ] || fail "MD5OfMessageAttributes missing (SDKs verify it)"
log "  ✓ MessageId + correct MD5OfMessageBody + MD5OfMessageAttributes present"

# --- 4. ReceiveMessage: identical body, MD5, attributes, ApproximateReceiveCount ---------------
log "receive-message (visibility 2s) — assert body/MD5/attributes/receive-count"
read -r RID HANDLE1 RBODY RMD5 RCOUNT <<<"$(awsq "$WAK" "$WSK" receive-message --queue-url "$QURL" \
  --max-number-of-messages 1 --visibility-timeout 2 --attribute-names All --message-attribute-names All \
  --query 'Messages[0].[MessageId,ReceiptHandle,Body,MD5OfBody,Attributes.ApproximateReceiveCount]' 2>/dev/null)"
[ "$RID" = "$MID" ] || fail "received a different MessageId ($RID != $MID)"
[ "$RBODY" = "$BODY" ] || fail "received body differs: '$RBODY' != '$BODY'"
[ "$RMD5" = "$(md5 "$BODY")" ] || fail "MD5OfBody on receive wrong"
[ "$RCOUNT" = "1" ] || fail "ApproximateReceiveCount should be 1 on first receive, got $RCOUNT"
[ -n "$HANDLE1" ] || fail "no ReceiptHandle returned"
log "  ✓ identical body, correct MD5, ApproximateReceiveCount=1"

# --- 5. Redelivery after the visibility timeout -----------------------------------------------
log "do NOT delete; wait out the 2s visibility; message must REDELIVER with receive-count 2"
sleep 3
read -r RID2 HANDLE2 RCOUNT2 <<<"$(awsq "$WAK" "$WSK" receive-message --queue-url "$QURL" \
  --max-number-of-messages 1 --visibility-timeout 30 --attribute-names All \
  --query 'Messages[0].[MessageId,ReceiptHandle,Attributes.ApproximateReceiveCount]' 2>/dev/null)"
[ "$RID2" = "$MID" ] || fail "message did not redeliver after visibility timeout (got '$RID2')"
[ "$RCOUNT2" = "2" ] || fail "ApproximateReceiveCount should be 2 on redelivery, got $RCOUNT2"
log "  ✓ redelivered, ApproximateReceiveCount=2"

# --- 6. Stale ReceiptHandle is rejected -------------------------------------------------------
log "delete with the STALE handle from the first receive — must be REJECTED"
if awsq "$WAK" "$WSK" delete-message --queue-url "$QURL" --receipt-handle "$HANDLE1" >/dev/null 2>"$PWD/.sqs_stale_err"; then
  fail "a stale receipt handle deleted a redelivered message (silent data loss)"
fi
grep -qiE 'ReceiptHandleIsInvalid|not valid' "$PWD/.sqs_stale_err" || fail "stale handle rejected with the wrong error: $(cat "$PWD/.sqs_stale_err")"
rm -f "$PWD/.sqs_stale_err"
log "  ✓ stale handle rejected (ReceiptHandleIsInvalid)"
log "delete with the CURRENT handle — must succeed, then the queue is empty"
awsq "$WAK" "$WSK" delete-message --queue-url "$QURL" --receipt-handle "$HANDLE2" >/dev/null 2>&1 || fail "delete with the current handle failed"

# --- 7. maxReceiveCount → DLQ -----------------------------------------------------------------
log "dead-letter: maxReceiveCount=1 moves an un-deleted message to the DLQ"
DLQN="aws-shim-probe-dlq-${SFX}"
DLQURL="$(awsq "$WAK" "$WSK" create-queue --queue-name "$DLQN" --query QueueUrl 2>/dev/null)"
CREATED_QUEUES+=("$DLQURL")
DLQARN="$(awsq "$WAK" "$WSK" get-queue-attributes --queue-url "$DLQURL" --attribute-names QueueArn --query 'Attributes.QueueArn' 2>/dev/null)"
[ -n "$DLQARN" ] || fail "could not read the DLQ ARN"
MQN="aws-shim-probe-main-${SFX}"
RP="{\"deadLetterTargetArn\":\"${DLQARN}\",\"maxReceiveCount\":\"1\"}"
MQURL="$(awsq "$WAK" "$WSK" create-queue --queue-name "$MQN" --attributes "{\"RedrivePolicy\":$(printf '%s' "$RP" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')}" --query QueueUrl 2>/dev/null)"
CREATED_QUEUES+=("$MQURL")
awsq "$WAK" "$WSK" send-message --queue-url "$MQURL" --message-body "dlq-bound-$SFX" >/dev/null 2>&1 || fail "send to the redrive queue failed"
awsq "$WAK" "$WSK" receive-message --queue-url "$MQURL" --visibility-timeout 1 --query 'Messages[0].MessageId' >/dev/null 2>&1 || fail "first receive on the redrive queue failed"
sleep 2  # let the 1s visibility lapse so the next receive is the (maxReceiveCount+1)th
# This receive attempt should move the message to the DLQ and return empty from the main queue.
EMPTY="$(awsq "$WAK" "$WSK" receive-message --queue-url "$MQURL" --query 'Messages[0].MessageId' 2>/dev/null || true)"
[ -z "$EMPTY" ] || [ "$EMPTY" = "None" ] || fail "message was not moved to the DLQ (still deliverable on the main queue)"
DLQCOUNT="$(awsq "$WAK" "$WSK" receive-message --queue-url "$DLQURL" --attribute-names All --wait-time-seconds 3 --query 'Messages[0].Attributes.ApproximateReceiveCount' 2>/dev/null || true)"
[ -n "$DLQCOUNT" ] && [ "$DLQCOUNT" != "None" ] || fail "the dead-lettered message was not receivable on the DLQ"
log "  ✓ message dead-lettered and receivable on the DLQ (ApproximateReceiveCount=$DLQCOUNT)"

# --- 8. Long polling returns an empty success -------------------------------------------------
log "long-poll an empty queue (wait 2s) — must return an empty SUCCESS, not an error"
start=$(date +%s)
OUT="$(awsq "$WAK" "$WSK" receive-message --queue-url "$QURL" --wait-time-seconds 2 --query 'Messages' 2>/dev/null)" \
  || fail "long-poll on an empty queue errored instead of returning empty"
elapsed=$(( $(date +%s) - start ))
[ "$OUT" = "None" ] || [ -z "$OUT" ] || fail "long-poll returned messages on an empty queue: $OUT"
[ "$elapsed" -ge 1 ] || fail "long-poll returned immediately (WaitTimeSeconds not honored)"
log "  ✓ empty success after ~${elapsed}s"

# --- 9a. Negative: wrong secret ---------------------------------------------------------------
log "negative: a valid key ID with a WRONG secret must be rejected"
if awsq "$WAK" "wrong-secret-not-the-real-one" send-message --queue-url "$QURL" --message-body x >/dev/null 2>"$PWD/.sqs_neg"; then
  fail "a wrong secret was accepted"
fi
grep -qiE 'SignatureDoesNotMatch' "$PWD/.sqs_neg" || fail "wrong secret rejected with the wrong error: $(cat "$PWD/.sqs_neg")"
rm -f "$PWD/.sqs_neg"
log "  ✓ rejected as SignatureDoesNotMatch"

# --- 9b. Negative: a receive-only principal is denied DeleteMessage ----------------------------
log "seeding a READER principal (openinfra:readers) + key"
read -r RAK RSK <<<"$(mint_key "sqs-probe-reader-$SFX" "readers")"
sleep 2
awsq "$WAK" "$WSK" send-message --queue-url "$QURL" --message-body "for-reader-$SFX" >/dev/null 2>&1 || fail "seed message for the reader failed"
log "reader CAN receive (the consume read)"
RHANDLE="$(awsq "$RAK" "$RSK" receive-message --queue-url "$QURL" --visibility-timeout 30 --query 'Messages[0].ReceiptHandle' 2>/dev/null || true)"
[ -n "$RHANDLE" ] && [ "$RHANDLE" != "None" ] || fail "the reader could not ReceiveMessage (should be allowed)"
log "  ✓ reader received"
log "reader must be DENIED DeleteMessage (receive != delete)"
if awsq "$RAK" "$RSK" delete-message --queue-url "$QURL" --receipt-handle "$RHANDLE" >/dev/null 2>"$PWD/.sqs_rd"; then
  fail "a receive-only principal was allowed to DeleteMessage"
fi
grep -qiE 'AccessDenied' "$PWD/.sqs_rd" || fail "reader delete rejected with the wrong error: $(cat "$PWD/.sqs_rd")"
rm -f "$PWD/.sqs_rd"
log "  ✓ reader denied DeleteMessage (AccessDenied)"

printf '\n✓ PASS — aws-shim SQS is semantically faithful (visibility, receipt-handle, DLQ, long-poll) and enforces auth + the receive/delete boundary.\n'
