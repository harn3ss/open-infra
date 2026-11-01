#!/usr/bin/env bash
# Probe: a CloudFormation stack's queue, topic, parameter and key are usable through the SQS, SNS, SSM
# and KMS APIs (#347 J).
#
# It deploys, through the aws-shim CloudFormation front door, a stack with an SQS queue (+ a dead-letter
# queue it redrives to), an SNS topic subscribed to the queue, an UNNAMED SSM parameter, and a KMS key
# with an alias; then, with the same caller's key and the stack's Outputs:
#   - sqs get-queue-url finds the queue under the URL the stack reports; its RedrivePolicy is set
#   - sns publish to the stack's TopicArn lands the message in the queue (receive-message); the stack's
#     AWS::SQS::QueuePolicy is the queue's Policy, and a second subscribed topic it does not allow delivers
#     nothing
#   - ssm get-parameter reads the parameter under the name CloudFormation generated
#   - kms encrypt/decrypt round-trips through the stack's alias, and list-keys lists the key
#   - delete-stack removes the queue, topic and parameter, and schedules the key for deletion
#
# On-demand (needs a deployed shim with the CloudFormation, SQS, SNS, SSM and KMS front doors).
# Exit 0 = pass, 1 = a real failure, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-cfn-data-services.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
STACK="cfndata-$SFX"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v jq      >/dev/null || inconclusive "jq is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

CREATED_USERS=(); CREATED_KEYS=(); AK=""; SK=""
a() { AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --output json "$@"; }

cleanup() {
  [ -n "$AK" ] && a cloudformation delete-stack --stack-name "$STACK" >/dev/null 2>&1 || true
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for k in "${CREATED_KEYS[@]:-}";  do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
  rm -rf "$TMP"
}
trap cleanup EXIT

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }
owner="cfndata-admin-$SFX"
AK="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
SK="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "${owner}", namespace: "${USERS_NS}" }
spec: { displayName: "${owner}", groups: ["admins"], source: local }
YAML
CREATED_USERS+=("$owner")
kubectl -n "$SHIM_NS" create secret generic "$(secret_name "$AK")" --from-literal=accessKeyId="$AK" --from-literal=secretKey="$SK" --from-literal=owner="$owner" >/dev/null
CREATED_KEYS+=("$(secret_name "$AK")")
sleep 20 # let the new key reach the shim's key cache

cat > "$TMP/stack.json" <<JSON
{
  "Resources": {
    "DLQ":   { "Type": "AWS::SQS::Queue" },
    "Queue": { "Type": "AWS::SQS::Queue", "Properties": { "VisibilityTimeout": 30,
               "RedrivePolicy": { "deadLetterTargetArn": { "Fn::GetAtt": ["DLQ", "Arn"] }, "maxReceiveCount": 5 } } },
    "Topic": { "Type": "AWS::SNS::Topic", "Properties": {
               "Subscription": [ { "Protocol": "sqs", "Endpoint": { "Fn::GetAtt": ["Queue", "Arn"] } } ] } },
    "Other": { "Type": "AWS::SNS::Topic", "Properties": {
               "Subscription": [ { "Protocol": "sqs", "Endpoint": { "Fn::GetAtt": ["Queue", "Arn"] } } ] } },
    "QueuePolicy": { "Type": "AWS::SQS::QueuePolicy", "Properties": { "Queues": [ { "Ref": "Queue" } ],
               "PolicyDocument": { "Version": "2012-10-17", "Statement": [ { "Effect": "Allow",
                 "Principal": { "Service": "sns.amazonaws.com" }, "Action": "sqs:SendMessage",
                 "Resource": { "Fn::GetAtt": ["Queue", "Arn"] },
                 "Condition": { "ArnEquals": { "aws:SourceArn": { "Ref": "Topic" } } } } ] } } },
    "Param": { "Type": "AWS::SSM::Parameter", "Properties": { "Type": "String", "Value": "hello-$SFX" } },
    "Key":   { "Type": "AWS::KMS::Key", "Properties": { "Description": "probe key", "PendingWindowInDays": 7 } },
    "Alias": { "Type": "AWS::KMS::Alias", "Properties": { "AliasName": "alias/cfndata-$SFX", "TargetKeyId": { "Ref": "Key" } } }
  },
  "Outputs": {
    "QueueUrl":  { "Value": { "Ref": "Queue" } },
    "QueueArn":  { "Value": { "Fn::GetAtt": ["Queue", "Arn"] } },
    "TopicArn":  { "Value": { "Ref": "Topic" } },
    "OtherArn":  { "Value": { "Ref": "Other" } },
    "ParamName": { "Value": { "Ref": "Param" } },
    "KeyId":     { "Value": { "Ref": "Key" } }
  }
}
JSON

log "create-stack $STACK (queue + DLQ, topic → queue, unnamed parameter, key + alias)"
a cloudformation create-stack --stack-name "$STACK" --template-body "file://$TMP/stack.json" >/dev/null \
  || fail "create-stack was refused"
st=""
for _ in $(seq 1 60); do
  st="$(a cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
  case "$st" in CREATE_COMPLETE|*FAILED|ROLLBACK*) break ;; esac
  sleep 5
done
[ "$st" = CREATE_COMPLETE ] || fail "the stack is $st, not CREATE_COMPLETE: $(a cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatusReason' --output text 2>/dev/null)"
out() { a cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue | [0]" --output text; }
QURL="$(out QueueUrl)"; QARN="$(out QueueArn)"; TARN="$(out TopicArn)"; PNAME="$(out ParamName)"; KEYID="$(out KeyId)"
for v in QURL QARN TARN PNAME KEYID; do [ -n "${!v}" ] && [ "${!v}" != None ] || fail "Output $v did not resolve"; done
log "  ✓ CREATE_COMPLETE; Outputs: QueueUrl=$QURL TopicArn=$TARN ParamName=$PNAME KeyId=$KEYID"

QNAME="${QURL##*/}"
got="$(a sqs get-queue-url --queue-name "$QNAME" --query QueueUrl --output text 2>&1)" || fail "sqs get-queue-url $QNAME: $got"
[ "$got" = "$QURL" ] || fail "sqs get-queue-url returned $got, the stack reports $QURL"
rp="$(a sqs get-queue-attributes --queue-url "$QURL" --attribute-names RedrivePolicy --query 'Attributes.RedrivePolicy' --output text)"
printf '%s' "$rp" | jq -e '.maxReceiveCount == 5' >/dev/null 2>&1 || fail "the queue's RedrivePolicy is $rp"
log "  ✓ the SQS API serves the stack's queue under its URL, with its RedrivePolicy"

a sns publish --topic-arn "$TARN" --message "order-$SFX" >/dev/null || fail "sns publish to the stack's TopicArn was refused"
body=""
for _ in 1 2 3 4 5; do
  body="$(a sqs receive-message --queue-url "$QURL" --wait-time-seconds 2 --query 'Messages[0].Body' --output text 2>/dev/null || true)"
  [ -n "$body" ] && [ "$body" != None ] && break
done
printf '%s' "$body" | jq -e --arg m "order-$SFX" '.Message == $m' >/dev/null 2>&1 || fail "the topic did not deliver to the queue (got: $body)"
log "  ✓ sns publish to the stack's topic arrives in the stack's queue"

pol="$(a sqs get-queue-attributes --queue-url "$QURL" --attribute-names Policy --query 'Attributes.Policy' --output text)"
printf '%s' "$pol" | jq -e --arg t "$TARN" '.Statement[0].Condition.ArnEquals["aws:SourceArn"] == $t' >/dev/null 2>&1 \
  || fail "the queue's Policy is not the stack's QueuePolicy (got: $pol)"
OARN="$(out OtherArn)"
a sns publish --topic-arn "$OARN" --message "other-$SFX" >/dev/null || fail "sns publish to the second topic was refused"
for _ in 1 2 3; do
  b="$(a sqs receive-message --queue-url "$QURL" --wait-time-seconds 2 --query 'Messages[].Body' --output text 2>/dev/null || true)"
  case "$b" in *"other-$SFX"*) fail "the queue policy allows only the first topic, but the second one delivered";; esac
done
log "  ✓ the stack's QueuePolicy is the queue's Policy, and a topic it does not allow delivers nothing"

val="$(a ssm get-parameter --name "$PNAME" --query Parameter.Value --output text 2>&1)" || fail "ssm get-parameter $PNAME: $val"
[ "$val" = "hello-$SFX" ] || fail "the parameter's value is $val"
case "$PNAME" in "$STACK-Param-"*) ;; *) fail "the unnamed parameter is named $PNAME, not CloudFormation's <stack>-<logical id>-<suffix>";; esac
log "  ✓ ssm get-parameter reads the stack's unnamed parameter ($PNAME)"

a kms list-keys --query 'Keys[].KeyId' --output text | tr '\t' '\n' | grep -qx "$KEYID" || fail "kms list-keys does not list the stack's key $KEYID"
ct="$(a kms encrypt --key-id "alias/cfndata-$SFX" --plaintext "$(printf secret | base64)" --query CiphertextBlob --output text)" \
  || fail "kms encrypt through the stack's alias failed"
pt="$(a kms decrypt --ciphertext-blob "$ct" --query Plaintext --output text | base64 -d)"
[ "$pt" = secret ] || fail "kms decrypt returned $pt"
log "  ✓ kms lists the stack's key and encrypts/decrypts through its alias"

log "delete-stack $STACK"
a cloudformation delete-stack --stack-name "$STACK" >/dev/null || fail "delete-stack was refused"
for _ in $(seq 1 60); do
  a cloudformation describe-stacks --stack-name "$STACK" >/dev/null 2>&1 || break
  st="$(a cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
  [ "$st" = DELETE_FAILED ] && fail "delete-stack failed: $(a cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatusReason' --output text)"
  sleep 3
done
a sqs get-queue-url --queue-name "$QNAME" >/dev/null 2>&1 && fail "the queue survived delete-stack"
a sns publish --topic-arn "$TARN" --message x >/dev/null 2>&1 && fail "the topic survived delete-stack"
a ssm get-parameter --name "$PNAME" >/dev/null 2>&1 && fail "the parameter survived delete-stack"
ks="$(a kms describe-key --key-id "$KEYID" --query KeyMetadata.KeyState --output text 2>/dev/null || true)"
[ "$ks" = PendingDeletion ] || fail "the key is $ks after delete-stack, not PendingDeletion"
a kms describe-key --key-id "alias/cfndata-$SFX" >/dev/null 2>&1 && fail "the alias survived delete-stack"
log "  ✓ delete-stack removed the queue, topic, parameter and alias, and scheduled the key for deletion"

echo "✓ PASS — a stack's queue, topic, parameter and key are usable through the SQS, SNS, SSM and KMS APIs by the names and ARNs its Outputs report, and delete-stack removes them"
