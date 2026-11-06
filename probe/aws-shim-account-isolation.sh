#!/usr/bin/env bash
# Compatibility probe: each account's resources are its own, as on AWS. Through the real AWS CLI:
#   - the management account's administrator creates a throwaway member account (Organizations
#     CreateAccount) and assumes its OrganizationAccountAccessRole (sts:AssumeRole), as AWS's management
#     account reaches a member account; GetCallerIdentity answers the member account;
#   - for each account-scoped front door, the management account and the member account each create a
#     resource of the SAME name; each reads back its own (its own value, an ARN or URL naming its own
#     account), each lists only its own, and neither reaches the other's by name;
#   - a front door that cannot keep accounts apart refuses the member account as AWS-shaped as it can
#     (Glue and Athena), and SES has no verified identity in a member account.
# Everything the probe made is removed on exit: its resources in both accounts, the throwaway account,
# its home namespace (only when this run created it), and the administrator's key.
#
# On-demand (a deployed shim with the Organizations front door and the Account kind, kubectl as a cluster
# operator). Exit 0 = pass, 1 = fail, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-account-isolation.sh
#   SERVICES="sqs sns ssm" …   # only these front doors (default: every one below)
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SETTLE="${IAM_SETTLE_SECONDS:-35}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
NAME="iso-$SFX"
TMP="$(mktemp -d)"
START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SERVICES="${SERVICES:-sqs sns kms secretsmanager ssm kinesis dynamodb logs events monitoring lambda glue athena ses apigateway ecs ecr s3 states rds}"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; FAILED=1; }
die()  { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }
FAILED=0

command -v aws >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v python3 >/dev/null || inconclusive "python3 is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
kubectl get crd accounts.organizations.openinfra.dev >/dev/null 2>&1 || inconclusive "the Account kind is not installed"

OWNER="iso-admin-$SFX"; AK=""; SK=""; KS=""; NEW_ACCOUNT=""; NEW_HOME=""
CLEAN=()   # commands run on exit, in reverse
cleanup() {
  local i
  for ((i=${#CLEAN[@]}-1; i>=0; i--)); do eval "${CLEAN[$i]}" >/dev/null 2>&1 || true; done
  [ -n "$NEW_ACCOUNT" ] && kubectl delete accounts.organizations.openinfra.dev "$NEW_ACCOUNT" --ignore-not-found --wait=false >/dev/null 2>&1
  if [ -n "$NEW_HOME" ]; then
    created="$(kubectl get ns "$NEW_HOME" -o jsonpath='{.metadata.creationTimestamp}' 2>/dev/null)"
    if [ -n "$created" ] && [[ "$created" > "$START" || "$created" == "$START" ]]; then
      kubectl delete ns "$NEW_HOME" --ignore-not-found --wait=false >/dev/null 2>&1
    fi
  fi
  [ -n "$KS" ] && kubectl -n "$SHIM_NS" delete secret "$KS" --ignore-not-found >/dev/null 2>&1
  kubectl -n "$USERS_NS" delete users.iam.openinfra.dev "$OWNER" --ignore-not-found >/dev/null 2>&1
  rm -rf "$TMP"
  return 0
}
trap cleanup EXIT

# --- 1. the management account's administrator, and a member account ---------------------------------
AK="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
SK="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
KS="iam-ak-$(printf '%s' "$AK" | sha256sum | cut -c1-40)"
printf 'apiVersion: iam.openinfra.dev/v1\nkind: User\nmetadata: { name: "%s", namespace: "%s" }\nspec: { displayName: "%s", groups: ["admins"], source: local }\n' \
  "$OWNER" "$USERS_NS" "$OWNER" | kubectl apply -f - >/dev/null || inconclusive "could not create the administrator"
kubectl -n "$SHIM_NS" create secret generic "$KS" --from-literal=accessKeyId="$AK" --from-literal=secretKey="$SK" \
  --from-literal=owner="$OWNER" >/dev/null || inconclusive "could not create the administrator's key"
M() { AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" "$@"; }
for _ in $(seq 1 20); do M sts get-caller-identity >/dev/null 2>&1 && break; sleep 3; done
sleep "$SETTLE"
MGMT="$(M sts get-caller-identity --query Account --output text 2>/dev/null)"
[ -n "$MGMT" ] || inconclusive "the administrator's key does not authenticate"

log "creating a member account and assuming its OrganizationAccountAccessRole"
car="$(M organizations create-account --email "$NAME@example.com" --account-name "$NAME" --query 'CreateAccountStatus.Id' --output text 2>"$TMP/err")" \
  || inconclusive "create-account: $(tr '\n' ' ' < "$TMP/err")"
for _ in $(seq 1 60); do
  read -r state acct < <(M organizations describe-create-account-status --create-account-request-id "$car" \
    --query 'CreateAccountStatus.[State,AccountId]' --output text 2>/dev/null)
  [ "$state" = SUCCEEDED ] && NEW_ACCOUNT="$acct" && break
  [ "$state" = FAILED ] && inconclusive "create-account FAILED"
  sleep 5
done
[ -n "$NEW_ACCOUNT" ] || inconclusive "the member account was not created"
NEW_HOME="$(kubectl get accounts.organizations.openinfra.dev "$NEW_ACCOUNT" -o jsonpath='{.spec.namespaces[0]}' 2>/dev/null)"
for _ in $(seq 1 60); do
  [ "$(kubectl -n "$NEW_HOME" get roles.iam.openinfra.dev organizationaccountaccessrole \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = True ] && break
  sleep 5
done
sleep "$SETTLE"
M sts assume-role --role-arn "arn:aws:iam::$NEW_ACCOUNT:role/OrganizationAccountAccessRole" \
  --role-session-name isolation --output json > "$TMP/session.json" 2>"$TMP/err" \
  || die "assume-role into the member account: $(tr '\n' ' ' < "$TMP/err")"
read -r MAK MSK MST < <(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["Credentials"]; print(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"])' "$TMP/session.json")
B() { AWS_ACCESS_KEY_ID="$MAK" AWS_SECRET_ACCESS_KEY="$MSK" AWS_SESSION_TOKEN="$MST" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" "$@"; }
who="$(B sts get-caller-identity --query Account --output text 2>/dev/null)"
[ "$who" = "$NEW_ACCOUNT" ] || die "the assumed session is account $who, want the member account $NEW_ACCOUNT"
log "  ✓ the session acts in member account $NEW_ACCOUNT (management account $MGMT)"

# has <file> <needle>: whether the CLI output holds needle.
has() { grep -qF -- "$2" "$1"; }

# --- 2. per front door: the same name in both accounts, each its own ----------------------------------
check_sqs() {
  M sqs create-queue --queue-name "$NAME" --query QueueUrl --output text > "$TMP/mq" 2>"$TMP/err" || { fail "sqs: management create-queue: $(cat "$TMP/err")"; return; }
  CLEAN+=("M sqs delete-queue --queue-url $(cat "$TMP/mq")")
  B sqs create-queue --queue-name "$NAME" --query QueueUrl --output text > "$TMP/bq" 2>"$TMP/err" || { fail "sqs: member create-queue: $(cat "$TMP/err")"; return; }
  CLEAN+=("B sqs delete-queue --queue-url $(cat "$TMP/bq")")
  has "$TMP/bq" "/$NEW_ACCOUNT/$NAME" || fail "sqs: the member's queue URL $(cat "$TMP/bq") does not name its account"
  [ "$(cat "$TMP/mq")" != "$(cat "$TMP/bq")" ] || fail "sqs: both accounts got the same queue URL"
  B sqs send-message --queue-url "$(cat "$TMP/bq")" --message-body member >/dev/null 2>&1 || fail "sqs: member send-message"
  M sqs receive-message --queue-url "$(cat "$TMP/mq")" --wait-time-seconds 1 --query 'Messages[].Body' --output text > "$TMP/mr" 2>/dev/null
  has "$TMP/mr" member && fail "sqs: the member's message arrived in the management account's queue"
  B sqs list-queues --query 'QueueUrls' --output text > "$TMP/bl" 2>/dev/null
  has "$TMP/bl" "$(cat "$TMP/mq")" && fail "sqs: the member listed the management account's queue"
  M sqs list-queues --queue-name-prefix "$NAME" --query 'QueueUrls' --output text > "$TMP/ml" 2>/dev/null
  has "$TMP/ml" "$NEW_ACCOUNT" && fail "sqs: the management account listed the member's queue"
  B sqs get-queue-url --queue-name "$NAME" --query QueueUrl --output text > "$TMP/bu" 2>/dev/null
  [ "$(cat "$TMP/bu")" = "$(cat "$TMP/bq")" ] || fail "sqs: the member's get-queue-url answered $(cat "$TMP/bu")"
}
check_sns() {
  M sns create-topic --name "$NAME" --query TopicArn --output text > "$TMP/mt" 2>"$TMP/err" || { fail "sns: management create-topic: $(cat "$TMP/err")"; return; }
  CLEAN+=("M sns delete-topic --topic-arn $(cat "$TMP/mt")")
  B sns create-topic --name "$NAME" --query TopicArn --output text > "$TMP/bt" 2>"$TMP/err" || { fail "sns: member create-topic: $(cat "$TMP/err")"; return; }
  CLEAN+=("B sns delete-topic --topic-arn $(cat "$TMP/bt")")
  [ "$(cat "$TMP/bt")" = "arn:aws:sns:$REGION:$NEW_ACCOUNT:$NAME" ] || fail "sns: the member's topic ARN is $(cat "$TMP/bt")"
  B sns list-topics --query 'Topics[].TopicArn' --output text > "$TMP/bl" 2>/dev/null
  has "$TMP/bl" "$(cat "$TMP/mt")" && fail "sns: the member listed the management account's topic"
  M sns list-topics --query 'Topics[].TopicArn' --output text > "$TMP/ml" 2>/dev/null
  has "$TMP/ml" "$(cat "$TMP/bt")" && fail "sns: the management account listed the member's topic"
}
check_secretsmanager() {
  M secretsmanager create-secret --name "$NAME" --secret-string mgmt-value >/dev/null 2>"$TMP/err" || { fail "secretsmanager: management create-secret: $(cat "$TMP/err")"; return; }
  CLEAN+=("M secretsmanager delete-secret --secret-id $NAME --force-delete-without-recovery")
  B secretsmanager create-secret --name "$NAME" --secret-string member-value --query ARN --output text > "$TMP/ba" 2>"$TMP/err" || { fail "secretsmanager: member create-secret: $(cat "$TMP/err")"; return; }
  CLEAN+=("B secretsmanager delete-secret --secret-id $NAME --force-delete-without-recovery")
  has "$TMP/ba" ":$NEW_ACCOUNT:secret:$NAME" || fail "secretsmanager: the member's secret ARN is $(cat "$TMP/ba")"
  [ "$(B secretsmanager get-secret-value --secret-id "$NAME" --query SecretString --output text 2>/dev/null)" = member-value ] || fail "secretsmanager: the member read back another value"
  [ "$(M secretsmanager get-secret-value --secret-id "$NAME" --query SecretString --output text 2>/dev/null)" = mgmt-value ] || fail "secretsmanager: the management account's secret changed"
}
check_ssm() {
  M ssm put-parameter --name "/$NAME/p" --value mgmt-value --type String >/dev/null 2>"$TMP/err" || { fail "ssm: management put-parameter: $(cat "$TMP/err")"; return; }
  CLEAN+=("M ssm delete-parameter --name /$NAME/p")
  B ssm put-parameter --name "/$NAME/p" --value member-value --type String >/dev/null 2>"$TMP/err" || { fail "ssm: member put-parameter: $(cat "$TMP/err")"; return; }
  CLEAN+=("B ssm delete-parameter --name /$NAME/p")
  [ "$(B ssm get-parameter --name "/$NAME/p" --query Parameter.Value --output text 2>/dev/null)" = member-value ] || fail "ssm: the member read back another value"
  [ "$(M ssm get-parameter --name "/$NAME/p" --query Parameter.Value --output text 2>/dev/null)" = mgmt-value ] || fail "ssm: the management account's parameter changed"
  B ssm get-parameter --name "/$NAME/p" --query Parameter.ARN --output text > "$TMP/ba" 2>/dev/null
  has "$TMP/ba" ":$NEW_ACCOUNT:parameter/$NAME/p" || fail "ssm: the member's parameter ARN is $(cat "$TMP/ba")"
  [ "$(B ssm get-parameters-by-path --path "/$NAME" --query 'length(Parameters)' --output text 2>/dev/null)" = 1 ] || fail "ssm: the member's path listing is not its one parameter"
}
check_kms() {
  B kms create-key --query KeyMetadata.Arn --output text > "$TMP/bk" 2>"$TMP/err" || { fail "kms: member create-key: $(cat "$TMP/err")"; return; }
  CLEAN+=("B kms schedule-key-deletion --key-id $(cat "$TMP/bk") --pending-window-in-days 7")
  has "$TMP/bk" ":$NEW_ACCOUNT:key/" || fail "kms: the member's key ARN is $(cat "$TMP/bk")"
  kid="$(sed 's|.*key/||' "$TMP/bk")"
  M kms describe-key --key-id "$kid" >/dev/null 2>&1 && fail "kms: the management account described the member's key by its id"
  B kms create-alias --alias-name "alias/$NAME" --target-key-id "$kid" >/dev/null 2>"$TMP/err" || fail "kms: member create-alias: $(cat "$TMP/err")"
  CLEAN+=("B kms delete-alias --alias-name alias/$NAME")
  M kms create-key --query KeyMetadata.KeyId --output text > "$TMP/mk" 2>/dev/null && CLEAN+=("M kms schedule-key-deletion --key-id $(cat "$TMP/mk") --pending-window-in-days 7")
  M kms create-alias --alias-name "alias/$NAME" --target-key-id "$(cat "$TMP/mk")" >/dev/null 2>"$TMP/err" || fail "kms: the same alias name in the management account: $(cat "$TMP/err")"
  CLEAN+=("M kms delete-alias --alias-name alias/$NAME")
}
check_kinesis() {
  M kinesis create-stream --stream-name "$NAME" --shard-count 1 >/dev/null 2>"$TMP/err" || { fail "kinesis: management create-stream: $(cat "$TMP/err")"; return; }
  CLEAN+=("M kinesis delete-stream --stream-name $NAME")
  B kinesis create-stream --stream-name "$NAME" --shard-count 1 >/dev/null 2>"$TMP/err" || { fail "kinesis: member create-stream: $(cat "$TMP/err")"; return; }
  CLEAN+=("B kinesis delete-stream --stream-name $NAME")
  B kinesis describe-stream-summary --stream-name "$NAME" --query StreamDescriptionSummary.StreamARN --output text > "$TMP/ba" 2>/dev/null
  has "$TMP/ba" ":$NEW_ACCOUNT:stream/$NAME" || fail "kinesis: the member's stream ARN is $(cat "$TMP/ba")"
}
check_dynamodb() {
  for who in M B; do
    $who dynamodb create-table --table-name "$NAME" --attribute-definitions AttributeName=k,AttributeType=S \
      --key-schema AttributeName=k,KeyType=HASH --billing-mode PAY_PER_REQUEST >/dev/null 2>"$TMP/err" || { fail "dynamodb: $who create-table: $(cat "$TMP/err")"; return; }
    CLEAN+=("$who dynamodb delete-table --table-name $NAME")
  done
  M dynamodb put-item --table-name "$NAME" --item '{"k":{"S":"x"},"v":{"S":"mgmt"}}' >/dev/null 2>&1 || fail "dynamodb: management put-item"
  B dynamodb put-item --table-name "$NAME" --item '{"k":{"S":"x"},"v":{"S":"member"}}' >/dev/null 2>&1 || fail "dynamodb: member put-item"
  [ "$(M dynamodb get-item --table-name "$NAME" --key '{"k":{"S":"x"}}' --query Item.v.S --output text 2>/dev/null)" = mgmt ] || fail "dynamodb: the management account's item changed"
  [ "$(B dynamodb get-item --table-name "$NAME" --key '{"k":{"S":"x"}}' --query Item.v.S --output text 2>/dev/null)" = member ] || fail "dynamodb: the member read another item"
  B dynamodb describe-table --table-name "$NAME" --query Table.TableArn --output text > "$TMP/ba" 2>/dev/null
  has "$TMP/ba" ":$NEW_ACCOUNT:table/$NAME" || fail "dynamodb: the member's table ARN is $(cat "$TMP/ba")"
}
check_logs() {
  for who in M B; do
    $who logs create-log-group --log-group-name "/$NAME" >/dev/null 2>"$TMP/err" || { fail "logs: $who create-log-group: $(cat "$TMP/err")"; return; }
    CLEAN+=("$who logs delete-log-group --log-group-name /$NAME")
  done
  B logs describe-log-groups --log-group-name-prefix "/$NAME" --query 'logGroups[].arn' --output text > "$TMP/ba" 2>/dev/null
  has "$TMP/ba" ":$NEW_ACCOUNT:log-group:/$NAME" || fail "logs: the member's log group ARN is $(cat "$TMP/ba")"
  has "$TMP/ba" ":$MGMT:" && fail "logs: the member listed the management account's log group"
}
check_events() {
  for who in M B; do
    $who events put-rule --name "$NAME" --schedule-expression 'rate(1 day)' --state DISABLED --query RuleArn --output text > "$TMP/$who.rule" 2>"$TMP/err" || { fail "events: $who put-rule: $(cat "$TMP/err")"; return; }
    CLEAN+=("$who events delete-rule --name $NAME")
  done
  has "$TMP/B.rule" ":$NEW_ACCOUNT:rule/$NAME" || fail "events: the member's rule ARN is $(cat "$TMP/B.rule")"
  B events list-rules --name-prefix "$NAME" --query 'Rules[].Arn' --output text > "$TMP/bl" 2>/dev/null
  has "$TMP/bl" ":$MGMT:" && fail "events: the member listed the management account's rule"
}
check_monitoring() {
  for who in M B; do
    $who cloudwatch put-metric-alarm --alarm-name "$NAME" --namespace "Iso/$SFX" --metric-name m --statistic Sum \
      --period 60 --evaluation-periods 1 --threshold 1 --comparison-operator GreaterThanThreshold >/dev/null 2>"$TMP/err" || { fail "cloudwatch: $who put-metric-alarm: $(cat "$TMP/err")"; return; }
    CLEAN+=("$who cloudwatch delete-alarms --alarm-names $NAME")
  done
  B cloudwatch describe-alarms --alarm-names "$NAME" --query 'MetricAlarms[].AlarmArn' --output text > "$TMP/ba" 2>/dev/null
  has "$TMP/ba" ":$NEW_ACCOUNT:alarm:$NAME" || fail "cloudwatch: the member's alarm ARN is $(cat "$TMP/ba")"
  has "$TMP/ba" ":$MGMT:" && fail "cloudwatch: the member described the management account's alarm"
}
check_lambda() {
  B lambda list-functions --query 'Functions[].FunctionArn' --output text > "$TMP/bl" 2>"$TMP/err" || { fail "lambda: member list-functions: $(cat "$TMP/err")"; return; }
  has "$TMP/bl" ":$MGMT:" && fail "lambda: the member listed the management account's functions"
  return 0
}
check_glue() {
  B glue get-databases >/dev/null 2>"$TMP/err" && { fail "glue: a member account read the management account's catalog"; return; }
  log "    glue refuses the member account: $(head -c 160 "$TMP/err" | tr '\n' ' ')"
}
check_athena() {
  B athena list-work-groups >/dev/null 2>"$TMP/err" && { fail "athena: a member account reached the management account's query engine"; return; }
  log "    athena refuses the member account: $(head -c 160 "$TMP/err" | tr '\n' ' ')"
}
check_ses() {
  B ses send-email --from "probe@example.com" --to probe@example.com --subject x --text x \
    >/dev/null 2>"$TMP/err" && { fail "ses: a member account sent as an identity it has not verified"; return; }
  has "$TMP/err" "not verified" || has "$TMP/err" "MessageRejected" || has "$TMP/err" "AccessDenied" || fail "ses: the member's refusal is not AWS's: $(head -c 200 "$TMP/err")"
}

check_apigateway() {
  for who in M B; do
    $who apigateway create-rest-api --name "$NAME" --query id --output text > "$TMP/$who.api" 2>"$TMP/err" || { fail "apigateway: $who create-rest-api: $(cat "$TMP/err")"; return; }
    CLEAN+=("$who apigateway delete-rest-api --rest-api-id $(cat "$TMP/$who.api")")
  done
  B apigateway get-rest-api --rest-api-id "$(cat "$TMP/M.api")" >/dev/null 2>"$TMP/err" && fail "apigateway: the member read the management account's API by its id"
  B apigateway get-rest-apis --query 'items[].id' --output text > "$TMP/bl" 2>/dev/null
  has "$TMP/bl" "$(cat "$TMP/M.api")" && fail "apigateway: the member listed the management account's API"
  has "$TMP/bl" "$(cat "$TMP/B.api")" || fail "apigateway: the member does not list its own API"
  M apigateway get-rest-apis --query 'items[].id' --output text > "$TMP/ml" 2>/dev/null
  has "$TMP/ml" "$(cat "$TMP/B.api")" && fail "apigateway: the management account listed the member's API"
  return 0
}
check_ecs() {
  for who in M B; do
    $who ecs create-cluster --cluster-name "$NAME" --query cluster.clusterArn --output text > "$TMP/$who.cl" 2>"$TMP/err" || { fail "ecs: $who create-cluster: $(cat "$TMP/err")"; return; }
    CLEAN+=("$who ecs delete-cluster --cluster $NAME")
    $who ecs register-task-definition --family "$NAME" --container-definitions '[{"name":"c","image":"busybox","memory":64,"essential":true}]' \
      --query taskDefinition.taskDefinitionArn --output text > "$TMP/$who.td" 2>"$TMP/err" || { fail "ecs: $who register-task-definition: $(cat "$TMP/err")"; return; }
    CLEAN+=("$who ecs deregister-task-definition --task-definition $NAME:1")
  done
  [ "$(cat "$TMP/B.cl")" = "arn:aws:ecs:$REGION:$NEW_ACCOUNT:cluster/$NAME" ] || fail "ecs: the member's cluster ARN is $(cat "$TMP/B.cl")"
  has "$TMP/B.td" ":$NEW_ACCOUNT:task-definition/$NAME:1" || fail "ecs: the member's first revision is $(cat "$TMP/B.td") (a revision counts within its account)"
  has "$TMP/M.td" ":$NAME:1" || fail "ecs: the management account's first revision is $(cat "$TMP/M.td")"
  B ecs list-clusters --query 'clusterArns' --output text > "$TMP/bl" 2>/dev/null
  has "$TMP/bl" "$(cat "$TMP/M.cl")" && fail "ecs: the member listed the management account's cluster"
  M ecs list-clusters --query 'clusterArns' --output text > "$TMP/ml" 2>/dev/null
  has "$TMP/ml" "$(cat "$TMP/B.cl")" && fail "ecs: the management account listed the member's cluster"
  return 0
}
check_ecr() {
  for who in M B; do
    $who ecr create-repository --repository-name "$NAME" --query repository.[repositoryArn,repositoryUri] --output text > "$TMP/$who.repo" 2>"$TMP/err" || { fail "ecr: $who create-repository: $(cat "$TMP/err")"; return; }
    CLEAN+=("$who ecr delete-repository --repository-name $NAME --force")
  done
  has "$TMP/B.repo" ":$NEW_ACCOUNT:repository/$NAME" || fail "ecr: the member's repository ARN: $(cat "$TMP/B.repo")"
  has "$TMP/B.repo" "/$NEW_ACCOUNT/$NAME" || fail "ecr: the member's repository URI does not name its registry: $(cat "$TMP/B.repo")"
  B ecr describe-repositories --query 'repositories[].repositoryArn' --output text > "$TMP/bl" 2>/dev/null
  has "$TMP/bl" ":$MGMT:repository/$NAME" && fail "ecr: the member listed the management account's repository"
  return 0
}
check_s3() {
  M s3api create-bucket --bucket "$NAME-mg" >/dev/null 2>"$TMP/err" || { fail "s3: management create-bucket: $(cat "$TMP/err")"; return; }
  CLEAN+=("M s3api delete-bucket --bucket $NAME-mg")
  B s3api create-bucket --bucket "$NAME-mb" >/dev/null 2>"$TMP/err" || { fail "s3: member create-bucket: $(cat "$TMP/err")"; return; }
  CLEAN+=("B s3api delete-bucket --bucket $NAME-mb")
  for _ in $(seq 1 40); do M s3api head-bucket --bucket "$NAME-mg" >/dev/null 2>&1 && B s3api head-bucket --bucket "$NAME-mb" >/dev/null 2>&1 && break; sleep 3; done
  B s3api create-bucket --bucket "$NAME-mg" >/dev/null 2>"$TMP/err" && fail "s3: the member made a bucket of the management account's name"
  B s3api list-buckets --query 'Buckets[].Name' --output text > "$TMP/bl" 2>/dev/null
  has "$TMP/bl" "$NAME-mb" || fail "s3: the member does not list its own bucket"
  has "$TMP/bl" "$NAME-mg" && fail "s3: the member listed the management account's bucket"
  M s3api list-buckets --query 'Buckets[].Name' --output text > "$TMP/ml" 2>/dev/null
  has "$TMP/ml" "$NAME-mb" && fail "s3: the management account listed the member's bucket"
  printf member > "$TMP/obj"
  B s3api put-object --bucket "$NAME-mg" --key k --body "$TMP/obj" >/dev/null 2>&1 && fail "s3: the member wrote into the management account's bucket"
  B s3api put-object --bucket "$NAME-mb" --key k --body "$TMP/obj" >/dev/null 2>"$TMP/err" || fail "s3: the member could not write its own bucket: $(head -c 200 "$TMP/err")"
  CLEAN+=("B s3api delete-object --bucket $NAME-mb --key k")
  return 0
}
check_states() {
  local trust='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
  local def='{"StartAt":"P","States":{"P":{"Type":"Pass","Result":"ok","End":true}}}'
  for who in M B; do
    $who iam create-role --role-name "$NAME-sfn" --assume-role-policy-document "$trust" --query Role.Arn --output text > "$TMP/$who.role" 2>"$TMP/err" || { fail "states: $who create-role: $(cat "$TMP/err")"; return; }
    CLEAN+=("$who iam delete-role --role-name $NAME-sfn")
  done
  sleep "$SETTLE"
  for who in M B; do
    $who stepfunctions create-state-machine --name "$NAME" --definition "$def" --role-arn "$(cat "$TMP/$who.role")" \
      --query stateMachineArn --output text > "$TMP/$who.sm" 2>"$TMP/err" || { fail "states: $who create-state-machine: $(cat "$TMP/err")"; return; }
    CLEAN+=("$who stepfunctions delete-state-machine --state-machine-arn $(cat "$TMP/$who.sm")")
  done
  [ "$(cat "$TMP/B.sm")" = "arn:aws:states:$REGION:$NEW_ACCOUNT:stateMachine:$NAME" ] || fail "states: the member's state machine ARN is $(cat "$TMP/B.sm")"
  B stepfunctions describe-state-machine --state-machine-arn "$(cat "$TMP/M.sm")" >/dev/null 2>&1 && fail "states: the member described the management account's state machine"
  B stepfunctions list-state-machines --query 'stateMachines[].stateMachineArn' --output text > "$TMP/bl" 2>/dev/null
  has "$TMP/bl" "$(cat "$TMP/M.sm")" && fail "states: the member listed the management account's state machine"
  B stepfunctions start-execution --state-machine-arn "$(cat "$TMP/B.sm")" --query executionArn --output text > "$TMP/bx" 2>"$TMP/err" || { fail "states: member start-execution: $(cat "$TMP/err")"; return; }
  st=""
  for _ in $(seq 1 30); do
    st="$(B stepfunctions describe-execution --execution-arn "$(cat "$TMP/bx")" --query status --output text 2>/dev/null)"
    [ "$st" = SUCCEEDED ] || [ "$st" = FAILED ] && break
    sleep 2
  done
  [ "$st" = SUCCEEDED ] || fail "states: the member's execution ended $st"
  return 0
}
check_rds() {
  B rds create-db-instance --db-instance-identifier "$NAME" --engine postgres --db-instance-class db.t3.micro \
    --allocated-storage 1 --master-username probe --master-user-password "Pw$SFX$SFX" \
    --query DBInstance.DBInstanceArn --output text > "$TMP/ba" 2>"$TMP/err" || { fail "rds: member create-db-instance: $(cat "$TMP/err")"; return; }
  CLEAN+=("B rds delete-db-instance --db-instance-identifier $NAME --skip-final-snapshot")
  [ "$(cat "$TMP/ba")" = "arn:aws:rds:$REGION:$NEW_ACCOUNT:db:$NAME" ] || fail "rds: the member's DBInstanceArn is $(cat "$TMP/ba")"
  M rds describe-db-instances --db-instance-identifier "$NAME" >/dev/null 2>&1 && fail "rds: the management account described the member's DB instance"
  B rds describe-db-instances --query 'DBInstances[].DBInstanceArn' --output text > "$TMP/bl" 2>/dev/null
  has "$TMP/bl" ":$MGMT:" && fail "rds: the member listed the management account's DB instances"
  has "$TMP/bl" "$(cat "$TMP/ba")" || fail "rds: the member does not list its own DB instance"
  B rds delete-db-instance --db-instance-identifier "$NAME" --skip-final-snapshot >/dev/null 2>"$TMP/err" || fail "rds: member delete-db-instance: $(cat "$TMP/err")"
  return 0
}

for s in $SERVICES; do
  log "$s: the same name in both accounts"
  before=$FAILED; FAILED=0
  "check_$s"
  [ "$FAILED" = 0 ] && log "  ✓ $s keeps each account's resources apart"
  [ "$FAILED" = 1 ] || FAILED=$before
done

[ "$FAILED" = 0 ] || exit 1
log "✓ PASS — each account's resources are its own across: $SERVICES"
