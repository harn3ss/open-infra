#!/usr/bin/env bash
# One authorization plane, proven at both doors: the same principal gets the same IAM decision through the
# console and through the AWS API (the aws-shim), for every served service — an allow and a deny each.
#
# The principal is a throwaway User whose only authority is an inline policy granting each service's list
# action (s3:ListAllMyBuckets, sqs:ListQueues, iam:ListUsers, …). Per service it asks, at both doors:
#   allow — the list action the policy grants;
#   deny  — another action of the same service the policy does not grant (a read, or a mutation of a
#           resource the probe makes up), so a wrong "allow" changes nothing.
# A pair whose doors disagree, or that disagrees with the policy, fails.
#
# Needs IAM policy to decide for the principal: the console and shim in IAM_AUTHZ=shadow with
# PRINCIPAL_MODE=canary (the throwaway User is labelled for the canary), or IAM_AUTHZ=enforce.
# Exit 0 = pass, 1 = fail, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 [CONSOLE_ENDPOINT=http://localhost:18080] PRINCIPAL_MODE=canary ./probe/iam-parity.sh
set -uo pipefail
# shellcheck source=probe/iam-lib.sh
. "$(dirname "$0")/iam-lib.sh"
trap iamp_cleanup EXIT
iamp_require

NS="${CLAIM_NAMESPACE:-default}"      # a tenant namespace of the management account
K8S="/api/k8s/apis/openinfra.dev/v1/namespaces/$NS"
NOPE="iam-parity-nope-$SFX"

# service | allow action | console allow (METHOD path) | shim allow (aws args) | deny action | console deny | shim deny
CASES=$(cat <<EOF
s3|s3:ListAllMyBuckets|GET /api/buckets|s3api list-buckets|s3:ListBucket|GET /api/buckets/$NOPE/objects|s3api list-objects-v2 --bucket $NOPE
sqs|sqs:ListQueues|GET /api/queues|sqs list-queues|sqs:ReceiveMessage|GET /api/queues/$NOPE/messages|sqs receive-message --queue-url $ENDPOINT/$ACCOUNT/$NOPE
iam|iam:ListUsers|GET /api/iam/users|iam list-users|iam:ListRoles|GET /api/iam/roles|iam list-roles
kms|kms:ListKeys|GET /api/encryption/keys|kms list-keys|kms:DescribeKey|GET $K8S/encryptionkeys/$NOPE|kms describe-key --key-id 00000000-0000-4000-8000-$SFX$SFX
dynamodb|dynamodb:ListTables|GET $K8S/tables|dynamodb list-tables|dynamodb:DescribeTable|GET $K8S/tables/$NOPE|dynamodb describe-table --table-name $NOPE
lambda|lambda:ListFunctions|GET $K8S/functions|lambda list-functions|lambda:GetFunction|GET /api/functions/$NS/$NOPE/code|lambda get-function --function-name $NOPE
ssm|ssm:DescribeParameters|GET $K8S/parameters|ssm describe-parameters|ssm:GetParameter|GET $K8S/parameters/$NOPE|ssm get-parameter --name /$NOPE
states|states:ListStateMachines|GET $K8S/statemachines|stepfunctions list-state-machines|states:DescribeStateMachine|GET $K8S/statemachines/$NOPE|stepfunctions describe-state-machine --state-machine-arn arn:aws:states:$REGION:$ACCOUNT:stateMachine:$NOPE
kinesis|kinesis:ListStreams|GET $K8S/streams|kinesis list-streams|kinesis:DescribeStream|GET $K8S/streams/$NOPE|kinesis describe-stream --stream-name $NOPE
cognito-idp|cognito-idp:ListUserPools|GET $K8S/userpools|cognito-idp list-user-pools --max-results 10|cognito-idp:DescribeUserPool|GET $K8S/userpools/$NOPE|cognito-idp describe-user-pool --user-pool-id ${REGION}_nope$SFX
appsync|appsync:ListGraphqlApis|GET $K8S/graphqlapis|appsync list-graphql-apis|appsync:GetGraphqlApi|GET $K8S/graphqlapis/$NOPE|appsync get-graphql-api --api-id $NOPE
cloudfront|cloudfront:ListDistributions|GET $K8S/staticsites|cloudfront list-distributions|cloudfront:GetDistribution|GET $K8S/staticsites/$NOPE|cloudfront get-distribution --id E$SFX
ec2|ec2:DescribeInstances|GET $K8S/virtualmachines|ec2 describe-instances|ec2:DescribeVolumes|GET $K8S/volumes|ec2 describe-volumes
rds|rds:DescribeDBSnapshots|GET /api/snapshots|rds describe-db-snapshots|rds:DeleteDBSnapshot|DELETE /api/snapshots?id=$NOPE|rds delete-db-snapshot --db-snapshot-identifier $NOPE
EOF
)
[ -n "${SERVICES:-}" ] && CASES="$(printf '%s\n' "$CASES" | awk -F'|' -v want=",${SERVICES}," 'index(want, ","$1",")')"

ALLOWS="$(printf '%s\n' "$CASES" | awk -F'|' 'NF {printf "%s\"%s\"", (n++ ? "," : ""), $2}')"
DOC="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[${ALLOWS}],\"Resource\":\"*\"}]}"

USER="iam-parity-$SFX"
log "principal $USER: no group, one inline policy allowing $(printf '%s\n' "$CASES" | grep -c .) list actions${PRINCIPAL_MODE:+ (PRINCIPAL_MODE=$PRINCIPAL_MODE)}"
iamp_user "$USER" "" "$DOC"
JAR="$PROBE_TMP/jar"
iamp_login "$USER" "$U_PW" "$JAR"
iamp_settle   # the shim's policy world picks the new principal up

failures=0
check() { # <service> <kind> <action> <want> <console method+path> <shim args>
  local svc="$1" kind="$2" action="$3" want="$4" cpath="$5" sargs="$6" c s
  # shellcheck disable=SC2086
  c="$(console_decision "$JAR" ${cpath%% *} "${cpath#* }" "$action")"
  # shellcheck disable=SC2086
  s="$(shim_decision "$U_AK" "$U_SK" $sargs)"
  decided "$c"; decided "$s"
  if [ "$c" = "$want" ] && [ "$s" = "$want" ]; then
    log "  ✓ $svc $kind $action: console $c, API $s"
  else
    printf '  ✗ %s %s %s: want %s — console %s (%s), API %s (aws %s)\n' "$svc" "$kind" "$action" "$want" "$c" "$cpath" "$s" "$sargs" >&2
    failures=$((failures + 1))
  fi
}
while IFS='|' read -r svc aact acon ashim dact dcon dshim; do
  [ -n "$svc" ] || continue
  check "$svc" allow "$aact" allow "$acon" "$ashim"
  check "$svc" deny  "$dact" deny  "$dcon" "$dshim"
done <<< "$CASES"

[ "$failures" = 0 ] || fail "$failures decision(s) differ between the console and the API, or from the policy"
log "✓ PASS — the same principal gets the same IAM decision through the console and the API, allow and deny, for $(printf '%s\n' "$CASES" | grep -c .) services"
