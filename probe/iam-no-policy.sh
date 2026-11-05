#!/usr/bin/env bash
# A principal with no policy can do nothing, as on AWS: every console route and every AWS service the
# shim fronts denies it.
#
# The principal is a throwaway User in no group with no attached or inline policy. It signs in (sign-in
# itself is allowed, as on AWS, and /api/auth/me answers), then:
#   console — every route in the console's route table with a fixed IAM action (read from
#             console-api/cmd/server/routes.go, so a new route is covered without editing this probe),
#             path parameters filled with made-up names, plus the Kubernetes proxy for a claim list, a
#             claim delete, a Secret read and a pod list: each must be the gate's 403 naming its action;
#   API     — one call per service in the shim's router (probe/registry/shim-router.json): each must
#             be AWS's access-denied. sts:GetCallerIdentity is the exception AWS makes (any principal may
#             ask who it is), so it must be allowed.
#
# Needs IAM policy to decide for the principal (IAM_AUTHZ=shadow + PRINCIPAL_MODE=canary, or enforce).
# Exit 0 = pass, 1 = fail, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 PRINCIPAL_MODE=canary ./probe/iam-no-policy.sh
set -uo pipefail
# shellcheck source=probe/iam-lib.sh
. "$(dirname "$0")/iam-lib.sh"
trap iamp_cleanup EXIT
iamp_require

NOPE="iam-nopol-nope-$SFX"
ROUTES="$HERE_REPO/console-api/cmd/server/routes.go"
[ -f "$ROUTES" ] || inconclusive "the console route table ($ROUTES) is not in this checkout"

USER="iam-nopol-$SFX"
log "principal $USER: no group, no policy${PRINCIPAL_MODE:+ (PRINCIPAL_MODE=$PRINCIPAL_MODE)}"
iamp_user "$USER" "" ""
JAR="$PROBE_TMP/jar"
iamp_login "$USER" "$U_PW" "$JAR"
sleep "${KEY_SETTLE_SECONDS:-15}"

failures=0; checked=0

# --- console: every fixed-action route, plus the proxy -----------------------------------------------
iamp_console_routes "$ROUTES" "$NOPE" > "$PROBE_TMP/routes.txt"
n_routes="$(grep -c . "$PROBE_TMP/routes.txt")"
[ "$n_routes" -ge 50 ] || inconclusive "read only $n_routes routes from $ROUTES (has the route table moved?)"
K8S="/api/k8s"
cat >> "$PROBE_TMP/routes.txt" <<EOF
GET $K8S/apis/openinfra.dev/v1/namespaces/default/buckets s3:ListAllMyBuckets
DELETE $K8S/apis/openinfra.dev/v1/namespaces/default/queues/$NOPE sqs:DeleteQueue
GET $K8S/api/v1/namespaces/kube-system/secrets/$NOPE openinfra-operator:Get*
GET $K8S/api/v1/pods openinfra-operator:List*
EOF
log "console: $(grep -c . "$PROBE_TMP/routes.txt") routes ($n_routes from the route table + 4 through the proxy)"
while read -r method path action; do
  [ -n "$method" ] || continue
  checked=$((checked + 1))
  d="$(CONSOLE_BODY='{}' console_decision "$JAR" "$method" "$path" "$action")"; decided "$d"
  if [ "$d" != deny ]; then
    printf '  ✗ console %s %s (%s) was not denied\n' "$method" "$path" "$action" >&2
    failures=$((failures + 1))
  fi
done < "$PROBE_TMP/routes.txt"
me="$(curl -s -m 10 -o /dev/null -w '%{http_code}' -b "$JAR" "$CONSOLE/api/auth/me")"
[ "$me" = 200 ] || { printf '  ✗ /api/auth/me answered %s: a principal with no policy must still be able to sign in and see who it is\n' "$me" >&2; failures=$((failures + 1)); }

# --- API: one call per fronted service -----------------------------------------------------------
declare -A CALL=(
  [acm]="acm list-certificates"
  [apigateway]="apigateway get-rest-apis"
  [appsync]="appsync list-graphql-apis"
  [athena]="athena list-work-groups"
  [cloudformation]="cloudformation list-stacks"
  [cloudfront]="cloudfront list-distributions"
  [cognito-idp]="cognito-idp list-user-pools --max-results 5"
  [dynamodb]="dynamodb list-tables"
  [dynamodbstreams]="dynamodbstreams list-streams"
  [ec2]="ec2 describe-instances"
  [ecr]="ecr describe-repositories"
  [ecs]="ecs list-clusters"
  [eks]="eks list-clusters"
  [email]="sesv2 list-email-identities"
  [events]="events list-event-buses"
  [glue]="glue get-databases"
  [iam]="iam list-users"
  [kinesis]="kinesis list-streams"
  [kms]="kms list-keys"
  [lambda]="lambda list-functions"
  [logs]="logs describe-log-groups"
  [monitoring]="cloudwatch list-metrics"
  [organizations]="organizations describe-organization"
  [rds]="rds describe-db-instances"
  [s3]="s3api list-buckets"
  [secretsmanager]="secretsmanager list-secrets"
  [servicequotas]="service-quotas list-services"
  [ses]="ses list-identities"
  [sns]="sns list-topics"
  [sqs]="sqs list-queues"
  [ssm]="ssm describe-parameters"
  [states]="stepfunctions list-state-machines"
)
mapfile -t KEYS < <(python3 -c 'import json,sys; print("\n".join(sorted(json.load(open(sys.argv[1]))["services"])))' "$HERE_REPO/probe/registry/shim-router.json")
for k in "${KEYS[@]}"; do
  [ "$k" = sts ] && continue
  if [ -z "${CALL[$k]:-}" ]; then
    printf '  ✗ the shim fronts %s, which this probe has no call for (add one to CALL)\n' "$k" >&2
    failures=$((failures + 1)); continue
  fi
  checked=$((checked + 1))
  # shellcheck disable=SC2086
  d="$(shim_decision "$U_AK" "$U_SK" ${CALL[$k]})"; decided "$d"
  [ "$d" = deny ] || { printf '  ✗ API %s (aws %s) was not denied\n' "$k" "${CALL[$k]}" >&2; failures=$((failures + 1)); }
done
d="$(shim_decision "$U_AK" "$U_SK" sts get-caller-identity)"; decided "$d"
[ "$d" = allow ] || { printf '  ✗ sts get-caller-identity was denied: AWS lets every principal ask who it is\n' >&2; failures=$((failures + 1)); }

[ "$failures" = 0 ] || fail "$failures of $checked checks let a principal with no policy through (or refused it sign-in or GetCallerIdentity)"
log "✓ PASS — a principal with no policy is denied on all $checked console routes and API services (sign-in, /api/auth/me and sts:GetCallerIdentity still answer)"
