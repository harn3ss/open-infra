#!/usr/bin/env bash
# The AWS managed policies behave as AWS documents them, at both doors (the console and the API):
#   PowerUserAccess     — everything except IAM, Organizations and Account management: denied
#                         iam:CreateUser, iam:AttachUserPolicy (no self-escalation), iam:PutRolePolicy and
#                         the operator surface (a Kubernetes Secret through the console), allowed
#                         iam:ListRoles (in AWS's document) and other services' actions;
#   ReadOnlyAccess      — reads allowed, writes denied;
#   AdministratorAccess — everything allowed, the operator surface and IAM writes included.
# Each principal is a throwaway User in no group, holding only that managed policy (attached by its
# object name, aws-<name>). Writes target resources the probe makes up, so a wrong "allow" changes
# nothing; the one create (iam:CreateUser) names a user the cleanup removes.
#
# Needs IAM policy to decide (IAM_AUTHZ=shadow + PRINCIPAL_MODE=canary, or enforce).
# Exit 0 = pass, 1 = fail, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 PRINCIPAL_MODE=canary ./probe/iam-managed-policies.sh
set -uo pipefail
# shellcheck source=probe/iam-lib.sh
. "$(dirname "$0")/iam-lib.sh"
trap iamp_cleanup EXIT
iamp_require

NOPE="iam-mp-nope-$SFX"
CREATED_USERS+=("$NOPE")       # removed even if a wrong allow let iam:CreateUser through
SECRET="/api/k8s/api/v1/namespaces/kube-system/secrets/$NOPE"   # the operator surface: a Secret read
DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'

declare -A AK SK JARS
for who in poweruser readonly admin; do
  case "$who" in
    poweruser) pol=aws-poweruseraccess ;; readonly) pol=aws-readonlyaccess ;; admin) pol=aws-administratoraccess ;;
  esac
  kubectl -n "$USERS_NS" get policies.iam.openinfra.dev "$pol" >/dev/null 2>&1 || inconclusive "managed policy $pol is not installed (platform/abstraction/managed-policies)"
  name="iam-mp-$who-$SFX"
  log "principal $name: only $pol${PRINCIPAL_MODE:+ (PRINCIPAL_MODE=$PRINCIPAL_MODE)}"
  iamp_user "$name" "$pol" ""
  AK[$who]="$U_AK"; SK[$who]="$U_SK"; JARS[$who]="$PROBE_TMP/jar-$who"
  iamp_login "$name" "$U_PW" "${JARS[$who]}"
done
iamp_settle   # the shim's policy world picks the new principals up
PU_NAME="iam-mp-poweruser-$SFX"

failures=0; checked=0
api() { # <who> <want> <aws args…>
  local who="$1" want="$2"; shift 2; local d
  checked=$((checked + 1))
  d="$(shim_decision "${AK[$who]}" "${SK[$who]}" "$@")"; decided "$d"
  if [ "$d" = "$want" ]; then log "  ✓ $who API $* → $d"
  else printf '  ✗ %s API aws %s: want %s, got %s\n' "$who" "$*" "$want" "$d" >&2; failures=$((failures + 1)); fi
}
con() { # <who> <want> <method> <path> <action>
  local who="$1" want="$2" method="$3" path="$4" action="$5" d
  checked=$((checked + 1))
  d="$(CONSOLE_BODY='{}' console_decision "${JARS[$who]}" "$method" "$path" "$action")"; decided "$d"
  if [ "$d" = "$want" ]; then log "  ✓ $who console $method $path ($action) → $d"
  else printf '  ✗ %s console %s %s (%s): want %s, got %s\n' "$who" "$method" "$path" "$action" "$want" "$d" >&2; failures=$((failures + 1)); fi
}

log "PowerUserAccess: no IAM writes, no operator surface; everything else"
api poweruser deny  iam create-user --user-name "$NOPE"
con poweruser deny  POST /api/iam/users iam:CreateUser
api poweruser deny  iam attach-user-policy --user-name "$PU_NAME" --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
api poweruser deny  iam put-role-policy --role-name "$NOPE" --policy-name probe --policy-document "$DOC"
con poweruser deny  GET "$SECRET" "openinfra-operator:Get*"
api poweruser allow iam list-roles
api poweruser allow s3api list-buckets
api poweruser allow dynamodb delete-table --table-name "$NOPE"
api poweruser allow sqs list-queues
con poweruser allow GET /api/buckets s3:ListAllMyBuckets
con poweruser allow DELETE "/api/buckets/$NOPE" s3:DeleteBucket

log "ReadOnlyAccess: reads, no writes"
api readonly allow s3api list-buckets
api readonly allow dynamodb list-tables
api readonly allow iam list-users
con readonly allow GET /api/iam/users iam:ListUsers
api readonly deny  dynamodb delete-table --table-name "$NOPE"
api readonly deny  sqs delete-queue --queue-url "$ENDPOINT/$ACCOUNT/$NOPE"
api readonly deny  iam delete-user --user-name "$NOPE"
con readonly deny  DELETE "/api/buckets/$NOPE" s3:DeleteBucket
con readonly deny  POST /api/iam/users iam:CreateUser

log "AdministratorAccess: everything"
api admin allow iam list-users
api admin allow iam delete-user --user-name "$NOPE-absent"
api admin allow s3api delete-bucket --bucket "$NOPE"
api admin allow organizations describe-organization
con admin allow GET "$SECRET" "openinfra-operator:Get*"
con admin allow DELETE "/api/buckets/$NOPE" s3:DeleteBucket

[ "$failures" = 0 ] || fail "$failures of $checked managed-policy checks disagree with AWS's documented behaviour"
log "✓ PASS — PowerUserAccess, ReadOnlyAccess and AdministratorAccess behave as AWS documents them, at the console and the API ($checked checks)"
