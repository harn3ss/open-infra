#!/usr/bin/env bash
# Live probe: a CloudFormation service role (RoleARN) is what a stack acts as, as on AWS.
#
# An administrator (allowed everything) creates the same one-queue stack twice:
#   - with RoleARN = a role trusting cloudformation.amazonaws.com and allowed sqs:*  → CREATE_COMPLETE, and
#     DescribeStacks shows the role;
#   - with RoleARN = a role trusting CloudFormation but allowed nothing              → the queue is REFUSED
#     and the stack rolls back: it acted as the role, not as the administrator.
# And the passing of the role is checked as on AWS:
#   - a power user (PowerUserAccess has no iam:PassRole) passing the role is refused AccessDenied;
#   - a role that does not trust CloudFormation is refused ValidationError ("… cannot be assumed").
# Before the fix the shim ignored RoleARN: the second stack completed with the administrator's authority.
#
# Exit 0 pass, 1 fail, 42 inconclusive. Needs the aws CLI and kubectl (KUBECONFIG); reaches the shim at
# SHIM_ENDPOINT (port-forward svc/aws-shim 4566).
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
ACCOUNT="${ACCOUNT_ID:-000000000000}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

ADMIN="sr-probe-admin-$SFX"; POWER="sr-probe-power-$SFX"
ROLE_OK="sr-probe-sqs-$SFX"; ROLE_NONE="sr-probe-none-$SFX"; ROLE_UNTRUSTED="sr-probe-untrusted-$SFX"
STACK_OK="sr-probe-ok-$SFX"; STACK_NONE="sr-probe-none-$SFX"
CREATED_KEYS=(); CREATED_USERS=(); ROLES=(); STACKS=()
as() { local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$@"; }
cleanup() {
  for s in "${STACKS[@]:-}"; do [ -n "$s" ] && as "$AAK" "$ASK" cloudformation delete-stack --stack-name "$s" >/dev/null 2>&1; done
  for s in "${STACKS[@]:-}"; do
    [ -n "$s" ] || continue
    for _ in $(seq 1 30); do as "$AAK" "$ASK" cloudformation describe-stacks --stack-name "$s" >/dev/null 2>&1 || break; sleep 2; done
  done
  for r in "${ROLES[@]:-}"; do
    [ -n "$r" ] || continue
    as "$AAK" "$ASK" iam delete-role-policy --role-name "$r" --policy-name p >/dev/null 2>&1
    as "$AAK" "$ASK" iam delete-role --role-name "$r" >/dev/null 2>&1
  done
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1; done
  for k in "${CREATED_KEYS[@]:-}"; do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1; done
  rm -rf "$TMP"
}
trap cleanup EXIT

# mint_key <owner> <group>: a kind: User and an access key the shim authenticates; sets MK_AK MK_SK.
mint_key() {
  local owner="$1" group="$2" ak sk name
  ak="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  sk="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  cat <<YAML | kubectl apply -f - >/dev/null || inconclusive "could not create User $owner"
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "${owner}", namespace: "${USERS_NS}" }
spec: { displayName: "${owner}", groups: ["${group}"], source: local }
YAML
  CREATED_USERS+=("$owner")
  name="iam-ak-$(printf '%s' "$ak" | sha256sum | cut -c1-40)"
  kubectl -n "$SHIM_NS" create secret generic "$name" --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" \
    --from-literal=owner="$owner" >/dev/null || inconclusive "could not create the access key"
  CREATED_KEYS+=("$name")
  MK_AK="$ak"; MK_SK="$sk"
}

# --- 1. principals and roles ---------------------------------------------------------------------------
log "seeding an administrator, a power user (no iam:PassRole) and three roles"
mint_key "$ADMIN" "admins"; AAK="$MK_AK"; ASK="$MK_SK"
mint_key "$POWER" "powerusers"; PAK="$MK_AK"; PSK="$MK_SK"
CFN_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudformation.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
OTHER_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::'"$ACCOUNT"':user/'"$ADMIN"'"},"Action":"sts:AssumeRole"}]}'
mkrole() { # <name> <trust> <policy>
  local ok=""
  for _ in $(seq 1 10); do
    as "$AAK" "$ASK" iam create-role --role-name "$1" --assume-role-policy-document "$2" >/dev/null 2>"$TMP/cr" && { ok=1; break; }
    sleep 3   # the new key reaches the shim's key cache
  done
  [ -n "$ok" ] || inconclusive "create-role $1 failed: $(head -c 300 "$TMP/cr")"
  ROLES+=("$1")
  as "$AAK" "$ASK" iam put-role-policy --role-name "$1" --policy-name p --policy-document "$3" >/dev/null || fail "put-role-policy $1 failed"
}
mkrole "$ROLE_OK" "$CFN_TRUST" '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*"}]}'
mkrole "$ROLE_NONE" "$CFN_TRUST" '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudwatch:DescribeAlarms","Resource":"*"}]}'
mkrole "$ROLE_UNTRUSTED" "$OTHER_TRUST" '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*"}]}'
arn() { printf 'arn:aws:iam::%s:role/%s' "$ACCOUNT" "$1"; }
log "waiting 35s for the IAM policy world to load the roles' policies"
sleep 35

TEMPLATE='{"Resources":{"Q":{"Type":"AWS::SQS::Queue"}}}'
# final_status <stack>: the stack's status once it stops being *_IN_PROGRESS (up to ~3 minutes).
final_status() {
  local st=""
  for _ in $(seq 1 60); do
    st="$(as "$AAK" "$ASK" cloudformation describe-stacks --stack-name "$1" --query 'Stacks[0].StackStatus' 2>/dev/null)"
    case "$st" in *_IN_PROGRESS|"") sleep 3 ;; *) break ;; esac
  done
  printf '%s' "$st"
}

# --- 2. the role's authority, not the caller's ---------------------------------------------------------
log "the administrator creates $STACK_OK as $ROLE_OK (allowed sqs:*)"
as "$AAK" "$ASK" cloudformation create-stack --stack-name "$STACK_OK" --template-body "$TEMPLATE" --role-arn "$(arn "$ROLE_OK")" \
  >/dev/null 2>"$TMP/c1" || fail "CreateStack with a usable role was refused: $(head -c 300 "$TMP/c1")"
STACKS+=("$STACK_OK")
st="$(final_status "$STACK_OK")"
[ "$st" = CREATE_COMPLETE ] || fail "the stack acting as a role allowed sqs:* ended $st"
got="$(as "$AAK" "$ASK" cloudformation describe-stacks --stack-name "$STACK_OK" --query 'Stacks[0].RoleARN')"
[ "$got" = "$(arn "$ROLE_OK")" ] || fail "DescribeStacks shows RoleARN '$got', want $(arn "$ROLE_OK")"
log "  ✓ CREATE_COMPLETE, RoleARN shown"

log "the administrator creates $STACK_NONE as $ROLE_NONE (allowed no SQS)"
as "$AAK" "$ASK" cloudformation create-stack --stack-name "$STACK_NONE" --template-body "$TEMPLATE" --role-arn "$(arn "$ROLE_NONE")" \
  >/dev/null 2>"$TMP/c2" || fail "CreateStack with a usable role was refused: $(head -c 300 "$TMP/c2")"
STACKS+=("$STACK_NONE")
st="$(final_status "$STACK_NONE")"
case "$st" in
  CREATE_COMPLETE) fail "WIDER THAN AWS: the stack created a queue its role isn't allowed to — it acted as the administrator" ;;
  *ROLLBACK_COMPLETE|CREATE_FAILED|ROLLBACK_FAILED) log "  ✓ the queue was refused as the role ($st)" ;;
  *) inconclusive "the stack acting as a role allowed nothing ended '$st'" ;;
esac

# --- 3. passing the role -------------------------------------------------------------------------------
log "a power user (no iam:PassRole) passing $ROLE_OK is refused"
if as "$PAK" "$PSK" cloudformation create-stack --stack-name "sr-probe-power-$SFX" --template-body "$TEMPLATE" \
    --role-arn "$(arn "$ROLE_OK")" >/dev/null 2>"$TMP/c3"; then
  STACKS+=("sr-probe-power-$SFX"); fail "a caller without iam:PassRole passed the role"
fi
grep -q "AccessDenied" "$TMP/c3" || fail "the refusal is not AccessDenied: $(head -c 300 "$TMP/c3")"
log "  ✓ AccessDenied"

log "a role that does not trust CloudFormation is refused"
if as "$AAK" "$ASK" cloudformation create-stack --stack-name "sr-probe-untrusted-$SFX" --template-body "$TEMPLATE" \
    --role-arn "$(arn "$ROLE_UNTRUSTED")" >/dev/null 2>"$TMP/c4"; then
  STACKS+=("sr-probe-untrusted-$SFX"); fail "a role that doesn't trust CloudFormation was used"
fi
grep -q "ValidationError" "$TMP/c4" && grep -q "cannot be assumed" "$TMP/c4" || fail "the refusal is not AWS's: $(head -c 300 "$TMP/c4")"
log "  ✓ ValidationError: the role cannot be assumed"

log "PASS: a stack acts as its service role (RoleARN), not its caller; passing it takes iam:PassRole and the role's trust of CloudFormation"
