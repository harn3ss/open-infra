#!/usr/bin/env bash
# The console's Switch role is decided as AWS decides sts:AssumeRole: the role's trust policy, and the
# caller's own policy wherever the trust names the caller's account or the role is another account's.
#
# An administrator (AdministratorAccess) creates a throwaway member account (Organizations CreateAccount)
# and, through the IAM API, two throwaway roles: one in the management account whose trust names a second
# User, which has no policy, and one in the member account whose trust names that account's OWN user of the
# administrator's name. Each User signs in to the console, which then switches role as its account menu does:
#   - the administrator switches into the member account's OrganizationAccountAccessRole (its trust names
#     the management account) and the session is that role's in that account; that session is refused the
#     console's IAM pages, which manage the management account's IAM (no management user is made); it
#     switches back;
#   - the User with no policy is refused that role, with AWS's AccessDenied, since another account's role
#     needs the caller's own policy too;
#   - the User with no policy switches into the management account's role whose trust names it, as a trust
#     naming the caller in its own account is enough on its own;
#   - the administrator is refused the member account's role whose trust names that account's own user of
#     its name: another account's principal is named by its ARN, never by a bare name.
# Everything the probe made is removed on exit: the roles, the member account and its home namespace (only
# when this run created it), the Users, their passwords and keys.
#
# Needs a deployed console and shim with IAM policy deciding for the probe's principals (IAM_AUTHZ=enforce,
# or shadow with PRINCIPAL_MODE=canary), the Organizations front door and the Account kind. Exit 0 = pass,
# 1 = fail, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 CONSOLE_ENDPOINT=http://localhost:8080 ./probe/aws-shim-sts-switch-role.sh
set -uo pipefail
# shellcheck source=probe/iam-lib.sh
. "$(dirname "$0")/iam-lib.sh"
START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
MGMT_ROLE=""; MEMBER_ROLE=""; NEW_ACCOUNT=""; NEW_HOME=""
cleanup() {
  if [ -n "$MEMBER_ROLE" ] && [ -n "${M_AK:-}" ]; then
    AWS_ACCESS_KEY_ID="$M_AK" AWS_SECRET_ACCESS_KEY="$M_SK" AWS_SESSION_TOKEN="$M_TOK" AWS_REGION="$REGION" \
      aws --endpoint-url "$ENDPOINT" --no-cli-pager iam delete-role --role-name "$MEMBER_ROLE" >/dev/null 2>&1
  fi
  if [ -n "$MGMT_ROLE" ] && [ -n "${A_AK:-}" ]; then
    AWS_ACCESS_KEY_ID="$A_AK" AWS_SECRET_ACCESS_KEY="$A_SK" AWS_SESSION_TOKEN="" AWS_REGION="$REGION" \
      aws --endpoint-url "$ENDPOINT" --no-cli-pager iam delete-role --role-name "$MGMT_ROLE" >/dev/null 2>&1
  fi
  [ -n "$NEW_ACCOUNT" ] && kubectl delete accounts.organizations.openinfra.dev "$NEW_ACCOUNT" --ignore-not-found --wait=false >/dev/null 2>&1
  if [ -n "$NEW_HOME" ]; then
    created="$(kubectl get ns "$NEW_HOME" -o jsonpath='{.metadata.creationTimestamp}' 2>/dev/null)"
    if [ -n "$created" ] && [[ "$created" > "$START" || "$created" == "$START" ]]; then
      kubectl delete ns "$NEW_HOME" --ignore-not-found --wait=false >/dev/null 2>&1
    fi
  fi
  iamp_cleanup
}
trap cleanup EXIT
iamp_require
kubectl get crd accounts.organizations.openinfra.dev >/dev/null 2>&1 || inconclusive "the Account kind is not installed"
kubectl -n "$USERS_NS" get policies.iam.openinfra.dev aws-administratoraccess >/dev/null 2>&1 \
  || inconclusive "managed policy aws-administratoraccess is not installed (platform/abstraction/managed-policies)"

ADMIN="sr-admin-$SFX"
NOPOL="sr-nopolicy-$SFX"
iamp_user "$ADMIN" aws-administratoraccess ""
A_AK="$U_AK"; A_SK="$U_SK"; A_PW="$U_PW"
iamp_user "$NOPOL" "" ""
N_PW="$U_PW"
iamp_settle

as() { # <ak> <sk> <token> <aws args…>
  local ak="$1" sk="$2" tok="$3"; shift 3
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_SESSION_TOKEN="$tok" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output json "$@"
}
trust() { printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"%s"},"Action":"sts:AssumeRole"}]}' "$1"; }

# --- the member account, and the roles -----------------------------------------------------------------
log "creating a member account"
car="$(as "$A_AK" "$A_SK" "" organizations create-account --email "$ADMIN@example.com" --account-name "$ADMIN" \
  --query 'CreateAccountStatus.Id' --output text 2>"$PROBE_TMP/err")" \
  || inconclusive "create-account: $(head -c 300 "$PROBE_TMP/err")"
for _ in $(seq 1 60); do
  read -r state acct < <(as "$A_AK" "$A_SK" "" organizations describe-create-account-status \
    --create-account-request-id "$car" --query 'CreateAccountStatus.[State,AccountId]' --output text 2>/dev/null)
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
sleep "$IAM_SETTLE_SECONDS"
log "  ✓ member account $NEW_ACCOUNT, with its OrganizationAccountAccessRole"

# The member account's own role, made through its OrganizationAccountAccessRole as AWS's administrator does.
as "$A_AK" "$A_SK" "" sts assume-role --role-arn "arn:aws:iam::$NEW_ACCOUNT:role/OrganizationAccountAccessRole" \
  --role-session-name switch-role-probe > "$PROBE_TMP/member.json" 2>"$PROBE_TMP/err" \
  || inconclusive "the administrator could not assume the member account's OrganizationAccountAccessRole: $(head -c 300 "$PROBE_TMP/err")"
read -r M_AK M_SK M_TOK < <(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["Credentials"]; print(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"])' "$PROBE_TMP/member.json")
MEMBER_ROLE="sr-bare-$SFX"
as "$M_AK" "$M_SK" "$M_TOK" iam create-role --role-name "$MEMBER_ROLE" \
  --assume-role-policy-document "$(trust "arn:aws:iam::$NEW_ACCOUNT:user/$ADMIN")" >/dev/null 2>"$PROBE_TMP/err" \
  || { MEMBER_ROLE=""; inconclusive "could not create a role in the member account: $(head -c 300 "$PROBE_TMP/err")"; }
MGMT_ROLE="sr-ops-$SFX"
as "$A_AK" "$A_SK" "" iam create-role --role-name "$MGMT_ROLE" \
  --assume-role-policy-document "$(trust "arn:aws:iam::$ACCOUNT:user/$NOPOL")" >/dev/null 2>"$PROBE_TMP/err" \
  || { MGMT_ROLE=""; inconclusive "the administrator could not create a role: $(head -c 300 "$PROBE_TMP/err")"; }
for r in "$NEW_HOME/$MEMBER_ROLE" "$USERS_NS/$MGMT_ROLE"; do
  for _ in $(seq 1 30); do
    kubectl -n "${r%%/*}" get roles.iam.openinfra.dev "${r#*/}" >/dev/null 2>&1 && break
    sleep 2
  done
done

# --- the console's Switch role ---------------------------------------------------------------------------
A_JAR="$PROBE_TMP/admin.jar"; N_JAR="$PROBE_TMP/nopolicy.jar"
iamp_login "$ADMIN" "$A_PW" "$A_JAR"
iamp_login "$NOPOL" "$N_PW" "$N_JAR"

# switch_role <jar> <account> <role>: the console's answer (HTTP code; body in $PROBE_TMP/sr.out), as its
# account menu sends it (the role name lower-cased). The role session lands in <jar>.switched, so the
# signed-in session stays the user's.
switch_role() {
  cp "$1" "$1.switched"
  curl -s -m 30 -b "$1.switched" -c "$1.switched" -X POST -o "$PROBE_TMP/sr.out" -w '%{http_code}' \
    -H 'Content-Type: application/json' -H 'X-Openinfra-Console: 1' \
    -d "{\"account\":\"$2\",\"roleName\":\"$3\"}" "$CONSOLE/api/sts/switch-role"
}
field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))' "$PROBE_TMP/sr.out" "$1" 2>/dev/null; }
me() { curl -s -m 10 -b "$1" "$CONSOLE/api/auth/me" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("account",""), d.get("arn",""))' 2>/dev/null; }

code="$(switch_role "$A_JAR" "$NEW_ACCOUNT" organizationaccountaccessrole)"
[ "$code" = 200 ] || fail "the administrator was refused the member account's OrganizationAccountAccessRole: $code $(head -c 300 "$PROBE_TMP/sr.out")"
want="arn:aws:sts::$NEW_ACCOUNT:assumed-role/organizationaccountaccessrole/$ADMIN"
read -r acct arn < <(me "$A_JAR.switched")
[ "$acct" = "$NEW_ACCOUNT" ] && [ "$arn" = "$want" ] || fail "after Switch role the console session is account '$acct' as '$arn', want $NEW_ACCOUNT as $want"
log "  ✓ the administrator switches into the member account's OrganizationAccountAccessRole: $arn"
# The console's IAM pages manage the management account's IAM: the member account's role session is
# refused them, so it cannot create (or mint keys for) a management account user.
MADE="sr-made-$SFX"; CREATED_USERS+=("$MADE")
code="$(curl -s -m 15 -b "$A_JAR.switched" -X POST -o "$PROBE_TMP/iam.out" -w '%{http_code}' \
  -H 'Content-Type: application/json' -H 'X-Openinfra-Console: 1' -d "{\"name\":\"$MADE\",\"groups\":[]}" "$CONSOLE/api/iam/users")"
[ "$code" = 403 ] && grep -q AccessDeniedException "$PROBE_TMP/iam.out" || fail "the member account's role session was not refused the console's IAM pages: $code $(head -c 300 "$PROBE_TMP/iam.out")"
sleep 2
kubectl -n "$USERS_NS" get users.iam.openinfra.dev "$MADE" >/dev/null 2>&1 && fail "the member account's role session created a management account user"
log "  ✓ in the member account's role session the console's IAM pages refuse it: AccessDenied, no management user made"
code="$(curl -s -m 15 -b "$A_JAR.switched" -c "$A_JAR.switched" -X POST -o "$PROBE_TMP/sb.out" -w '%{http_code}' \
  -H 'X-Openinfra-Console: 1' "$CONSOLE/api/sts/switch-back")"
read -r acct arn < <(me "$A_JAR.switched")
[ "$code" = 200 ] && [ "$arn" = "arn:aws:iam::$ACCOUNT:user/$ADMIN" ] || fail "Switch back answered $code and left the session as '$arn'"
log "  ✓ and switches back: $arn"

code="$(switch_role "$N_JAR" "$NEW_ACCOUNT" organizationaccountaccessrole)"
[ "$code" = 403 ] || fail "a User with no policy switched into another account's role: $code $(head -c 300 "$PROBE_TMP/sr.out")"
[ "$(field errorCode)" = AccessDeniedException ] && [ "$(field action)" = sts:AssumeRole ] || fail "the refusal is not AWS's AccessDenied for sts:AssumeRole: $(head -c 300 "$PROBE_TMP/sr.out")"
log "  ✓ a User with no policy is refused another account's role, though its trust names the account: AccessDenied"

code="$(switch_role "$N_JAR" "$ACCOUNT" "$MGMT_ROLE")"
[ "$code" = 200 ] || fail "a User with no policy was refused a role of its own account whose trust names it: $code $(head -c 300 "$PROBE_TMP/sr.out")"
[ "$(field arn)" = "arn:aws:sts::$ACCOUNT:assumed-role/$MGMT_ROLE/$NOPOL" ] || fail "the role session is '$(field arn)'"
log "  ✓ a User with no policy switches into a role of its own account whose trust names it"

code="$(switch_role "$A_JAR" "$NEW_ACCOUNT" "$MEMBER_ROLE")"
[ "$code" = 403 ] || fail "the administrator switched into a member role whose trust names that account's own user of its name: $code $(head -c 300 "$PROBE_TMP/sr.out")"
[ "$(field errorCode)" = AccessDeniedException ] || fail "the bare-name refusal is not AWS's AccessDenied: $(head -c 300 "$PROBE_TMP/sr.out")"
log "  ✓ another account's bare name is that account's user: the administrator is refused, AccessDenied"
log "PASS: the console's Switch role is decided as sts:AssumeRole, its trust policy and the caller's own policy"
