#!/usr/bin/env bash
# STS refuses an AssumeRole the role's trust policy does not admit, as AWS does.
#
# An administrator (AdministratorAccess) creates two throwaway roles through the IAM API: one whose trust
# policy names only a made-up user, one whose trust names the caller. The caller is a throwaway User whose
# policy allows sts:AssumeRole on every role. Through the real AWS CLI it is:
#   - refused, with AccessDenied, assuming the role whose trust does not name it;
#   - given credentials for the role whose trust names it, and is that role (GetCallerIdentity).
# The roles are deleted on exit.
#
# Needs IAM policy to decide for the principals (IAM_AUTHZ=enforce, or shadow with PRINCIPAL_MODE=canary).
# Exit 0 = pass, 1 = fail, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-sts-deny.sh
set -uo pipefail
# shellcheck source=probe/iam-lib.sh
. "$(dirname "$0")/iam-lib.sh"
ROLES=()
cleanup() {
  for r in "${ROLES[@]:-}"; do
    [ -n "$r" ] && [ -n "${A_AK:-}" ] && AWS_ACCESS_KEY_ID="$A_AK" AWS_SECRET_ACCESS_KEY="$A_SK" AWS_REGION="$REGION" \
      aws --endpoint-url "$ENDPOINT" --no-cli-pager iam delete-role --role-name "$r" >/dev/null 2>&1
  done
  iamp_cleanup
}
trap cleanup EXIT
iamp_require

kubectl -n "$USERS_NS" get policies.iam.openinfra.dev aws-administratoraccess >/dev/null 2>&1 \
  || inconclusive "managed policy aws-administratoraccess is not installed (platform/abstraction/managed-policies)"
ADMIN="sts-deny-admin-$SFX"
CALLER="sts-deny-caller-$SFX"
iamp_user "$ADMIN" aws-administratoraccess ""
A_AK="$U_AK"; A_SK="$U_SK"
iamp_user "$CALLER" "" '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}'
C_AK="$U_AK"; C_SK="$U_SK"
iamp_settle

as() { # <ak> <sk> <aws args…>
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_SESSION_TOKEN="" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output json "$@"
}
trust() { printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"%s"},"Action":"sts:AssumeRole"}]}' "$1"; }

UNTRUSTED="sts-deny-other-$SFX"
TRUSTED="sts-deny-mine-$SFX"
as "$A_AK" "$A_SK" iam create-role --role-name "$UNTRUSTED" \
  --assume-role-policy-document "$(trust "arn:aws:iam::$ACCOUNT:user/nobody-$SFX")" >/dev/null 2>"$PROBE_TMP/err" \
  || inconclusive "the administrator could not create a role: $(head -c 300 "$PROBE_TMP/err")"
ROLES+=("$UNTRUSTED")
as "$A_AK" "$A_SK" iam create-role --role-name "$TRUSTED" \
  --assume-role-policy-document "$(trust "arn:aws:iam::$ACCOUNT:user/$CALLER")" >/dev/null 2>"$PROBE_TMP/err" \
  || inconclusive "the administrator could not create a role: $(head -c 300 "$PROBE_TMP/err")"
ROLES+=("$TRUSTED")
sleep "$IAM_SETTLE_SECONDS"   # the shim's policy world picks the roles up

d="$(shim_decision "$C_AK" "$C_SK" sts assume-role --role-arn "arn:aws:iam::$ACCOUNT:role/$UNTRUSTED" --role-session-name probe)"
decided "$d"
[ "$d" = deny ] || fail "a role whose trust does not name the caller was assumed"
grep -q AccessDenied "$PROBE_TMP/s.err" || fail "the untrusted AssumeRole was refused, but not with AccessDenied: $(head -c 300 "$PROBE_TMP/s.err")"
log "  ✓ assume a role whose trust does not name the caller: AccessDenied"

as "$C_AK" "$C_SK" sts assume-role --role-arn "arn:aws:iam::$ACCOUNT:role/$TRUSTED" --role-session-name probe \
  > "$PROBE_TMP/creds.json" 2>"$PROBE_TMP/err" || fail "a role whose trust names the caller was refused: $(head -c 300 "$PROBE_TMP/err")"
read -r R_AK R_SK R_TOK < <(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["Credentials"]; print(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"])' "$PROBE_TMP/creds.json")
WHO="$(AWS_ACCESS_KEY_ID="$R_AK" AWS_SECRET_ACCESS_KEY="$R_SK" AWS_SESSION_TOKEN="$R_TOK" AWS_REGION="$REGION" \
  aws --endpoint-url "$ENDPOINT" --no-cli-pager sts get-caller-identity --query Arn --output text 2>"$PROBE_TMP/err")"
case "$WHO" in
  "arn:aws:sts::$ACCOUNT:assumed-role/$TRUSTED/probe") log "  ✓ assume a role whose trust names the caller: $WHO" ;;
  *) fail "the assumed role's identity is '$WHO', want arn:aws:sts::$ACCOUNT:assumed-role/$TRUSTED/probe ($(head -c 200 "$PROBE_TMP/err"))" ;;
esac
log "PASS: STS assumes a role only for a caller its trust policy admits"
