#!/usr/bin/env bash
# Live probe: UpdateAssumeRolePolicy replaces a role's trust policy, and AssumeRole follows the new one.
#
# Through the AWS front door, with the real AWS CLI:
#   - a role trusts its caller only from 203.0.113.50 (aws:SourceIp): AssumeRole from here is AccessDenied;
#   - UpdateAssumeRolePolicy drops the address condition: GetRole returns the new document, as written, and
#     AssumeRole from here succeeds;
#   - a user with no policy is refused UpdateAssumeRolePolicy with AWS's AccessDenied, and the trust is
#     unchanged;
#   - a missing role is NoSuchEntity and a document that is not a trust policy is MalformedPolicyDocument.
#
# Exit 0 pass, 1 fail, 42 inconclusive. Needs kubectl (KUBECONFIG), the aws CLI and go (iam-lib hashes each
# user's console password).
set -uo pipefail
HERE_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=probe/iam-lib.sh
source "$HERE_DIR/iam-lib.sh"

ROLE="iam-probe-trust-$SFX"
ROLE_CREATED=""
cleanup() {
  [ -n "$ROLE_CREATED" ] && shim_as "$A_AK" "$A_SK" iam delete-role --role-name "$ROLE" >/dev/null 2>&1
  iamp_cleanup
}
trap cleanup EXIT

shim_as() { local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_SESSION_TOKEN="" AWS_REGION="${AWS_REGION:-us-east-1}" \
    AWS_REQUEST_CHECKSUM_CALCULATION=when_required AWS_RESPONSE_CHECKSUM_VALIDATION=when_required \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$@"; }

iamp_require

# --- 1. principals: one with IAMFullAccess (it also calls AssumeRole), one with no policy ------------------
log "seeding an IAM administrator (IAMFullAccess + sts:AssumeRole) and a user with no policy"
iamp_user "trust-admin-$SFX" "aws-iamfullaccess" '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}'
A_AK="$U_AK"; A_SK="$U_SK"
iamp_user "trust-none-$SFX" "" ""
N_AK="$U_AK"; N_SK="$U_SK"
iamp_settle
CALLER="$(shim_as "$A_AK" "$A_SK" sts get-caller-identity --query Arn 2>/dev/null)"
[ -n "$CALLER" ] || inconclusive "the administrator's key does not authenticate"

FAR='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"'"$CALLER"'"},"Action":"sts:AssumeRole","Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.50/32"}}}]}'
OPEN='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"'"$CALLER"'"},"Action":"sts:AssumeRole"}]}'

# --- 2. the role, trusting its caller only from another address -------------------------------------------
log "create-role $ROLE: trusts $CALLER only from 203.0.113.50"
shim_as "$A_AK" "$A_SK" iam create-role --role-name "$ROLE" --assume-role-policy-document "$FAR" >/dev/null 2>"$PROBE_TMP/e" \
  || fail "create-role failed: $(cat "$PROBE_TMP/e")"
ROLE_CREATED=1
ROLE_ARN="$(shim_as "$A_AK" "$A_SK" iam get-role --role-name "$ROLE" --query Role.Arn)"
assume() { shim_as "$A_AK" "$A_SK" sts assume-role --role-arn "$ROLE_ARN" --role-session-name probe --query Credentials.AccessKeyId >/dev/null 2>"$PROBE_TMP/a"; }
sleep 35 # the shim's role world reloads within 30 s
if assume; then fail "AssumeRole succeeded from an address the trust policy does not name"; fi
grep -q AccessDenied "$PROBE_TMP/a" || fail "AssumeRole was refused with the wrong error: $(cat "$PROBE_TMP/a")"
log "  ✓ AssumeRole refused AccessDenied: the trust names another address"

# --- 3. a user with no policy may not change the trust ------------------------------------------------------
log "DENY: a user with no policy calls update-assume-role-policy"
if shim_as "$N_AK" "$N_SK" iam update-assume-role-policy --role-name "$ROLE" --policy-document "$OPEN" >/dev/null 2>"$PROBE_TMP/d"; then
  fail "a user with no policy changed a role's trust policy"
fi
grep -q AccessDenied "$PROBE_TMP/d" || fail "refused with the wrong error: $(cat "$PROBE_TMP/d")"
shim_as "$A_AK" "$A_SK" iam get-role --role-name "$ROLE" --query Role.AssumeRolePolicyDocument --output json | grep -q 203.0.113.50 \
  || fail "a refused call changed the trust policy"
log "  ✓ refused AccessDenied, and the trust is unchanged"

# --- 4. the administrator replaces the trust; AssumeRole follows it -----------------------------------------
log "update-assume-role-policy: trust $CALLER from anywhere"
shim_as "$A_AK" "$A_SK" iam update-assume-role-policy --role-name "$ROLE" --policy-document "$OPEN" >/dev/null 2>"$PROBE_TMP/e" \
  || fail "update-assume-role-policy failed: $(cat "$PROBE_TMP/e")"
DOC="$(shim_as "$A_AK" "$A_SK" iam get-role --role-name "$ROLE" --query Role.AssumeRolePolicyDocument --output json)"
if printf '%s' "$DOC" | grep -q 203.0.113.50; then fail "GetRole still returns the old trust policy: $DOC"; fi
printf '%s' "$DOC" | grep -q "$CALLER" || fail "GetRole does not return the new trust policy: $DOC"
log "  ✓ GetRole returns the new document"
ok=""
for _ in $(seq 1 8); do assume && { ok=1; break; }; sleep 5; done
[ -n "$ok" ] || fail "AssumeRole is still refused after the trust allows it: $(cat "$PROBE_TMP/a")"
log "  ✓ AssumeRole succeeds under the new trust"

# --- 5. AWS's errors ----------------------------------------------------------------------------------------
if shim_as "$A_AK" "$A_SK" iam update-assume-role-policy --role-name "no-such-role-$SFX" --policy-document "$OPEN" >/dev/null 2>"$PROBE_TMP/e"; then
  fail "a missing role was updated"
fi
grep -q NoSuchEntity "$PROBE_TMP/e" || fail "a missing role: wrong error: $(cat "$PROBE_TMP/e")"
if shim_as "$A_AK" "$A_SK" iam update-assume-role-policy --role-name "$ROLE" --policy-document '{"Version":"2012-10-17"}' >/dev/null 2>"$PROBE_TMP/e"; then
  fail "a document with no statement was accepted"
fi
grep -q MalformedPolicyDocument "$PROBE_TMP/e" || fail "a malformed document: wrong error: $(cat "$PROBE_TMP/e")"
log "  ✓ NoSuchEntity for a missing role, MalformedPolicyDocument for a bad document"

log "PASS: UpdateAssumeRolePolicy replaces the trust policy, AssumeRole follows it, and a caller without the action is refused"
