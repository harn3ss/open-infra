#!/usr/bin/env bash
# Compatibility probe for IAM login profiles: a console password managed through `aws iam`, end to end.
#
#   1. An admin gives a throwaway local User a login profile (create-login-profile --password-reset-required)
#      and reads it back; a second create is EntityAlreadyExists, the reserved name root is NoSuchEntity,
#      a password no policy accepts is PasswordPolicyViolation.
#   2. The User signs in to the console with that password and gets a session that can only change its
#      password (PasswordResetRequired); it changes it through the console and the session is whole.
#   3. As itself, with its own access key, it runs `aws iam change-password`: refused with no grant (unless
#      the account password policy lets every user change theirs), refused with a wrong old password once
#      it holds iam:ChangePassword on itself, then accepted. The console takes the new password and no
#      longer the old one.
#   4. The admin deletes the profile: get-login-profile is NoSuchEntity and the console refuses the password.
#
# Also: the hash is in the credential store namespace (the User's passwordSecretRef names it), labelled as a
# login profile, and the admission guard refuses the aws-shim's ServiceAccount an unlabelled iam-login-*
# Secret (a server-side dry run, nothing written). No Secret's data is read, and none outside the probe's own.
#
# The probe never sets the account password policy: that changes the rules for every user of the account.
#
# On demand (a deployed shim and console, the IAM CRDs, kubectl as a cluster operator).
# Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 CONSOLE_ENDPOINT=http://localhost:8080 ./probe/aws-shim-iam-login-profile.sh
#   PRINCIPAL_MODE=canary …   # the User is decided by IAM policy while the platform runs in shadow
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=probe/iam-lib.sh
. "$HERE/iam-lib.sh"

ADMIN="lp${SFX}-admin"
USER_NAME="lp${SFX}-user"
PROFILE_SECRET=""
AAK=""; ASK=""

cleanup() {
  if [ -n "$AAK" ]; then
    AWS_ACCESS_KEY_ID="$AAK" AWS_SECRET_ACCESS_KEY="$ASK" AWS_REGION="$REGION" \
      aws --endpoint-url "$ENDPOINT" --no-cli-pager iam delete-login-profile --user-name "$USER_NAME" >/dev/null 2>&1 || true
  fi
  [ -n "$PROFILE_SECRET" ] && kubectl -n "$SHIM_NS" delete secret "$PROFILE_SECRET" --ignore-not-found >/dev/null 2>&1
  iamp_cleanup
}
trap cleanup EXIT

command -v aws >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v curl >/dev/null || inconclusive "curl is required"
command -v python3 >/dev/null || inconclusive "python3 is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"
if [ -z "$CONSOLE" ]; then
  port=$(( 20000 + RANDOM % 20000 ))
  kubectl -n "$USERS_NS" port-forward svc/console "$port:80" >/dev/null 2>&1 &
  CONSOLE_PF=$!
  CONSOLE="http://127.0.0.1:$port"
  for _ in $(seq 1 20); do curl -fsS -m 2 "$CONSOLE/healthz" >/dev/null 2>&1 && break; sleep 1; done
fi
curl -fsS -m 5 "$CONSOLE/healthz" >/dev/null 2>&1 || inconclusive "console not reachable at $CONSOLE (set CONSOLE_ENDPOINT)"

# awsc <ak> <sk> <aws args…>: runs the CLI; output in $PROBE_TMP/out, errors in $PROBE_TMP/err.
awsc() {
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_SESSION_TOKEN="" AWS_REGION="$REGION" \
    AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=2 \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output json "$@" >"$PROBE_TMP/out" 2>"$PROBE_TMP/err"
}
# code: the AWS error code of the last failed call ("An error occurred (Code) when calling …").
code() { sed -n 's/.*An error occurred (\([A-Za-z]*\)).*/\1/p' "$PROBE_TMP/err" | head -1; }
err() { tr '\n' ' ' < "$PROBE_TMP/err" | cut -c1-240; }
# expect_error <Code> <what> <aws args…>: as the admin, the call must fail with Code.
expect_error() {
  local want="$1" what="$2"; shift 2
  if awsc "$AAK" "$ASK" "$@"; then fail "$what succeeded; want $want"; fi
  [ "$(code)" = "$want" ] || fail "$what: want $want, got: $(err)"
  log "  ✓ $what → $want"
}

# mint <name> <groups-json> <labels-json>: a local User and an access key the shim authenticates; sets MK_AK
# MK_SK. Runs in this shell, so the CREATED_* lists reach the EXIT trap.
mint() {
  local name="$1" groups="$2" labels="$3"
  cat > "$PROBE_TMP/user-$name.json" <<JSON
{"apiVersion":"iam.openinfra.dev/v1","kind":"User",
 "metadata":{"name":"$name","namespace":"$USERS_NS","labels":$labels},
 "spec":{"displayName":"$name","source":"local","groups":$groups,"policies":[]}}
JSON
  kubectl apply -f "$PROBE_TMP/user-$name.json" >/dev/null || inconclusive "could not create User $name"
  CREATED_USERS+=("$name")
  MK_AK="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  MK_SK="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  local keysec; keysec="iam-ak-$(printf '%s' "$MK_AK" | sha256sum | cut -c1-40)"
  kubectl -n "$SHIM_NS" create secret generic "$keysec" --from-literal=accessKeyId="$MK_AK" \
    --from-literal=secretKey="$MK_SK" --from-literal=owner="$name" >/dev/null || inconclusive "could not create an access key for $name"
  CREATED_SHIM_SECRETS+=("$keysec")
}

# login <password> <jar>: the console's answer to a sign-in as the User (HTTP code; body in $PROBE_TMP/login).
login() {
  rm -f "$2"
  curl -s -m 15 -c "$2" -o "$PROBE_TMP/login" -w '%{http_code}' -H 'Content-Type: application/json' \
    -d "{\"Username\":\"$USER_NAME\",\"Password\":\"$1\"}" "$CONSOLE/api/auth/login"
}
field() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1])).get(sys.argv[2]); print(str(v).lower() if isinstance(v,bool) else (v or ""))' "$1" "$2" 2>/dev/null; }
pw() { printf 'Lp-%s-%s-9x' "$1" "$(head -c 12 /dev/urandom | base64 | tr -d '/+=' | head -c 16)"; }

# --- the principals ---------------------------------------------------------------------------------
log "minting an IAM admin (openinfra:admins) and a throwaway local User with no policies"
mint "$ADMIN" '["admins"]' '{}'; AAK="$MK_AK"; ASK="$MK_SK"
canary='{}'
[ "${PRINCIPAL_MODE:-}" = canary ] && canary='{"openinfra.dev/iam-authz":"enforce"}'
mint "$USER_NAME" '[]' "$canary"; UAK="$MK_AK"; USK="$MK_SK"
sleep 3   # the shim and console read Users through informers

P1="$(pw one)"; P2="$(pw two)"; P3="$(pw three)"

# --- 1. the IAM API -------------------------------------------------------------------------------
log "1. login profiles through the IAM API"
expect_error NoSuchEntity "get-login-profile before one exists" iam get-login-profile --user-name "$USER_NAME"
awsc "$AAK" "$ASK" iam create-login-profile --user-name "$USER_NAME" --password "$P1" --password-reset-required \
  || { [ "$(code)" = AccessDenied ] && inconclusive "the admin was refused create-login-profile: $(err)"; fail "create-login-profile: $(err)"; }
[ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["LoginProfile"]["UserName"])' "$PROBE_TMP/out" 2>/dev/null)" = "$USER_NAME" ] \
  || fail "create-login-profile did not answer the LoginProfile: $(head -c 240 "$PROBE_TMP/out")"
log "  ✓ create-login-profile"
expect_error EntityAlreadyExists "a second create-login-profile" iam create-login-profile --user-name "$USER_NAME" --password "$P2"
expect_error NoSuchEntity "create-login-profile for root" iam create-login-profile --user-name root --password "$P2"
expect_error PasswordPolicyViolation "update-login-profile to a 5-character password" iam update-login-profile --user-name "$USER_NAME" --password "Ab1!x"
awsc "$AAK" "$ASK" iam get-login-profile --user-name "$USER_NAME" || fail "get-login-profile: $(err)"
python3 - "$PROBE_TMP/out" <<'PY' || fail "get-login-profile: $(head -c 240 "$PROBE_TMP/out")"
import json, sys
p = json.load(open(sys.argv[1]))["LoginProfile"]
assert p.get("PasswordResetRequired") is True and p.get("CreateDate"), p
PY
log "  ✓ get-login-profile (PasswordResetRequired, CreateDate)"

# Where the hash lives: the User names a Secret in the credential store, labelled as its login profile.
ref="$(kubectl -n "$USERS_NS" get users.iam.openinfra.dev "$USER_NAME" -o jsonpath='{.spec.passwordSecretRef.namespace}/{.spec.passwordSecretRef.name}' 2>/dev/null)"
[ "${ref%%/*}" = "$SHIM_NS" ] || fail "the User's passwordSecretRef is $ref — the hash must be in the credential store ($SHIM_NS), not the console namespace"
PROFILE_SECRET="${ref#*/}"
labels="$(kubectl -n "$SHIM_NS" get secret "$PROFILE_SECRET" -o jsonpath='{.metadata.labels.openinfra\.dev/login-profile} {.metadata.labels.openinfra\.dev/iam-user}' 2>/dev/null)"
[ "$labels" = "true $USER_NAME" ] || fail "the profile Secret $PROFILE_SECRET is labelled '$labels', want 'true $USER_NAME'"
log "  ✓ the hash is in $SHIM_NS/$PROFILE_SECRET, labelled for $USER_NAME"

# --- 2. the console sign-in -----------------------------------------------------------------------
log "2. console sign-in"
JAR="$PROBE_TMP/jar"
c=""
for _ in $(seq 1 15); do c="$(login "$P1" "$JAR")"; [ "$c" = 200 ] && break; sleep 2; done
[ "$c" = 200 ] || fail "console sign-in with the profile's password answered $c: $(head -c 200 "$PROBE_TMP/login")"
[ "$(field "$PROBE_TMP/login" passwordResetRequired)" = true ] || fail "the sign-in did not require a new password: $(head -c 200 "$PROBE_TMP/login")"
c="$(curl -s -m 10 -b "$JAR" -o "$PROBE_TMP/guarded" -w '%{http_code}' "$CONSOLE/api/config")"
[ "$c" = 403 ] && [ "$(field "$PROBE_TMP/guarded" code)" = PasswordResetRequired ] \
  || fail "a session that must change its password reached /api/config ($c): $(head -c 200 "$PROBE_TMP/guarded")"
log "  ✓ signed in; everything but the password change answers PasswordResetRequired"
c="$(curl -s -m 15 -b "$JAR" -c "$JAR" -o "$PROBE_TMP/chg" -w '%{http_code}' -H 'Content-Type: application/json' \
  -H 'X-Openinfra-Console: 1' -d "{\"oldPassword\":\"$P1\",\"newPassword\":\"$P2\"}" "$CONSOLE/api/auth/change-password")"
[ "$c" = 200 ] || fail "the console's password change answered $c: $(head -c 200 "$PROBE_TMP/chg")"
c="$(curl -s -m 10 -b "$JAR" -o /dev/null -w '%{http_code}' "$CONSOLE/api/config")"
[ "$c" = 200 ] || fail "after the password change the session still cannot reach /api/config ($c)"
log "  ✓ changed through the console; the session is whole"

# --- 3. aws iam change-password, as the User --------------------------------------------------------
log "3. aws iam change-password as $USER_NAME"
everyone=false
if awsc "$AAK" "$ASK" iam get-account-password-policy; then
  [ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["PasswordPolicy"].get("AllowUsersToChangePassword"))' "$PROBE_TMP/out")" = True ] && everyone=true
fi
if [ "$everyone" = true ]; then
  log "  · the account password policy lets every user change their password: the no-grant refusal is not testable here"
else
  if awsc "$UAK" "$USK" iam change-password --old-password "$P2" --new-password "$P3"; then
    fail "a User with no policies changed its password (no AllowUsersToChangePassword, no iam:ChangePassword)"
  fi
  [ "$(code)" = AccessDenied ] || fail "change-password with no grant: want AccessDenied, got: $(err)"
  log "  ✓ refused with no grant (AccessDenied)"
fi

arn="arn:aws:iam::*:user/$USER_NAME"
if awsc "$UAK" "$USK" sts get-caller-identity; then
  a="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["Arn"])' "$PROBE_TMP/out" 2>/dev/null)"
  [ -n "$a" ] && arn="$a"
fi
log "  granting iam:ChangePassword on $arn"
python3 - "$arn" > "$PROBE_TMP/grant.json" <<'PY'
import json, sys
doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:ChangePassword", "Resource": sys.argv[1]}]}
print(json.dumps({"spec": {"inlinePolicies": [{"name": "change-own-password", "document": doc}]}}))
PY
kubectl -n "$USERS_NS" patch users.iam.openinfra.dev "$USER_NAME" --type merge --patch-file "$PROBE_TMP/grant.json" >/dev/null \
  || inconclusive "could not grant iam:ChangePassword to $USER_NAME"

# A wrong old password, once the grant is seen: refused, and the password is unchanged.
granted=false
for _ in $(seq 1 30); do
  if awsc "$UAK" "$USK" iam change-password --old-password "not-the-password-1A!" --new-password "$P3"; then
    fail "change-password accepted a wrong old password"
  fi
  [ "$(code)" = AccessDenied ] || { granted=true; break; }
  sleep 3
done
if [ "$granted" != true ]; then
  mode="$(curl -s -m 10 -b "$JAR" "$CONSOLE/api/auth/me" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("iamAuthz",""))' 2>/dev/null)"
  [ "$mode" = enforce ] || inconclusive "iam:ChangePassword granted by policy, but IAM policy does not decide for $USER_NAME (iamAuthz=${mode:-unknown}): re-run with PRINCIPAL_MODE=canary under IAM_AUTHZ=shadow, or after the enforce step"
  fail "change-password stayed AccessDenied 90s after granting iam:ChangePassword on the User itself: $(err)"
fi
[ "$(code)" = InvalidUserType ] || fail "change-password with a wrong old password: want InvalidUserType, got: $(err)"
log "  ✓ a wrong old password is refused (InvalidUserType)"
[ "$(login "$P2" "$PROBE_TMP/jar2")" = 200 ] || fail "after a refused change-password the current password no longer signs in"

awsc "$UAK" "$USK" iam change-password --old-password "$P2" --new-password "$P3" || fail "change-password with the right old password: $(err)"
log "  ✓ change-password accepted"
c="$(login "$P3" "$PROBE_TMP/jar3")"
[ "$c" = 200 ] || fail "the console refused the password set by change-password ($c): $(head -c 200 "$PROBE_TMP/login")"
[ "$(field "$PROBE_TMP/login" passwordResetRequired)" = false ] || fail "a password the User chose still requires a reset"
c="$(login "$P2" "$PROBE_TMP/jar4")"
[ "$c" = 401 ] || fail "the console still accepts the replaced password ($c)"
log "  ✓ the console takes the new password and refuses the old one"

# --- the admission guard --------------------------------------------------------------------------
log "the admission guard (server-side dry run as the aws-shim's ServiceAccount; nothing is written)"
if kubectl -n "$SHIM_NS" create secret generic "iam-login-guard-$SFX" --from-literal=hash=x --dry-run=server \
     --as="system:serviceaccount:$SHIM_NS:aws-shim" -o name >/dev/null 2>"$PROBE_TMP/vap"; then
  fail "an unlabelled iam-login-* Secret was admitted for the aws-shim: is platform/aws-shim/login-profile-guard.yaml synced?"
elif grep -q "openinfra-login-profile-guard\|both or neither" "$PROBE_TMP/vap"; then
  log "  ✓ refused by openinfra-login-profile-guard"
elif grep -qi "cannot impersonate" "$PROBE_TMP/vap"; then
  log "  · skipped: this kubectl identity cannot impersonate the shim's ServiceAccount"
else
  fail "the dry run was refused, but not by the login-profile guard: $(tr '\n' ' ' < "$PROBE_TMP/vap" | cut -c1-240)"
fi

# --- 4. delete ------------------------------------------------------------------------------------
log "4. delete-login-profile"
awsc "$AAK" "$ASK" iam delete-login-profile --user-name "$USER_NAME" || fail "delete-login-profile: $(err)"
expect_error NoSuchEntity "get-login-profile after the delete" iam get-login-profile --user-name "$USER_NAME"
expect_error NoSuchEntity "a second delete-login-profile" iam delete-login-profile --user-name "$USER_NAME"
c="$(login "$P3" "$PROBE_TMP/jar5")"
[ "$c" = 401 ] || fail "the console still signs in a User whose login profile was deleted ($c)"
log "  ✓ the console refuses the deleted profile's password"
kubectl -n "$SHIM_NS" get secret "$PROFILE_SECRET" >/dev/null 2>&1 && fail "the profile Secret $PROFILE_SECRET outlived delete-login-profile"
PROFILE_SECRET=""

printf '\n✓ PASS — IAM login profiles: create/get/update/delete as IAM answers them, a console sign-in that must\n'
printf '  change its password first, aws iam change-password (refused without a grant or with a wrong old\n'
printf '  password, accepted with both), and the hash kept in the credential store under the admission guard.\n'
