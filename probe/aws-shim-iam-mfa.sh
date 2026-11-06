#!/usr/bin/env bash
# Compatibility probe for IAM virtual MFA devices and MFA-authenticated STS sessions, end to end with the
# real AWS CLI:
#
#   1. An admin creates a virtual MFA device (create-virtual-mfa-device: its QR code PNG, and its base32
#      seed), is refused a second one of the same name (EntityAlreadyExists), and enables it for a
#      throwaway user with two consecutive TOTP codes the probe computes from the seed (RFC 6238, SHA-1,
#      30 s, six digits — python3's hmac, no extra packages). Two codes that are not consecutive are
#      InvalidAuthenticationCode. list-mfa-devices and list-virtual-mfa-devices (by AssignmentStatus) show
#      it; delete-virtual-mfa-device and delete-user are DeleteConflict while it is assigned.
#   2. As the user: get-session-token with a wrong code is AccessDenied; with a fresh code it returns a
#      session of the user; the same code again is AccessDenied (no replay). A session obtained without MFA
#      cannot call IAM at all (InvalidClientTokenId) nor get-session-token again.
#   3. The admin deactivates and deletes the device; the user's devices list is empty again.
#   4. The user's policy is AWS's "deny unless MFA": Allow iam:GetUser on itself, Deny everything but the
#      MFA calls when BoolIfExists aws:MultiFactorAuthPresent is false. Its long-term access key is denied
#      GetUser (the explicit Deny: an access key never carries MFA); the session obtained with MFA is
#      allowed it. (Last, as it needs IAM policy to decide for the user; inconclusive when it does not.)
#
# Also: the device is a Secret in the credential store namespace labelled for the user (its data is never
# read), and the admission guard refuses the aws-shim's ServiceAccount an unlabelled iam-mfa-* Secret (a
# server-side dry run, nothing written).
#
# Codes are never reused: each one is computed for a TOTP step after the last one the probe used, waiting
# for the next step when needed (so the probe takes a minute or two). The probe and the shim must agree on
# the time within 30 seconds (NTP).
#
# On demand (a deployed shim with STS enabled, the IAM CRDs, kubectl as a cluster operator). IAM policy must
# decide for the probe's user: run under IAM_AUTHZ=enforce, or PRINCIPAL_MODE=canary under shadow.
# Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-iam-mfa.sh
#   PRINCIPAL_MODE=canary …   # the user is decided by IAM policy while the platform runs in shadow
#   ./probe/aws-shim-iam-mfa.sh --totp-selftest   # the probe's TOTP against RFC 6238's vectors; no cluster
set -uo pipefail

# totp <base32-seed-file> <step>: the six-digit code of one TOTP step (RFC 6238: HMAC-SHA1 over the step,
# dynamic truncation).
totp() {
  python3 - "$1" "$2" <<'PY'
import base64, hashlib, hmac, struct, sys
seed = open(sys.argv[1]).read().strip().upper()
key = base64.b32decode(seed + "=" * (-len(seed) % 8))
mac = hmac.new(key, struct.pack(">Q", int(sys.argv[2])), hashlib.sha1).digest()
off = mac[-1] & 0x0F
print("%06d" % ((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 1000000))
PY
}
step_now() { python3 -c 'import time; print(int(time.time()) // 30)'; }

if [ "${1:-}" = "--totp-selftest" ]; then
  # RFC 6238 Appendix B's SHA-1 seed and times; the low six digits of its eight-digit codes.
  d="$(mktemp -d)"; trap 'rm -rf "$d"' EXIT
  printf '%s' "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" > "$d/seed"   # base32 of "12345678901234567890"
  ok=0
  for pair in 59:287082 1111111109:081804 1111111111:050471 1234567890:005924 2000000000:279037 20000000000:353130; do
    t="${pair%%:*}"; want="${pair#*:}"; got="$(totp "$d/seed" $(( t / 30 )))"
    if [ "$got" != "$want" ]; then echo "T=$t: $got, want $want"; ok=1; fi
  done
  exit "$ok"
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=probe/iam-lib.sh
. "$HERE/iam-lib.sh"

ADMIN="mfa${SFX}-admin"
USER_NAME="mfa${SFX}-user"
DEVICE="mfa${SFX}-phone"
QR_DEVICE="mfa${SFX}-qr"
SERIAL=""; QR_SERIAL=""
SEED_FILE="$PROBE_TMP/seed"
AAK=""; ASK=""
LAST_STEP=0

# admin_aws <aws args…>: as the admin, errors ignored (cleanup).
admin_aws() {
  AWS_ACCESS_KEY_ID="$AAK" AWS_SECRET_ACCESS_KEY="$ASK" AWS_SESSION_TOKEN="" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager "$@" >/dev/null 2>&1
}
cleanup() {
  if [ -n "$AAK" ]; then
    for s in "$SERIAL" "$QR_SERIAL"; do
      [ -n "$s" ] || continue
      admin_aws iam deactivate-mfa-device --user-name "$USER_NAME" --serial-number "$s"
      admin_aws iam delete-virtual-mfa-device --serial-number "$s"
    done
  fi
  # Whatever the API could not remove: only this probe's own user's devices, by its unique name.
  kubectl -n "$SHIM_NS" delete secret -l "openinfra.dev/mfa-device=true,openinfra.dev/iam-user=$USER_NAME" \
    --ignore-not-found >/dev/null 2>&1
  iamp_cleanup
}
trap cleanup EXIT

command -v aws >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v curl >/dev/null || inconclusive "curl is required"
command -v python3 >/dev/null || inconclusive "python3 is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"

# awsc <ak> <sk> <token> <aws args…>: runs the CLI; output in $PROBE_TMP/out, errors in $PROBE_TMP/err.
awsc() {
  local ak="$1" sk="$2" tok="$3"; shift 3
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_SESSION_TOKEN="$tok" AWS_REGION="$REGION" \
    AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=1 \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output json "$@" >"$PROBE_TMP/out" 2>"$PROBE_TMP/err"
}
code() { sed -n 's/.*An error occurred (\([A-Za-z]*\)).*/\1/p' "$PROBE_TMP/err" | head -1; }
err() { tr '\n' ' ' < "$PROBE_TMP/err" | cut -c1-260; }
# jget <key|index>…: a value of the last call's JSON answer (an object or list as JSON).
jget() {
  python3 - "$PROBE_TMP/out" "$@" 2>/dev/null <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
for k in sys.argv[2:]:
    v = v[int(k)] if isinstance(v, list) else v[k]
print(json.dumps(v) if isinstance(v, (list, dict)) else v)
PY
}
# admin_expect <Code> <what> <aws args…>: as the admin, the call must fail with Code.
admin_expect() {
  local want="$1" what="$2"; shift 2
  if awsc "$AAK" "$ASK" "" "$@"; then fail "$what succeeded; want $want"; fi
  [ "$(code)" = "$want" ] || fail "$what: want $want, got: $(err)"
  log "  ✓ $what → $want"
}

# fresh_code: a code for a TOTP step after the last one the probe used — waiting for the next step when the
# clock has not moved on — so no code is ever sent twice by accident. Sets CODE.
fresh_code() {
  local now
  while :; do
    now="$(step_now)"
    [ "$now" -gt "$LAST_STEP" ] && break
    sleep 2
  done
  CODE="$(totp "$SEED_FILE" "$now")"
  LAST_STEP="$now"
}

# mint <name> <groups-json> <labels-json> <inline-doc-json|"">: a local User and an access key the shim
# authenticates; sets MK_AK MK_SK. Runs in this shell, so the CREATED_* lists reach the EXIT trap.
mint() {
  local name="$1" groups="$2" labels="$3" doc="$4"
  python3 - "$name" "$USERS_NS" "$groups" "$labels" "$doc" > "$PROBE_TMP/user-$name.json" <<'PY'
import json, sys
name, ns, groups, labels, doc = sys.argv[1:6]
spec = {"displayName": name, "source": "local", "groups": json.loads(groups), "policies": []}
if doc:
    spec["inlinePolicies"] = [{"name": "mfa-required", "document": json.loads(doc)}]
print(json.dumps({"apiVersion": "iam.openinfra.dev/v1", "kind": "User",
                  "metadata": {"name": name, "namespace": ns, "labels": json.loads(labels)}, "spec": spec}))
PY
  kubectl apply -f "$PROBE_TMP/user-$name.json" >/dev/null || inconclusive "could not create User $name"
  CREATED_USERS+=("$name")
  MK_AK="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  MK_SK="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  local keysec; keysec="iam-ak-$(printf '%s' "$MK_AK" | sha256sum | cut -c1-40)"
  kubectl -n "$SHIM_NS" create secret generic "$keysec" --from-literal=accessKeyId="$MK_AK" \
    --from-literal=secretKey="$MK_SK" --from-literal=owner="$name" >/dev/null || inconclusive "could not create an access key for $name"
  CREATED_SHIM_SECRETS+=("$keysec")
}

# --- the principals ---------------------------------------------------------------------------------
log "minting an IAM admin (openinfra:admins) and a throwaway user under AWS's \"deny unless MFA\" policy"
mint "$ADMIN" '["admins"]' '{}' ""; AAK="$MK_AK"; ASK="$MK_SK"
canary='{}'
[ "${PRINCIPAL_MODE:-}" = canary ] && canary='{"openinfra.dev/iam-authz":"enforce"}'
sleep 3   # the shim reads Users through informers
awsc "$AAK" "$ASK" "" sts get-caller-identity || inconclusive "the admin's key does not authenticate: $(err)"
ACCOUNT_ID="$(jget Account)"
[ -n "$ACCOUNT_ID" ] || inconclusive "get-caller-identity answered no Account"
USER_ARN="arn:aws:iam::${ACCOUNT_ID}:user/${USER_NAME}"
# The grant names the user in any account ("*"), so it holds whatever account id the install presents.
POLICY="$(python3 - "arn:aws:iam::*:user/${USER_NAME}" <<'PY'
import json, sys
print(json.dumps({"Version": "2012-10-17", "Statement": [
    {"Sid": "AllowGetSelf", "Effect": "Allow", "Action": "iam:GetUser", "Resource": sys.argv[1]},
    {"Sid": "DenyAllExceptListedIfNoMFA", "Effect": "Deny",
     "NotAction": ["iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "iam:ListMFADevices",
                   "iam:ListVirtualMFADevices", "iam:ResyncMFADevice", "sts:GetSessionToken"],
     "Resource": "*", "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}}]}))
PY
)"
mint "$USER_NAME" '[]' "$canary" "$POLICY"; UAK="$MK_AK"; USK="$MK_SK"
SETTLED_AT=$(( $(date +%s) + IAM_SETTLE_SECONDS ))

# --- 1. the device, through the IAM API ----------------------------------------------------------------
log "1. a virtual MFA device through the IAM API"
awsc "$AAK" "$ASK" "" iam create-virtual-mfa-device --virtual-mfa-device-name "$QR_DEVICE" \
  --outfile "$PROBE_TMP/qr.png" --bootstrap-method QRCodePNG \
  || { [ "$(code)" = AccessDenied ] && inconclusive "the admin was refused create-virtual-mfa-device: $(err)"; fail "create-virtual-mfa-device (QRCodePNG): $(err)"; }
QR_SERIAL="$(jget VirtualMFADevice SerialNumber)"
[ "$(head -c 8 "$PROBE_TMP/qr.png" | od -An -tx1 | tr -d ' \n')" = "89504e470d0a1a0a" ] \
  || fail "the QRCodePNG bootstrap is not a PNG"
awsc "$AAK" "$ASK" "" iam delete-virtual-mfa-device --serial-number "$QR_SERIAL" || fail "delete-virtual-mfa-device (unassigned): $(err)"
QR_SERIAL=""
log "  ✓ create-virtual-mfa-device --bootstrap-method QRCodePNG wrote a PNG; the unassigned device deleted"

awsc "$AAK" "$ASK" "" iam create-virtual-mfa-device --virtual-mfa-device-name "$DEVICE" \
  --outfile "$SEED_FILE" --bootstrap-method Base32StringSeed || fail "create-virtual-mfa-device (Base32StringSeed): $(err)"
SERIAL="$(jget VirtualMFADevice SerialNumber)"
[ "$SERIAL" = "arn:aws:iam::${ACCOUNT_ID}:mfa/${DEVICE}" ] || fail "the serial number is '$SERIAL', want arn:aws:iam::${ACCOUNT_ID}:mfa/${DEVICE}"
python3 -c 'import base64,sys; s=open(sys.argv[1]).read().strip(); assert len(base64.b32decode(s + "=" * (-len(s) % 8))) >= 10' "$SEED_FILE" 2>/dev/null \
  || fail "the Base32StringSeed bootstrap is not a base32 seed"
log "  ✓ create-virtual-mfa-device → $SERIAL (seed written to the outfile)"
admin_expect EntityAlreadyExists "a second device of the same name" iam create-virtual-mfa-device \
  --virtual-mfa-device-name "$DEVICE" --outfile "$PROBE_TMP/dup" --bootstrap-method Base32StringSeed
awsc "$AAK" "$ASK" "" iam list-virtual-mfa-devices --assignment-status Unassigned || fail "list-virtual-mfa-devices: $(err)"
grep -q "$SERIAL" "$PROBE_TMP/out" || fail "the new device is not listed Unassigned: $(head -c 300 "$PROBE_TMP/out")"
log "  ✓ listed Unassigned"

# Two codes that are not consecutive (the later step first) are refused.
fresh_code; now="$LAST_STEP"
c_prev="$(totp "$SEED_FILE" $(( now - 1 )))"
admin_expect InvalidAuthenticationCode "enable-mfa-device with codes out of order" iam enable-mfa-device \
  --user-name "$USER_NAME" --serial-number "$SERIAL" --authentication-code1 "$CODE" --authentication-code2 "$c_prev"
awsc "$AAK" "$ASK" "" iam enable-mfa-device --user-name "$USER_NAME" --serial-number "$SERIAL" \
  --authentication-code1 "$c_prev" --authentication-code2 "$CODE" || fail "enable-mfa-device with two consecutive codes: $(err)"
log "  ✓ enable-mfa-device with two consecutive codes"

awsc "$AAK" "$ASK" "" iam list-mfa-devices --user-name "$USER_NAME" || fail "list-mfa-devices: $(err)"
[ "$(jget MFADevices 0 SerialNumber)" = "$SERIAL" ] || fail "list-mfa-devices does not show the device: $(head -c 300 "$PROBE_TMP/out")"
awsc "$AAK" "$ASK" "" iam list-virtual-mfa-devices --assignment-status Assigned || fail "list-virtual-mfa-devices Assigned: $(err)"
python3 - "$PROBE_TMP/out" "$SERIAL" "$USER_NAME" <<'PY' || fail "list-virtual-mfa-devices Assigned: $(head -c 300 "$PROBE_TMP/out")"
import json, sys
devs = {d["SerialNumber"]: d for d in json.load(open(sys.argv[1]))["VirtualMFADevices"]}
d = devs[sys.argv[2]]
assert d["User"]["UserName"] == sys.argv[3] and d.get("EnableDate"), d
PY
awsc "$AAK" "$ASK" "" iam list-virtual-mfa-devices --assignment-status Unassigned || fail "list-virtual-mfa-devices Unassigned: $(err)"
grep -q "$SERIAL" "$PROBE_TMP/out" && fail "an assigned device is listed Unassigned"
log "  ✓ list-mfa-devices and list-virtual-mfa-devices (Assigned, with its user)"
admin_expect DeleteConflict "delete-virtual-mfa-device while assigned" iam delete-virtual-mfa-device --serial-number "$SERIAL"
admin_expect DeleteConflict "delete-user while it holds an MFA device" iam delete-user --user-name "$USER_NAME"

# Where the seed lives: a Secret in the credential store, labelled for the user (its data is not read).
n="$(kubectl -n "$SHIM_NS" get secrets -l "openinfra.dev/mfa-device=true,openinfra.dev/iam-user=$USER_NAME,openinfra.dev/iam-user-namespace=$USERS_NS" -o name 2>/dev/null | wc -l)"
[ "$n" = 1 ] || fail "want one device Secret labelled for $USER_NAME in $SHIM_NS, found $n"
log "  ✓ the device is one Secret in $SHIM_NS, labelled for $USER_NAME"

# --- 2. MFA sessions ------------------------------------------------------------------------------------
log "2. get-session-token with and without MFA"
if ! awsc "$UAK" "$USK" "" sts get-session-token --serial-number "$SERIAL" --token-code 000000; then
  if grep -qiE 'not enabled on this shim|no signing key' "$PROBE_TMP/err"; then
    inconclusive "STS is not enabled on this shim (no Vault sts/signing-key): GetSessionToken is gated. Enable STS and re-run."
  fi
  [ "$(code)" = AccessDenied ] || fail "get-session-token with a wrong code: want AccessDenied, got: $(err)"
  grep -q "invalid MFA one time pass code" "$PROBE_TMP/err" || fail "a wrong code's AccessDenied is not AWS's message: $(err)"
  log "  ✓ get-session-token with a wrong code → AccessDenied"
else
  # 000000 could, once in a million, be the right code: the session is real, and a fresh code follows.
  log "  · 000000 happened to be the right code"
fi

fresh_code
awsc "$UAK" "$USK" "" sts get-session-token --serial-number "$SERIAL" --token-code "$CODE" --duration-seconds 900 \
  || fail "get-session-token with a fresh code: $(err)"
read -r MAK MSK MTOK <<<"$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["Credentials"]; print(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"])' "$PROBE_TMP/out")"
[ "${MAK:0:4}" = ASIA ] && [ -n "$MTOK" ] || fail "get-session-token answered no temporary credentials: $(head -c 300 "$PROBE_TMP/out")"
log "  ✓ get-session-token with the device's code → a session ($MAK)"

if awsc "$UAK" "$USK" "" sts get-session-token --serial-number "$SERIAL" --token-code "$CODE"; then
  fail "the same MFA code was accepted twice"
fi
[ "$(code)" = AccessDenied ] || fail "a replayed code: want AccessDenied, got: $(err)"
log "  ✓ the same code again → AccessDenied (no replay)"

awsc "$MAK" "$MSK" "$MTOK" sts get-caller-identity || fail "get-caller-identity with the MFA session: $(err)"
[ "$(jget Arn)" = "$USER_ARN" ] || fail "the MFA session is '$(jget Arn)', want the user $USER_ARN"
log "  ✓ the MFA session is the user"

awsc "$UAK" "$USK" "" sts get-session-token --duration-seconds 900 || fail "get-session-token without MFA: $(err)"
read -r NAK NSK NTOK <<<"$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["Credentials"]; print(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"])' "$PROBE_TMP/out")"
if awsc "$NAK" "$NSK" "$NTOK" iam get-user --user-name "$USER_NAME"; then
  fail "a GetSessionToken session obtained without MFA called IAM"
fi
[ "$(code)" = InvalidClientTokenId ] || fail "IAM with a session without MFA: want InvalidClientTokenId, got: $(err)"
if awsc "$NAK" "$NSK" "$NTOK" sts get-session-token; then fail "session credentials obtained another session"; fi
[ "$(code)" = AccessDenied ] || fail "get-session-token with session credentials: want AccessDenied, got: $(err)"
log "  ✓ a session without MFA calls no IAM (InvalidClientTokenId) and gets no further session"

# --- the admission guard ---------------------------------------------------------------------------------
log "the admission guard (server-side dry run as the aws-shim's ServiceAccount; nothing is written)"
if kubectl -n "$SHIM_NS" create secret generic "iam-mfa-guard-$SFX" --from-literal=seed=x --dry-run=server \
     --as="system:serviceaccount:$SHIM_NS:aws-shim" -o name >/dev/null 2>"$PROBE_TMP/vap"; then
  fail "an unlabelled iam-mfa-* Secret was admitted for the aws-shim: is platform/aws-shim/mfa-device-guard.yaml synced?"
elif grep -q "openinfra-mfa-device-guard\|both or neither" "$PROBE_TMP/vap"; then
  log "  ✓ refused by openinfra-mfa-device-guard"
elif grep -qi "cannot impersonate" "$PROBE_TMP/vap"; then
  log "  · skipped: this kubectl identity cannot impersonate the shim's ServiceAccount"
else
  fail "the dry run was refused, but not by the MFA device guard: $(tr '\n' ' ' < "$PROBE_TMP/vap" | cut -c1-240)"
fi

# --- 3. deactivate and delete --------------------------------------------------------------------------
log "3. deactivate-mfa-device and delete-virtual-mfa-device"
awsc "$AAK" "$ASK" "" iam deactivate-mfa-device --user-name "$USER_NAME" --serial-number "$SERIAL" || fail "deactivate-mfa-device: $(err)"
awsc "$AAK" "$ASK" "" iam list-mfa-devices --user-name "$USER_NAME" || fail "list-mfa-devices: $(err)"
[ "$(jget MFADevices)" = "[]" ] || fail "the user still lists a device after deactivate-mfa-device: $(head -c 300 "$PROBE_TMP/out")"
awsc "$AAK" "$ASK" "" iam delete-virtual-mfa-device --serial-number "$SERIAL" || fail "delete-virtual-mfa-device: $(err)"
admin_expect NoSuchEntity "a second delete-virtual-mfa-device" iam delete-virtual-mfa-device --serial-number "$SERIAL"
SERIAL=""
# Read by the device-name annotation alone (never a Secret's data).
if kubectl -n "$SHIM_NS" get secrets -l openinfra.dev/mfa-device=true \
     -o jsonpath='{range .items[*]}{.metadata.annotations.openinfra\.dev/mfa-device-name}{"\n"}{end}' 2>/dev/null | grep -qx "$DEVICE"; then
  fail "the device Secret outlived delete-virtual-mfa-device"
fi
log "  ✓ the device is deactivated and deleted"

# --- 4. the "deny unless MFA" policy ----------------------------------------------------------------------
# Last: it needs IAM policy to decide for the user, and ends inconclusive when it does not. The MFA session
# was authenticated with MFA when it was minted; it keeps that whatever became of the device.
log "4. AWS's \"deny unless MFA\" policy decides with the credential's MFA"
left=$(( SETTLED_AT - $(date +%s) )); [ "$left" -gt 0 ] && sleep "$left"
denied_explicitly=false
for _ in $(seq 1 10); do
  if awsc "$UAK" "$USK" "" iam get-user --user-name "$USER_NAME"; then
    fail "the user's long-term access key was allowed iam:GetUser under \"deny unless MFA\": aws:MultiFactorAuthPresent must be absent for an access key, and BoolIfExists false must deny it"
  fi
  if [ "$(code)" = AccessDenied ] && grep -q "explicit Deny" "$PROBE_TMP/err"; then denied_explicitly=true; break; fi
  sleep 3
done
[ "$denied_explicitly" = true ] || inconclusive "the long-term key was refused, but not by the policy's explicit Deny ($(err)): IAM policy does not decide for $USER_NAME — run under IAM_AUTHZ=enforce, or PRINCIPAL_MODE=canary under shadow"
log "  ✓ the long-term key is denied iam:GetUser by the explicit Deny (an access key never carries MFA)"
awsc "$MAK" "$MSK" "$MTOK" iam get-user --user-name "$USER_NAME" \
  || fail "the MFA session was refused iam:GetUser — it must carry aws:MultiFactorAuthPresent true: $(err)"
log "  ✓ the session obtained with MFA is allowed iam:GetUser by the same policy"

printf '\n✓ PASS — IAM virtual MFA: a device created (QR code, seed) and enabled with two consecutive TOTP codes,\n'
printf '  listed and deleted as IAM answers them; under "deny unless MFA" the long-term key is denied and the\n'
printf '  GetSessionToken session obtained with a fresh code is allowed; wrong and replayed codes are AccessDenied,\n'
printf '  and a session without MFA calls no IAM. The seed is a Secret in the credential store, under its guard.\n'
