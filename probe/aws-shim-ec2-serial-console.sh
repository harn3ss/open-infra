#!/usr/bin/env bash
# Compatibility probe for EC2 Serial Console: the account setting (ec2 enable/disable/get serial console
# access), EC2 Instance Connect's send-serial-console-ssh-public-key, and the SSH endpoint it opens, driven
# with the REAL AWS CLI and OpenSSH against a VM the probe launches. It asserts:
#   - with the account's access off, a key push is SerialConsoleAccessDisabledException
#   - enable-serial-console-access turns it on (get-serial-console-access-status reads true)
#   - a pushed key lets `ssh <instance id>.port0@<endpoint>` in to the guest's serial console: a login prompt
#   - while that session is open, a second push is SerialConsoleSessionLimitExceededException
#   - a key that was not pushed, and a pushed key after 60 seconds, are refused by the endpoint
# and the NEGATIVE that is the point:
#   - a principal allowed ec2:* and ec2-instance-connect:* but denied
#     ec2-instance-connect:SendSerialConsoleSSHPublicKey on this instance is refused (AccessDeniedException)
# The account's access is put back as the probe found it.
#
# On-demand (needs a deployed shim with the EC2 front door and its serial console endpoint, KubeVirt, and the
# platform IAM; it launches one small Ubuntu VM in the stack namespace and terminates it). Exit 0 = pass,
# 1 = a real failure, 42 = INCONCLUSIVE (a prerequisite was missing).
#
#   SHIM_ENDPOINT=http://localhost:4566 [SERIAL_ENDPOINT=<host>[:<port>]] ./probe/aws-shim-ec2-serial-console.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
CFN_NS="${CFN_NS:-open-infra-cfn}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
VM="ec2-serial-probe-$SFX"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for c in aws kubectl ssh ssh-keygen; do command -v "$c" >/dev/null || inconclusive "$c is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"
if [ -z "${SERIAL_ENDPOINT:-}" ]; then
  SERIAL_ENDPOINT="$(kubectl -n "$SHIM_NS" get svc aws-shim-serial-console -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)"
fi
[ -n "$SERIAL_ENDPOINT" ] || inconclusive "the serial console endpoint has no address (set SERIAL_ENDPOINT=<host>[:<port>])"
SHOST="${SERIAL_ENDPOINT%%:*}"; SPORT=22
[[ "$SERIAL_ENDPOINT" == *:* ]] && SPORT="${SERIAL_ENDPOINT##*:}"

CREATED_KEYS=(); CREATED_USERS=(); CREATED_POLICIES=(); MADE_VM=""; WAK=""; WSK=""; WAS_ON=""; SSH_PID=""
cleanup() {
  [ -n "$SSH_PID" ] && kill "$SSH_PID" 2>/dev/null || true
  if [ -n "$WAK" ] && [ "$WAS_ON" = False ]; then
    AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager \
      ec2 disable-serial-console-access >/dev/null 2>&1 || true
  fi
  [ -n "$MADE_VM" ] && kubectl -n "$CFN_NS" delete virtualmachines.openinfra.dev "$MADE_VM" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  for k in "${CREATED_KEYS[@]:-}";       do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}";      do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for pol in "${CREATED_POLICIES[@]:-}"; do [ -n "$pol" ] && kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev "$pol" --ignore-not-found >/dev/null 2>&1 || true; done
  rm -rf "$TMP"
}
trap cleanup EXIT

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }

mint_key() { # <owner> <group>; sets MK_AK MK_SK (runs in THIS shell so CREATED_* reach cleanup)
  local owner="$1" group="$2"
  local ak="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  local sk; sk="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "${owner}", namespace: "${USERS_NS}" }
spec: { displayName: "${owner}", groups: ["${group}"], source: local }
YAML
  CREATED_USERS+=("$owner")
  local name; name="$(secret_name "$ak")"
  kubectl -n "$SHIM_NS" create secret generic "$name" \
    --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  CREATED_KEYS+=("$name")
  MK_AK="$ak"; MK_SK="$sk"
}

as() { # AK SK -- <aws args...>
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$@"
}

push() { # AK SK keyfile -> the CLI's answer (stderr to $TMP/push.err)
  as "$1" "$2" ec2-instance-connect send-serial-console-ssh-public-key --instance-id "$IID" --serial-port 0 \
    --ssh-public-key "file://$3" --query Success 2>"$TMP/push.err"
}

serial_ssh() { # keyfile seconds -> the session's output, sending a return after 3s
  { sleep 3; printf '\r'; sleep "$2"; } | timeout "$(( $2 + 10 ))" ssh -T -i "$1" -p "$SPORT" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o BatchMode=yes \
    -o ConnectTimeout=10 "$IID.port0@$SHOST" 2>&1 || true
}

# --- 1. an instance --------------------------------------------------------------------------------
log "launching $VM (ubuntu-24.04, 1 vCPU, 1 GiB) in $CFN_NS"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: openinfra.dev/v1
kind: VirtualMachine
metadata: { name: "${VM}", namespace: "${CFN_NS}" }
spec: { os: ubuntu-24.04, cpu: 1, memory: 1Gi, diskSize: 10Gi }
YAML
MADE_VM="$VM"
IID=""
for _ in $(seq 1 60); do
  IID="$(kubectl -n "$CFN_NS" get virtualmachines.openinfra.dev "$VM" -o jsonpath='{.status.instanceId}' 2>/dev/null || true)"
  [ -n "$IID" ] && break
  sleep 5
done
[[ "$IID" =~ ^i-[0-9a-f]{17}$ ]] || inconclusive "the VM reported no instance id in 5 minutes (got '$IID')"
log "  instance $IID"

# --- 2. principals -----------------------------------------------------------------------------------
log "seeding an admin principal and one denied the key push on $IID"
mint_key "ec2-serial-probe-$SFX" "admins"; WAK="$MK_AK"; WSK="$MK_SK"
mint_key "ec2-serial-probe-deny-$SFX" "admins"; DAK="$MK_AK"; DSK="$MK_SK"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "ec2-serial-deny-$SFX", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::ec2-serial-probe-deny-$SFX"]
    statements:
      - { effect: Allow, actions: ["ec2:*", "ec2-instance-connect:*"], resources: ["*"] }
      - { effect: Deny,  actions: ["ec2-instance-connect:SendSerialConsoleSSHPublicKey"], resources: ["Instance::${IID}"] }
YAML
CREATED_POLICIES+=("ec2-serial-deny-$SFX")
ssh-keygen -q -t ed25519 -N '' -C "probe@example.test" -f "$TMP/k1" >/dev/null
ssh-keygen -q -t ed25519 -N '' -C "probe@example.test" -f "$TMP/k2" >/dev/null

log "waiting for the guest to boot to a login prompt (get-console-output)"
for _ in $(seq 1 60); do
  as "$WAK" "$WSK" ec2 get-console-output --instance-id "$IID" --latest --query Output 2>/dev/null | grep -q "login:" && break
  sleep 10
done
as "$WAK" "$WSK" ec2 get-console-output --instance-id "$IID" --latest --query Output 2>/dev/null | grep -q "login:" \
  || fail "the guest did not reach a login prompt in 10 minutes"

# --- 3. the account setting -----------------------------------------------------------------------------
WAS_ON="$(as "$WAK" "$WSK" ec2 get-serial-console-access-status --query SerialConsoleAccessEnabled)" || fail "get-serial-console-access-status failed"
log "the account's serial console access was $WAS_ON; with it off, a key push is SerialConsoleAccessDisabledException"
as "$WAK" "$WSK" ec2 disable-serial-console-access >/dev/null || fail "disable-serial-console-access failed"
[ "$(as "$WAK" "$WSK" ec2 get-serial-console-access-status --query SerialConsoleAccessEnabled)" = False ] || fail "access reads on after disable"
if push "$WAK" "$WSK" "$TMP/k1.pub" >/dev/null; then fail "a key push succeeded with access off"; fi
grep -q "SerialConsoleAccessDisabledException" "$TMP/push.err" || fail "a push with access off gave $(cat "$TMP/push.err")"
[ "$(as "$WAK" "$WSK" ec2 enable-serial-console-access --query SerialConsoleAccessEnabled)" = True ] || fail "enable-serial-console-access did not answer true"
[ "$(as "$WAK" "$WSK" ec2 get-serial-console-access-status --query SerialConsoleAccessEnabled)" = True ] || fail "access reads off after enable"
log "  ✓ off: SerialConsoleAccessDisabledException; enable-serial-console-access turns it on"

# --- 4. the denial ----------------------------------------------------------------------------------------
log "a principal denied ec2-instance-connect:SendSerialConsoleSSHPublicKey on $IID is refused (the policy loader takes ~35s)"
DENIED=""
for _ in $(seq 1 9); do
  if ! push "$DAK" "$DSK" "$TMP/k2.pub" >/dev/null && grep -q "AccessDeniedException" "$TMP/push.err"; then DENIED=1; break; fi
  sleep 10
done
[ -n "$DENIED" ] || fail "a denied key push was not refused with AccessDeniedException: $(cat "$TMP/push.err")"
as "$DAK" "$DSK" ec2 describe-instances --instance-ids "$IID" >/dev/null || fail "the denied principal's other EC2 access stopped working"
log "  ✓ AccessDeniedException; the principal's other EC2 access stands"

# --- 5. a session ---------------------------------------------------------------------------------------------
log "send-serial-console-ssh-public-key, then ssh $IID.port0@$SHOST:$SPORT reaches the serial console"
[ "$(push "$WAK" "$WSK" "$TMP/k1.pub")" = True ] || fail "the key push failed: $(cat "$TMP/push.err")"
serial_ssh "$TMP/k1" 12 > "$TMP/session.out" &
SSH_PID=$!
sleep 6
if push "$WAK" "$WSK" "$TMP/k1.pub" >/dev/null; then fail "a second push succeeded while a session was open"; fi
grep -q "SerialConsoleSessionLimitExceededException" "$TMP/push.err" || fail "a push during a session gave $(cat "$TMP/push.err")"
wait "$SSH_PID" || true; SSH_PID=""
grep -q "login:" "$TMP/session.out" || fail "the session showed no login prompt: $(tail -c 300 "$TMP/session.out")"
log "  ✓ a login prompt over SSH; a second push during it is SerialConsoleSessionLimitExceededException"

# --- 6. what the endpoint refuses ---------------------------------------------------------------------------------
log "a key that was not pushed is refused, and so is a pushed key after 60 seconds"
sleep 12 # the session's lease is released when it ends
[ "$(push "$WAK" "$WSK" "$TMP/k1.pub")" = True ] || fail "the key push failed: $(cat "$TMP/push.err")"
serial_ssh "$TMP/k2" 2 > "$TMP/other.out"
grep -q "Permission denied" "$TMP/other.out" || fail "a key that was not pushed got in: $(tail -c 300 "$TMP/other.out")"
sleep 62
serial_ssh "$TMP/k1" 2 > "$TMP/late.out"
grep -q "Permission denied" "$TMP/late.out" || fail "a pushed key got in after 60 seconds: $(tail -c 300 "$TMP/late.out")"
log "  ✓ Permission denied for both"

log "PASS: EC2 Serial Console (access setting, SendSerialConsoleSSHPublicKey, the SSH endpoint)"
