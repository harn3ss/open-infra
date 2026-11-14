#!/usr/bin/env bash
# Compatibility probe for EC2's "Get system log" and "Get instance screenshot" on the aws-shim.
#
# Fires REAL AWS SDK calls (the aws CLI) at a deployed shim, against a VM it launches for the purpose, and
# asserts what troubleshooting tooling depends on:
#   - get-console-output --latest answers the guest's serial console (the CLI decodes EC2's base64 Output):
#     the boot reaches a login prompt, and the text is the last 64 KB at most
#   - get-console-screenshot --wake-up answers a JPEG (EC2's base64 ImageData)
#   - once the instance is stopped: get-console-output answers no Output, as EC2 does for an instance with
#     nothing buffered, and get-console-screenshot is IncorrectInstanceState
# and the NEGATIVES:
#   - a principal whose policy allows ec2:* but denies ec2:GetConsoleOutput and ec2:GetConsoleScreenshot
#     on this instance is refused both (UnauthorizedOperation)
#   - an instance id that does not exist is InvalidInstanceID.NotFound; a name is InvalidInstanceID.Malformed
#
# On-demand (needs a deployed shim with the EC2 front door, KubeVirt, and the platform IAM; it launches one
# small Ubuntu VM in the stack namespace and terminates it). Exit 0 = pass, 1 = a real failure,
# 42 = INCONCLUSIVE (a prerequisite was missing).
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-ec2-console.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
CFN_NS="${CFN_NS:-open-infra-cfn}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
VM="ec2-console-probe-$SFX"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required to seed the principals and launch the VM"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"
kubectl get crd virtualmachines.openinfra.dev >/dev/null 2>&1 || inconclusive "kind: VirtualMachine is not installed"

CREATED_KEYS=(); CREATED_USERS=(); CREATED_POLICIES=(); MADE_VM=""
cleanup() {
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

# --- 1. an instance to look at ----------------------------------------------------------------
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

# --- 2. principals ----------------------------------------------------------------------------
log "seeding an admin principal and one denied the console reads on $IID"
mint_key "ec2-console-probe-$SFX" "admins"; WAK="$MK_AK"; WSK="$MK_SK"
mint_key "ec2-console-probe-deny-$SFX" "admins"; DAK="$MK_AK"; DSK="$MK_SK"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "ec2-console-deny-$SFX", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::ec2-console-probe-deny-$SFX"]
    statements:
      - { effect: Allow, actions: ["ec2:*"], resources: ["*"] }
      - { effect: Deny,  actions: ["ec2:GetConsoleOutput", "ec2:GetConsoleScreenshot"], resources: ["Instance::${IID}"] }
YAML
CREATED_POLICIES+=("ec2-console-deny-$SFX")

# --- 3. the system log: the guest boots to a login prompt --------------------------------------
log "waiting for the guest's serial console to reach a login prompt (get-console-output --latest)"
OUT=""
for _ in $(seq 1 60); do
  OUT="$(as "$WAK" "$WSK" ec2 get-console-output --instance-id "$IID" --latest --query Output 2>"$TMP/err" || true)"
  printf '%s' "$OUT" | grep -q "login:" && break
  sleep 10
done
printf '%s' "$OUT" | grep -q "login:" || fail "no login prompt in the system log after 10 minutes (last error: $(cat "$TMP/err"); output tail: $(printf '%s' "$OUT" | tail -c 300))"
[ "$(printf '%s' "$OUT" | wc -c)" -le 65536 ] || fail "the system log is $(printf '%s' "$OUT" | wc -c) bytes, over EC2's 64 KB"
[ "$(as "$WAK" "$WSK" ec2 get-console-output --instance-id "$IID" --query InstanceId)" = "$IID" ] || fail "get-console-output did not name the instance"
log "  ✓ the system log shows the boot to a login prompt ($(printf '%s' "$OUT" | wc -c) bytes)"

# --- 4. the screenshot: a JPEG ------------------------------------------------------------------
log "get-console-screenshot --wake-up"
as "$WAK" "$WSK" ec2 get-console-screenshot --instance-id "$IID" --wake-up --query ImageData > "$TMP/shot.b64" \
  || fail "get-console-screenshot failed: $(cat "$TMP/shot.b64")"
base64 -d "$TMP/shot.b64" > "$TMP/shot.jpg" 2>/dev/null || fail "ImageData is not base64"
[ "$(head -c 3 "$TMP/shot.jpg" | od -An -tx1 | tr -d ' \n')" = "ffd8ff" ] || fail "ImageData is not a JPEG"
log "  ✓ a $(stat -c %s "$TMP/shot.jpg")-byte JPEG of the display"

# --- 5. ids the instance isn't -----------------------------------------------------------------
log "an unknown id is InvalidInstanceID.NotFound, a name InvalidInstanceID.Malformed"
for op in get-console-output get-console-screenshot; do
  if as "$WAK" "$WSK" ec2 "$op" --instance-id i-00000000000000000 >/dev/null 2>"$TMP/nf"; then fail "ec2 $op of an unknown instance succeeded"; fi
  grep -q "InvalidInstanceID.NotFound" "$TMP/nf" || fail "ec2 $op of an unknown instance gave $(cat "$TMP/nf")"
  if as "$WAK" "$WSK" ec2 "$op" --instance-id "$VM" >/dev/null 2>"$TMP/mf"; then fail "ec2 $op took a name"; fi
  grep -q "InvalidInstanceID.Malformed" "$TMP/mf" || fail "ec2 $op of a name gave $(cat "$TMP/mf")"
done

# --- 6. the denial ---------------------------------------------------------------------------------
log "a principal denied the console reads on $IID is refused both (the policy loader takes ~35s)"
DENIED=""
for _ in $(seq 1 9); do
  if ! as "$DAK" "$DSK" ec2 get-console-output --instance-id "$IID" >/dev/null 2>"$TMP/deny" \
     && grep -q "UnauthorizedOperation" "$TMP/deny"; then DENIED=1; break; fi
  sleep 10
done
[ -n "$DENIED" ] || fail "a denied GetConsoleOutput was not refused with UnauthorizedOperation: $(cat "$TMP/deny")"
if as "$DAK" "$DSK" ec2 get-console-screenshot --instance-id "$IID" >/dev/null 2>"$TMP/deny"; then fail "a denied GetConsoleScreenshot succeeded"; fi
grep -q "UnauthorizedOperation" "$TMP/deny" || fail "a denied GetConsoleScreenshot gave $(cat "$TMP/deny")"
as "$DAK" "$DSK" ec2 describe-instances --instance-ids "$IID" >/dev/null || fail "the denied principal's other ec2 grants stopped working"
log "  ✓ UnauthorizedOperation for both; the principal's other EC2 access stands"

# --- 7. a stopped instance --------------------------------------------------------------------------
log "stop-instances, then: no Output, and a screenshot is IncorrectInstanceState"
as "$WAK" "$WSK" ec2 stop-instances --instance-ids "$IID" >/dev/null || fail "stop-instances failed"
STATE=""
for _ in $(seq 1 36); do
  STATE="$(as "$WAK" "$WSK" ec2 describe-instances --instance-ids "$IID" --query 'Reservations[0].Instances[0].State.Name' 2>/dev/null || true)"
  [ "$STATE" = stopped ] && break
  sleep 5
done
[ "$STATE" = stopped ] || fail "the instance is '$STATE' 3 minutes after stop-instances, want stopped"
[ "$(as "$WAK" "$WSK" ec2 get-console-output --instance-id "$IID" --query Output)" = "None" ] || fail "a stopped instance answered console output"
if as "$WAK" "$WSK" ec2 get-console-screenshot --instance-id "$IID" >/dev/null 2>"$TMP/st"; then fail "a stopped instance answered a screenshot"; fi
grep -q "IncorrectInstanceState" "$TMP/st" || fail "a stopped instance's screenshot gave $(cat "$TMP/st")"

log "PASS: EC2 GetConsoleOutput and GetConsoleScreenshot"
