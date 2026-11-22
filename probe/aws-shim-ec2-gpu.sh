#!/usr/bin/env bash
# Probe: a GPU instance (g4dn.xlarge) gets a whole GPU of its own, and EC2's limits refuse it as on AWS.
#
# Through the real AWS CLI:
#   1. the management account's administrator creates a throwaway member account (Organizations
#      CreateAccount) and assumes its OrganizationAccountAccessRole; the operator gives the account no GPUs
#      (kind: Account spec.capacity.gpus 0);
#   2. DescribeInstanceTypes names g4dn.xlarge's GPU (GpuInfo: the installation's card, one of it);
#   3. a stack whose instance is a g4dn.xlarge fails with EC2's VcpuLimitExceeded (the account's GPU limit)
#      and rolls back;
#   4. with GPUs allowed, a g4dn.xlarge stack completes: the instance is a g4dn.xlarge, and its guest finds a
#      display device that is not an emulated one on its PCI bus (its UserData prints the bus's display
#      devices to the serial console, read with GetConsoleOutput);
#   5. a second g4dn.xlarge, while the first holds the card, fails with InsufficientInstanceCapacity;
#   6. DENIAL: a user of the member account with no policy is refused DescribeInstanceTypes
#      (UnauthorizedOperation).
# Everything the probe made is removed on exit: the stacks, the user, the member account and its home
# namespace (only when this run created it), and the administrator and its key. A free GPU card is needed:
# if every card is in use, the probe is inconclusive.
#
# Needs: aws (v2), kubectl (a cluster operator), curl, python3; a deployed shim with the Organizations, STS,
# IAM, CloudFormation and EC2 front doors, the compliance component (account capacity), and a card set aside
# for GPU instances (docs/gpu-instances.md). Exit 0 = pass, 1 = fail, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-ec2-gpu.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SETTLE="${IAM_SETTLE_SECONDS:-35}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
NAME="gpu-$SFX"
TMP="$(mktemp -d)"
START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

log()  { printf '▸ %s\n' "$*"; }
ok()   { printf '▸   ✓ %s\n' "$*"; }
die()  { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for t in aws kubectl curl python3; do command -v "$t" >/dev/null || inconclusive "$t is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
kubectl get crd accounts.organizations.openinfra.dev >/dev/null 2>&1 || inconclusive "the Account kind is not installed"
kubectl get clusterpolicy account-capacity-quota >/dev/null 2>&1 || inconclusive "account capacity is not enforced here (no compliance component)"

OWNER="gpu-admin-$SFX"; AK=""; SK=""; KS=""; NEW_ACCOUNT=""; NEW_HOME=""
CLEAN=() # commands run on exit, in reverse
cleanup() {
  local i
  for ((i=${#CLEAN[@]}-1; i>=0; i--)); do eval "${CLEAN[$i]}" >/dev/null 2>&1 || true; done
  [ -n "$NEW_ACCOUNT" ] && kubectl delete accounts.organizations.openinfra.dev "$NEW_ACCOUNT" --ignore-not-found --wait=false >/dev/null 2>&1
  if [ -n "$NEW_HOME" ]; then
    created="$(kubectl get ns "$NEW_HOME" -o jsonpath='{.metadata.creationTimestamp}' 2>/dev/null)"
    if [ -n "$created" ] && [[ "$created" > "$START" || "$created" == "$START" ]]; then
      kubectl delete ns "$NEW_HOME" --ignore-not-found --wait=false >/dev/null 2>&1
    fi
  fi
  [ -n "$KS" ] && kubectl -n "$SHIM_NS" delete secret "$KS" --ignore-not-found >/dev/null 2>&1
  kubectl -n "$USERS_NS" delete users.iam.openinfra.dev "$OWNER" --ignore-not-found >/dev/null 2>&1
  rm -rf "$TMP"
  return 0
}
trap cleanup EXIT

# gpus sets the member account's GPU capacity (and room for two instances' disks) and waits until its home
# namespace enforces it for GPU instances.
gpus() {
  kubectl patch accounts.organizations.openinfra.dev "$NEW_ACCOUNT" --type merge \
    -p "{\"spec\":{\"capacity\":{\"gpus\":$1,\"storage\":\"80Gi\"}}}" >/dev/null || inconclusive "could not set the account's capacity"
  for _ in $(seq 1 60); do
    [ "$(kubectl -n "$NEW_HOME" get resourcequota account-capacity-gpu -o jsonpath='{.spec.hard.requests\.openinfra\.dev/instance-gpu}' 2>/dev/null)" = "$1" ] && return 0
    sleep 5
  done
  inconclusive "the account's GPU capacity of $1 was not enforced for GPU instances in $NEW_HOME"
}

# stack_settles waits (up to $2 seconds) for stack $1 to leave its *_IN_PROGRESS status, and prints it.
stack_settles() {
  local st=""
  for _ in $(seq 1 $(($2 / 10))); do
    st="$(B cloudformation describe-stacks --stack-name "$1" --query 'Stacks[0].StackStatus' --output text 2>/dev/null)"
    case "$st" in *_IN_PROGRESS|"") sleep 10 ;; *) break ;; esac
  done
  printf '%s' "$st"
}

# why prints the reason stack $1's instance Box failed to create.
why() {
  B cloudformation describe-stack-events --stack-name "$1" \
    --query "StackEvents[?LogicalResourceId=='Box' && ResourceStatus=='CREATE_FAILED'].ResourceStatusReason | [0]" --output text 2>/dev/null
}

# --- 1. the management account's administrator, a member account, and no GPUs ----------------------------
AK="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
SK="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
KS="iam-ak-$(printf '%s' "$AK" | sha256sum | cut -c1-40)"
printf 'apiVersion: iam.openinfra.dev/v1\nkind: User\nmetadata: { name: "%s", namespace: "%s" }\nspec: { displayName: "%s", groups: ["admins"], source: local }\n' \
  "$OWNER" "$USERS_NS" "$OWNER" | kubectl apply -f - >/dev/null || inconclusive "could not create the administrator"
kubectl -n "$SHIM_NS" create secret generic "$KS" --from-literal=accessKeyId="$AK" --from-literal=secretKey="$SK" \
  --from-literal=owner="$OWNER" >/dev/null || inconclusive "could not create the administrator's key"
M() { AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" "$@"; }
for _ in $(seq 1 20); do M sts get-caller-identity >/dev/null 2>&1 && break; sleep 3; done
sleep "$SETTLE"
M sts get-caller-identity >/dev/null 2>&1 || inconclusive "the administrator's key does not authenticate"

log "1. a member account with no GPUs"
car="$(M organizations create-account --email "$NAME@example.com" --account-name "$NAME" --query 'CreateAccountStatus.Id' --output text 2>"$TMP/err")" \
  || inconclusive "create-account: $(tr '\n' ' ' < "$TMP/err")"
for _ in $(seq 1 60); do
  read -r state acct < <(M organizations describe-create-account-status --create-account-request-id "$car" \
    --query 'CreateAccountStatus.[State,AccountId]' --output text 2>/dev/null)
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
gpus 0
sleep "$SETTLE"
M sts assume-role --role-arn "arn:aws:iam::$NEW_ACCOUNT:role/OrganizationAccountAccessRole" \
  --role-session-name gpu --output json > "$TMP/session.json" 2>"$TMP/err" \
  || die "assume-role into the member account: $(tr '\n' ' ' < "$TMP/err")"
read -r MAK MSK MST < <(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["Credentials"]; print(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"])' "$TMP/session.json")
B() { AWS_ACCESS_KEY_ID="$MAK" AWS_SECRET_ACCESS_KEY="$MSK" AWS_SESSION_TOKEN="$MST" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" "$@"; }
[ "$(B sts get-caller-identity --query Account --output text 2>/dev/null)" = "$NEW_ACCOUNT" ] || die "the assumed session is not the member account's"
AMI="$(B ec2 describe-images --owners amazon --filters Name=name,Values=ubuntu-24.04 --query 'Images[0].ImageId' --output text 2>/dev/null)"
case "$AMI" in ami-*) ;; *) inconclusive "no ubuntu-24.04 image is listed (got '$AMI')" ;; esac
ok "acting in member account $NEW_ACCOUNT (home $NEW_HOME), image $AMI"

# --- 2. the instance type names its GPU -------------------------------------------------------------------
log "2. DescribeInstanceTypes names g4dn.xlarge's GPU"
B ec2 describe-instance-types --instance-types g4dn.xlarge --output json > "$TMP/type.json" 2>"$TMP/err" || {
  grep -q InvalidInstanceType "$TMP/err" && inconclusive "this installation offers no GPU instances (g4dn.xlarge is not listed)"
  die "describe-instance-types: $(tr '\n' ' ' < "$TMP/err")"
}
GPU="$(python3 -c '
import json,sys
t=json.load(open(sys.argv[1]))["InstanceTypes"][0]
g=t.get("GpuInfo",{}).get("Gpus",[{}])[0]
assert t["VCpuInfo"]["DefaultVCpus"]==4 and t["MemoryInfo"]["SizeInMiB"]==16384, t
assert g.get("Name") and g.get("Count")==1, t.get("GpuInfo")
print(" ".join(str(x) for x in [g.get("Manufacturer",""), g["Name"], str(g.get("MemoryInfo",{}).get("SizeInMiB","?"))+" MiB"]))' "$TMP/type.json" 2>"$TMP/err")" \
  || die "g4dn.xlarge is not 4 vCPUs, 16 GiB and one named GPU: $(tail -c 300 "$TMP/err")"
ok "g4dn.xlarge: 4 vCPUs, 16 GiB, 1 GPU ($GPU)"

cat > "$TMP/gpu.yaml" <<EOF
Resources:
  Box:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: $AMI
      InstanceType: g4dn.xlarge
      UserData:
        Fn::Base64: |
          #!/bin/bash
          for d in /sys/bus/pci/devices/*; do
            case "\$(cat \$d/class)" in 0x03*) echo "GPU-PROBE pci \$(cat \$d/vendor):\$(cat \$d/device) class \$(cat \$d/class)" ;; esac
          done > /dev/ttyS0
Outputs:
  InstanceId: { Value: !Ref Box }
EOF

# --- 3. the account's GPU limit refuses it ----------------------------------------------------------------
log "3. a g4dn.xlarge in an account with no GPUs fails with VcpuLimitExceeded"
B cloudformation create-stack --stack-name "$NAME-nogpu" --template-body "file://$TMP/gpu.yaml" >/dev/null 2>"$TMP/err" \
  || die "create-stack: $(tr '\n' ' ' < "$TMP/err")"
CLEAN+=("B cloudformation delete-stack --stack-name $NAME-nogpu")
t0=$(date +%s)
st="$(stack_settles "$NAME-nogpu" 900)"
took=$(( $(date +%s) - t0 ))
why "$NAME-nogpu" > "$TMP/why"
[ "$st" = ROLLBACK_COMPLETE ] || die "the refused stack is $st after ${took}s, want ROLLBACK_COMPLETE: $(head -c 300 "$TMP/why")"
grep -q "Error Code: VcpuLimitExceeded" "$TMP/why" || die "the instance's failure does not name VcpuLimitExceeded: $(head -c 400 "$TMP/why")"
ok "ROLLBACK_COMPLETE after ${took}s: $(head -c 120 "$TMP/why")…"
B cloudformation delete-stack --stack-name "$NAME-nogpu" >/dev/null 2>&1

# --- 4. with GPUs allowed, the instance has a GPU of its own ----------------------------------------------
log "4. with GPUs allowed, a g4dn.xlarge's guest finds its GPU"
gpus 2 # two, so the second instance below is refused for want of a card, not by the account's limit
B cloudformation create-stack --stack-name "$NAME-gpu" --template-body "file://$TMP/gpu.yaml" >/dev/null 2>"$TMP/err" \
  || die "create-stack: $(tr '\n' ' ' < "$TMP/err")"
CLEAN+=("B cloudformation delete-stack --stack-name $NAME-gpu")
st="$(stack_settles "$NAME-gpu" 1500)"
if [ "$st" != CREATE_COMPLETE ]; then
  why "$NAME-gpu" > "$TMP/why"
  grep -q InsufficientInstanceCapacity "$TMP/why" && inconclusive "every GPU instance card is in use: $(head -c 200 "$TMP/why")"
  die "the GPU instance's stack is $st: $(head -c 400 "$TMP/why")"
fi
IID="$(B cloudformation describe-stacks --stack-name "$NAME-gpu" --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue | [0]" --output text)"
itype="$(B ec2 describe-instances --instance-ids "$IID" --query 'Reservations[0].Instances[0].InstanceType' --output text 2>/dev/null)"
[ "$itype" = g4dn.xlarge ] || die "the instance reports type '$itype', want g4dn.xlarge"
OUT=""
for _ in $(seq 1 60); do
  OUT="$(B ec2 get-console-output --instance-id "$IID" --latest --query Output --output text 2>/dev/null || true)"
  printf '%s' "$OUT" | grep -q "GPU-PROBE pci" && break
  sleep 10
done
printf '%s\n' "$OUT" | grep "GPU-PROBE pci" | tr -d '\r' > "$TMP/pci"
[ -s "$TMP/pci" ] || die "the guest's UserData never listed its display devices on the serial console"
# Emulated display devices: QEMU's standard VGA / bochs (1234), QXL (1b36), virtio-gpu (1af4).
grep -v -E "pci 0x(1234|1b36|1af4):" "$TMP/pci" > "$TMP/real" || true
[ -s "$TMP/real" ] || die "the guest sees only emulated display devices: $(tr '\n' ';' < "$TMP/pci")"
ok "$IID is a g4dn.xlarge; its guest finds $(head -1 "$TMP/real" | sed 's/^.*GPU-PROBE //') (and $(grep -c . "$TMP/pci") display device(s) in all)"

# --- 5. no card free: a second one is refused -------------------------------------------------------------
log "5. a second g4dn.xlarge, while the first holds the card, fails with InsufficientInstanceCapacity"
free="$(kubectl get nodes -o jsonpath='{range .items[*]}{.status.allocatable.openinfra\.dev/instance-gpu}{"\n"}{end}' | awk '{s+=$1} END {print s+0}')"
[ "$free" -le 1 ] || inconclusive "this installation has $free GPU instance cards: a second instance would get one"
B cloudformation create-stack --stack-name "$NAME-second" --template-body "file://$TMP/gpu.yaml" >/dev/null 2>"$TMP/err" \
  || die "create-stack: $(tr '\n' ' ' < "$TMP/err")"
CLEAN+=("B cloudformation delete-stack --stack-name $NAME-second")
st="$(stack_settles "$NAME-second" 900)"
why "$NAME-second" > "$TMP/why"
[ "$st" = ROLLBACK_COMPLETE ] || die "the second GPU instance's stack is $st, want ROLLBACK_COMPLETE: $(head -c 300 "$TMP/why")"
grep -q "Error Code: InsufficientInstanceCapacity" "$TMP/why" || die "the second instance's failure does not name InsufficientInstanceCapacity: $(head -c 400 "$TMP/why")"
ok "ROLLBACK_COMPLETE: $(head -c 120 "$TMP/why")…"

# --- 6. DENIAL: a user with no policy may not describe instance types -------------------------------------
log "6. a user of the member account with no policy is refused DescribeInstanceTypes"
B iam create-user --user-name "$NAME-nopol" >/dev/null 2>"$TMP/err" || die "create-user: $(cat "$TMP/err")"
CLEAN+=("B iam delete-user --user-name $NAME-nopol")
B iam create-access-key --user-name "$NAME-nopol" --output json >"$TMP/key.json" 2>"$TMP/err" || die "create-access-key: $(cat "$TMP/err")"
read -r NAK NSK < <(python3 -c 'import json,sys; k=json.load(open(sys.argv[1]))["AccessKey"]; print(k["AccessKeyId"], k["SecretAccessKey"])' "$TMP/key.json")
CLEAN+=("B iam delete-access-key --user-name $NAME-nopol --access-key-id $NAK")
sleep "$SETTLE"
if AWS_ACCESS_KEY_ID="$NAK" AWS_SECRET_ACCESS_KEY="$NSK" AWS_SESSION_TOKEN="" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" \
  ec2 describe-instance-types --instance-types g4dn.xlarge >/dev/null 2>"$TMP/deny"; then
  die "a user with no policy described the instance types"
fi
grep -q UnauthorizedOperation "$TMP/deny" || die "the refusal is not UnauthorizedOperation: $(tail -c 300 "$TMP/deny")"
ok "DescribeInstanceTypes by a user with no policy: UnauthorizedOperation"

for s in "$NAME-second" "$NAME-gpu" "$NAME-nogpu"; do B cloudformation delete-stack --stack-name "$s" >/dev/null 2>&1; done
for s in "$NAME-second" "$NAME-gpu" "$NAME-nogpu"; do
  for _ in $(seq 1 60); do B cloudformation describe-stacks --stack-name "$s" >/dev/null 2>&1 || break; sleep 5; done
done
printf '✓ PASS — g4dn.xlarge names its GPU (%s); an account with no GPUs was refused one with VcpuLimitExceeded; with GPUs allowed the instance ran with a GPU of its own on its PCI bus; a second, with no card free, failed with InsufficientInstanceCapacity; a user with no policy was refused DescribeInstanceTypes.\n' "$GPU"
