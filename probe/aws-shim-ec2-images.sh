#!/usr/bin/env bash
# Live probe: an account makes an EC2 image of an instance, shares it, and another account launches from it.
#
# As the management account's administrator acting in two member accounts (OrganizationAccountAccessRole),
# through the AWS CLI:
#   - in ACCOUNT_ID (the image's owner): a CloudFormation stack launches a small Linux instance whose UserData
#     writes a marker file; Run Command (its role attaches AmazonSSMManagedInstanceCore) sees the marker;
#   - CreateImage of it answers an ami- id at once, pending; the image becomes available, and the instance
#     CreateImage stopped runs again;
#   - before it is shared, SHARE_ACCOUNT_ID cannot see the image (InvalidAMIID.NotFound) nor launch it (its
#     stack refuses: the image id does not exist for it);
#   - ModifyImageAttribute shares it with SHARE_ACCOUNT_ID, which then describes it (owner ACCOUNT_ID) but
#     may not read or change its attributes (AuthFailure), and launches an instance from it through
#     CloudFormation: DescribeInstances reports the image, and Run Command on it sees the marker the first
#     instance wrote;
#   - a principal with no policy is refused CreateImage with EC2's access-denied error.
# Everything it makes is deleted: both stacks, the image, the probe's principals.
#
# Exit 0 pass, 1 fail, 42 inconclusive. Needs the aws CLI, kubectl (KUBECONFIG) and curl; reaches the shim at
# SHIM_ENDPOINT (e.g. a port-forward of svc/aws-shim 4566).
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
IMAGE_WAIT="${IMAGE_WAIT_SECONDS:-2400}" # a disk copy takes minutes; a large root longer
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"
MARKER="openinfra-image-probe-${SFX}"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for c in aws kubectl curl; do command -v "$c" >/dev/null || inconclusive "$c is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

OWNER="${ACCOUNT_ID:?ACCOUNT_ID: the member account that makes the image}"
SHARED="${SHARE_ACCOUNT_ID:?SHARE_ACCOUNT_ID: another member account, which launches from it}"
[ "$OWNER" != "$SHARED" ] || inconclusive "ACCOUNT_ID and SHARE_ACCOUNT_ID must be two accounts"
ADMIN="images-admin-$SFX"; NOPOL="images-nopol-$SFX"
STACK_A="images-src-$SFX"; STACK_B="images-launch-$SFX"; STACK_DENIED="images-denied-$SFX"
IMAGE_NAME="probe build image ${SFX}"
CREATED_KEYS=(); CREATED_USERS=(); MADE_A=""; MADE_B=""; MADE_DENIED=""; AMI=""
as() { local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$@"; }
cleanup() {
  if [ -n "$MADE_B" ]; then
    in_b cloudformation delete-stack --stack-name "$STACK_B" >/dev/null 2>&1
    in_b cloudformation wait stack-delete-complete --stack-name "$STACK_B" >/dev/null 2>&1
  fi
  if [ -n "$MADE_DENIED" ]; then
    in_b cloudformation delete-stack --stack-name "$STACK_DENIED" >/dev/null 2>&1
    in_b cloudformation wait stack-delete-complete --stack-name "$STACK_DENIED" >/dev/null 2>&1
  fi
  [ -n "$AMI" ] && in_a ec2 deregister-image --image-id "$AMI" >/dev/null 2>&1
  if [ -n "$MADE_A" ]; then
    in_a cloudformation delete-stack --stack-name "$STACK_A" >/dev/null 2>&1
    in_a cloudformation wait stack-delete-complete --stack-name "$STACK_A" >/dev/null 2>&1
  fi
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1; done
  for k in "${CREATED_KEYS[@]:-}"; do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1; done
  rm -rf "$TMP"
}
trap cleanup EXIT

# mint_key <owner> [group]: a kind: User (in group, or in none) and an access key the shim authenticates;
# sets MK_AK MK_SK.
mint_key() {
  local owner="$1" group="${2:-}" ak sk name groups="[]"
  [ -n "$group" ] && groups="[\"${group}\"]"
  ak="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  sk="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  cat <<YAML | kubectl apply -f - >/dev/null || inconclusive "could not create User $owner"
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "${owner}", namespace: "${USERS_NS}" }
spec: { displayName: "${owner}", groups: ${groups}, source: local }
YAML
  CREATED_USERS+=("$owner")
  name="iam-ak-$(printf '%s' "$ak" | sha256sum | cut -c1-40)"
  kubectl -n "$SHIM_NS" create secret generic "$name" --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" \
    --from-literal=owner="$owner" >/dev/null || inconclusive "could not create the access key"
  CREATED_KEYS+=("$name")
  MK_AK="$ak"; MK_SK="$sk"
}

# act_in <account> <session>: the account's OrganizationAccountAccessRole, as the administrator; sets AI_AK
# AI_SK AI_TOK.
act_in() {
  local acct="$1" session="$2"
  AI_AK=""; AI_SK=""; AI_TOK=""
  for _ in $(seq 1 12); do
    read -r AI_AK AI_SK AI_TOK <<<"$(as "$AAK" "$ASK" sts assume-role --role-arn "arn:aws:iam::${acct}:role/OrganizationAccountAccessRole" \
      --role-session-name "$session" --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' 2>"$TMP/ar")"
    [ -n "${AI_TOK:-}" ] && return 0
    sleep 5
  done
  inconclusive "could not act in ${acct}: $(head -c 300 "$TMP/ar")"
}

log "seeding an administrator and a principal with no policy"
mint_key "$ADMIN" "admins"; AAK="$MK_AK"; ASK="$MK_SK"
mint_key "$NOPOL"; NAK="$MK_AK"; NSK="$MK_SK"
log "waiting 35s for the IAM policy world to load them"
sleep 35
act_in "$OWNER" images-probe-owner; A_AK="$AI_AK"; A_SK="$AI_SK"; A_TOK="$AI_TOK"
act_in "$SHARED" images-probe-shared; B_AK="$AI_AK"; B_SK="$AI_SK"; B_TOK="$AI_TOK"
in_a() { AWS_ACCESS_KEY_ID="$A_AK" AWS_SECRET_ACCESS_KEY="$A_SK" AWS_SESSION_TOKEN="$A_TOK" AWS_REGION="$REGION" \
  aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$@"; }
in_b() { AWS_ACCESS_KEY_ID="$B_AK" AWS_SECRET_ACCESS_KEY="$B_SK" AWS_SESSION_TOKEN="$B_TOK" AWS_REGION="$REGION" \
  aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$@"; }

# instance_template <image id> [user data, base64]: a role for Systems Manager, its instance profile, and an
# instance of the image, which the stack's InstanceId output names.
instance_template() {
  local ud=""
  [ -n "${2:-}" ] && ud=',"UserData":"'"$2"'"'
  printf '{"Resources":{"Role":{"Type":"AWS::IAM::Role","Properties":{"AssumeRolePolicyDocument":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]},"ManagedPolicyArns":["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]}},"Profile":{"Type":"AWS::IAM::InstanceProfile","Properties":{"Roles":[{"Ref":"Role"}]}},"Box":{"Type":"AWS::EC2::Instance","Properties":{"ImageId":"%s","InstanceType":"t3.small","IamInstanceProfile":{"Ref":"Profile"}%s}}},"Outputs":{"InstanceId":{"Value":{"Ref":"Box"}}}}' "$1" "$ud"
}

# run_marker <in_a|in_b> <instance id>: the marker file's content on the instance, through Run Command.
run_marker() {
  local who="$1" iid="$2" cmd out=""
  printf '{"commands":["cat /var/lib/openinfra-probe/marker 2>/dev/null || echo marker=missing"]}' > "$TMP/rc.json"
  for _ in $(seq 1 40); do
    cmd="$("$who" ssm send-command --document-name AWS-RunShellScript --instance-ids "$iid" --parameters "file://$TMP/rc.json" \
      --query Command.CommandId 2>/dev/null)" || { sleep 10; continue; }
    "$who" ssm wait command-executed --command-id "$cmd" --instance-id "$iid" 2>/dev/null \
      && out="$("$who" ssm get-command-invocation --command-id "$cmd" --instance-id "$iid" --query StandardOutputContent 2>/dev/null)" \
      && [ -n "$out" ] && { printf '%s' "$out" | tr -d '\r\n '; return 0; }
    sleep 10
  done
  return 1
}

# --- 1. the owner's instance writes the marker ------------------------------------------------------------
BASE="$(in_a ec2 describe-images --owners amazon --filters Name=name,Values=ubuntu-24.04 --query 'Images[0].ImageId' 2>/dev/null)"
case "$BASE" in ami-*) ;; *) inconclusive "no ubuntu-24.04 catalog image (got ${BASE})" ;; esac
UD="$(printf '#!/bin/bash\nmkdir -p /var/lib/openinfra-probe\necho %s > /var/lib/openinfra-probe/marker\nsync\n' "$MARKER" | base64 | tr -d '\n')"
instance_template "$BASE" "$UD" > "$TMP/src.json"
in_a cloudformation create-stack --stack-name "$STACK_A" --template-body "file://$TMP/src.json" --capabilities CAPABILITY_IAM >/dev/null 2>"$TMP/cs" \
  || fail "create-stack in ${OWNER}: $(head -c 300 "$TMP/cs")"
MADE_A=1
in_a cloudformation wait stack-create-complete --stack-name "$STACK_A" 2>/dev/null \
  || fail "the source stack did not complete: $(in_a cloudformation describe-stacks --stack-name "$STACK_A" --query 'Stacks[0].[StackStatus,StackStatusReason]' 2>&1 | tr '\t\n' '  ')"
IID_A="$(in_a cloudformation describe-stacks --stack-name "$STACK_A" --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue | [0]")"
got="$(run_marker in_a "$IID_A")" || fail "no Run Command reached ${IID_A}"
[ "$got" = "$MARKER" ] || fail "the source instance's UserData did not write the marker (got ${got})"
log "  ✓ ${IID_A} in ${OWNER} (from ${BASE}) wrote its marker"

# --- 2. a principal with no policy may not image it -------------------------------------------------------
if as "$NAK" "$NSK" ec2 create-image --instance-id "$IID_A" --name "denied ${SFX}" >/dev/null 2>"$TMP/deny"; then
  fail "create-image was allowed for a principal with no policy"
fi
grep -qE 'UnauthorizedOperation|AccessDenied' "$TMP/deny" || fail "create-image failed without EC2's access-denied error: $(head -c 300 "$TMP/deny")"
log "  ✓ a principal with no policy is refused CreateImage (UnauthorizedOperation)"

# --- 3. CreateImage: pending at once, then available, and the instance runs again --------------------------
AMI="$(in_a ec2 create-image --instance-id "$IID_A" --name "$IMAGE_NAME" --description "made by the images probe" \
  --tag-specifications "ResourceType=image,Tags=[{Key=probe,Value=${SFX}}]" --query ImageId 2>"$TMP/ci")" \
  || fail "create-image: $(head -c 300 "$TMP/ci")"
case "$AMI" in ami-*) ;; *) fail "create-image answered no image id (${AMI})" ;; esac
st="$(in_a ec2 describe-images --image-ids "$AMI" --query 'Images[0].State' 2>/dev/null)"
log "  ✓ CreateImage answered ${AMI} (${st})"
deadline=$((SECONDS + IMAGE_WAIT))
while :; do
  st="$(in_a ec2 describe-images --image-ids "$AMI" --query 'Images[0].State' 2>/dev/null)"
  [ "$st" = available ] && break
  [ "$st" = failed ] && fail "the image failed: $(in_a ec2 describe-images --image-ids "$AMI" --query 'Images[0].StateReason' 2>&1)"
  [ "$SECONDS" -lt "$deadline" ] || fail "the image is still ${st} after ${IMAGE_WAIT}s"
  sleep 15
done
owner_id="$(in_a ec2 describe-images --image-ids "$AMI" --query 'Images[0].OwnerId' 2>/dev/null)"
name="$(in_a ec2 describe-images --image-ids "$AMI" --query 'Images[0].Name' 2>/dev/null)"
tagv="$(in_a ec2 describe-images --image-ids "$AMI" --query 'Images[0].Tags[?Key==`probe`].Value | [0]' 2>/dev/null)"
[ "$owner_id" = "$OWNER" ] && [ "$name" = "$IMAGE_NAME" ] && [ "$tagv" = "$SFX" ] || fail "the image's owner, name or tag (${owner_id} / ${name} / ${tagv})"
ist=""
for _ in $(seq 1 40); do
  ist="$(in_a ec2 describe-instances --instance-ids "$IID_A" --query 'Reservations[0].Instances[0].State.Name' 2>/dev/null)"
  [ "$ist" = running ] && break
  sleep 15
done
[ "$ist" = running ] || fail "the instance CreateImage stopped did not run again (${ist})"
log "  ✓ ${AMI} is available (owner ${OWNER}), and ${IID_A} runs again"

# --- 4. not shared: the other account neither sees nor launches it ----------------------------------------
if in_b ec2 describe-images --image-ids "$AMI" >/dev/null 2>"$TMP/nf"; then fail "${SHARED} sees ${AMI} before it is shared"; fi
grep -q 'InvalidAMIID.NotFound' "$TMP/nf" || fail "describe-images of an unshared image: $(head -c 300 "$TMP/nf")"
instance_template "$AMI" > "$TMP/launch.json"
if in_b cloudformation create-stack --stack-name "$STACK_DENIED" --template-body "file://$TMP/launch.json" --capabilities CAPABILITY_IAM >/dev/null 2>"$TMP/dn"; then
  MADE_DENIED=1
  in_b cloudformation wait stack-create-complete --stack-name "$STACK_DENIED" 2>/dev/null && fail "${SHARED} launched from ${AMI} before it was shared"
  reason="$(in_b cloudformation describe-stacks --stack-name "$STACK_DENIED" --query 'Stacks[0].StackStatusReason' 2>/dev/null)
$(in_b cloudformation describe-stack-events --stack-name "$STACK_DENIED" --query 'StackEvents[].ResourceStatusReason' 2>/dev/null)"
else
  reason="$(cat "$TMP/dn")"
fi
printf '%s' "$reason" | grep -q "does not exist" || fail "the unshared launch failed without EC2's InvalidAMIID.NotFound wording: $(printf '%s' "$reason" | head -c 400)"
log "  ✓ before it is shared, ${SHARED} gets InvalidAMIID.NotFound, and its stack refuses the image"

# --- 5. shared: the other account describes it, cannot change it, and launches from it ----------------------
in_a ec2 modify-image-attribute --image-id "$AMI" --launch-permission "Add=[{UserId=${SHARED}}]" >/dev/null 2>"$TMP/mia" \
  || fail "modify-image-attribute: $(head -c 300 "$TMP/mia")"
perm="$(in_a ec2 describe-image-attribute --image-id "$AMI" --attribute launchPermission --query 'LaunchPermissions[].UserId' 2>/dev/null)"
[ "$perm" = "$SHARED" ] || fail "the launch permission reads ${perm}, not ${SHARED}"
read -r bst bowner <<<"$(in_b ec2 describe-images --image-ids "$AMI" --query 'Images[0].[State,OwnerId]' 2>/dev/null)"
[ "$bst/$bowner" = "available/$OWNER" ] || fail "${SHARED} describes the shared image as ${bst}/${bowner}"
if in_b ec2 modify-image-attribute --image-id "$AMI" --description "Value=not mine" >/dev/null 2>"$TMP/af"; then
  fail "${SHARED} changed an image it does not own"
fi
grep -q 'AuthFailure' "$TMP/af" || fail "a non-owner's modify-image-attribute: $(head -c 300 "$TMP/af")"
log "  ✓ shared with ${SHARED}: it describes ${AMI} (owner ${OWNER}) and is refused changing it (AuthFailure)"
in_b cloudformation create-stack --stack-name "$STACK_B" --template-body "file://$TMP/launch.json" --capabilities CAPABILITY_IAM >/dev/null 2>"$TMP/cb" \
  || fail "create-stack in ${SHARED}: $(head -c 300 "$TMP/cb")"
MADE_B=1
in_b cloudformation wait stack-create-complete --stack-name "$STACK_B" 2>/dev/null \
  || fail "the launch stack did not complete: $(in_b cloudformation describe-stacks --stack-name "$STACK_B" --query 'Stacks[0].[StackStatus,StackStatusReason]' 2>&1 | tr '\t\n' '  ')"
IID_B="$(in_b cloudformation describe-stacks --stack-name "$STACK_B" --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue | [0]")"
bimg="$(in_b ec2 describe-instances --instance-ids "$IID_B" --query 'Reservations[0].Instances[0].ImageId' 2>/dev/null)"
[ "$bimg" = "$AMI" ] || fail "${IID_B} reports image ${bimg}, not ${AMI}"
got="$(run_marker in_b "$IID_B")" || fail "no Run Command reached ${IID_B}"
[ "$got" = "$MARKER" ] || fail "the instance launched from ${AMI} does not hold the marker (got ${got})"
log "  ✓ ${SHARED} launched ${IID_B} from ${AMI} through CloudFormation; it holds the marker ${IID_A} wrote"

printf '\n✓ PASS: an account images its instance, shares the image, and another account launches from it (and is refused before it is shared)\n'
