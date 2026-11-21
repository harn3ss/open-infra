#!/usr/bin/env bash
# Probe: an instance its account's limits refuse fails at once with EC2's error, and a stack update starts
# an instance that shut itself down on its new UserData, as on AWS.
#
# Through the real AWS CLI:
#   1. the management account's administrator creates a throwaway member account (Organizations
#      CreateAccount) and assumes its OrganizationAccountAccessRole; the operator gives the account 15 GiB
#      of storage capacity (kind: Account spec.capacity);
#   2. a stack in the member account whose instance's 20 GiB root is beyond that fails within minutes with
#      EC2's VolumeLimitExceeded, and rolls back (ROLLBACK_COMPLETE) naming it;
#   3. with the storage raised, a stack's instance whose UserData shuts it down a minute after boot is
#      stopped (Client.InstanceInitiatedShutdown); an update of its UserData starts it on the new spec
#      (UPDATE_COMPLETE, the instance running), as AWS stops, changes and starts it;
#   4. DENIAL: a user of the member account with no policy is refused UpdateStack (AccessDenied).
# Everything the probe made is removed on exit: the stacks, the user, the member account and its home
# namespace (only when this run created it), and the administrator and its key.
#
# Needs: aws (v2), kubectl (a cluster operator), curl, python3; a deployed shim with the Organizations, STS,
# IAM, CloudFormation and EC2 front doors, and the compliance component (account capacity). Exit 0 = pass,
# 1 = fail, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-ec2-launch-limits.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SETTLE="${IAM_SETTLE_SECONDS:-35}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
NAME="limits-$SFX"
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

OWNER="limits-admin-$SFX"; AK=""; SK=""; KS=""; NEW_ACCOUNT=""; NEW_HOME=""
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

# capacity sets the member account's storage capacity and waits until its home namespace enforces it.
capacity() {
  kubectl patch accounts.organizations.openinfra.dev "$NEW_ACCOUNT" --type merge \
    -p "{\"spec\":{\"capacity\":{\"storage\":\"$1\"}}}" >/dev/null || inconclusive "could not set the account's capacity"
  for _ in $(seq 1 60); do
    [ "$(kubectl -n "$NEW_HOME" get resourcequota account-capacity-storage -o jsonpath='{.spec.hard.requests\.storage}' 2>/dev/null)" = "$1" ] && return 0
    sleep 5
  done
  inconclusive "the account's storage capacity of $1 was not enforced in $NEW_HOME"
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

# --- 1. the management account's administrator, a member account, and its capacity --------------------
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

log "1. a member account with 15 GiB of storage capacity"
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
capacity 15Gi
sleep "$SETTLE"
M sts assume-role --role-arn "arn:aws:iam::$NEW_ACCOUNT:role/OrganizationAccountAccessRole" \
  --role-session-name limits --output json > "$TMP/session.json" 2>"$TMP/err" \
  || die "assume-role into the member account: $(tr '\n' ' ' < "$TMP/err")"
read -r MAK MSK MST < <(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["Credentials"]; print(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"])' "$TMP/session.json")
B() { AWS_ACCESS_KEY_ID="$MAK" AWS_SECRET_ACCESS_KEY="$MSK" AWS_SESSION_TOKEN="$MST" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" "$@"; }
[ "$(B sts get-caller-identity --query Account --output text 2>/dev/null)" = "$NEW_ACCOUNT" ] || die "the assumed session is not the member account's"
AMI="$(B ec2 describe-images --owners amazon --filters Name=name,Values=ubuntu-24.04 --query 'Images[0].ImageId' --output text 2>/dev/null)"
case "$AMI" in ami-*) ;; *) inconclusive "no ubuntu-24.04 image is listed (got '$AMI')" ;; esac
ok "acting in member account $NEW_ACCOUNT (home $NEW_HOME), image $AMI"

# --- 2. an instance beyond the account's storage fails with EC2's error ---------------------------------
log "2. an instance whose 20 GiB root is beyond the account's 15 GiB fails with VolumeLimitExceeded"
cat > "$TMP/big.yaml" <<EOF
Resources:
  Box:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: $AMI
      InstanceType: t3.micro
      BlockDeviceMappings:
        - DeviceName: /dev/sda1
          Ebs: { VolumeSize: 20 }
EOF
B cloudformation create-stack --stack-name "$NAME-big" --template-body "file://$TMP/big.yaml" >/dev/null 2>"$TMP/err" \
  || die "create-stack: $(tr '\n' ' ' < "$TMP/err")"
CLEAN+=("B cloudformation delete-stack --stack-name $NAME-big")
t0=$(date +%s)
st="$(stack_settles "$NAME-big" 900)"
took=$(( $(date +%s) - t0 ))
B cloudformation describe-stack-events --stack-name "$NAME-big" \
  --query "StackEvents[?LogicalResourceId=='Box' && ResourceStatus=='CREATE_FAILED'].ResourceStatusReason | [0]" --output text > "$TMP/why" 2>/dev/null
[ "$st" = ROLLBACK_COMPLETE ] || die "the refused stack is $st after ${took}s, want ROLLBACK_COMPLETE: $(head -c 300 "$TMP/why")"
grep -q "Error Code: VolumeLimitExceeded" "$TMP/why" || die "the instance's failure does not name VolumeLimitExceeded: $(head -c 400 "$TMP/why")"
[ "$took" -lt 600 ] || die "the refused launch took ${took}s to fail"
ok "ROLLBACK_COMPLETE after ${took}s: $(head -c 120 "$TMP/why")…"

# --- 3. an instance that shut itself down is started by an update of its UserData ----------------------
log "3. an instance that shuts itself down is started on its new UserData by a stack update"
capacity 40Gi
userdata() { printf '#!/bin/bash\n%s\n' "$1" | base64 -w0; }
cat > "$TMP/warm.yaml" <<EOF
Parameters:
  Script: { Type: String }
Resources:
  Box:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: $AMI
      InstanceType: t3.micro
      UserData: !Ref Script
Outputs:
  InstanceId: { Value: !Ref Box }
EOF
B cloudformation create-stack --stack-name "$NAME-warm" --template-body "file://$TMP/warm.yaml" \
  --parameters "ParameterKey=Script,ParameterValue=$(userdata 'shutdown -h +1')" >/dev/null 2>"$TMP/err" \
  || die "create-stack: $(tr '\n' ' ' < "$TMP/err")"
CLEAN+=("B cloudformation delete-stack --stack-name $NAME-warm")
st="$(stack_settles "$NAME-warm" 1200)"
[ "$st" = CREATE_COMPLETE ] || die "the instance's stack is $st: $(B cloudformation describe-stacks --stack-name "$NAME-warm" --query 'Stacks[0].StackStatusReason' --output text 2>&1 | head -c 300)"
IID="$(B cloudformation describe-stacks --stack-name "$NAME-warm" --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue | [0]" --output text)"
state=""; reason=""
for _ in $(seq 1 60); do
  read -r state reason < <(B ec2 describe-instances --instance-ids "$IID" \
    --query 'Reservations[0].Instances[0].[State.Name,StateReason.Code]' --output text 2>/dev/null)
  [ "$state" = stopped ] && break
  sleep 10
done
[ "$state" = stopped ] || die "the instance did not shut itself down (state '$state')"
[ "$reason" = Client.InstanceInitiatedShutdown ] || die "the stopped instance's reason is '$reason'"
ok "$IID shut itself down: stopped, $reason"
B cloudformation update-stack --stack-name "$NAME-warm" --template-body "file://$TMP/warm.yaml" \
  --parameters "ParameterKey=Script,ParameterValue=$(userdata 'echo second > /var/tmp/second')" >/dev/null 2>"$TMP/err" \
  || die "update-stack: $(tr '\n' ' ' < "$TMP/err")"
st="$(stack_settles "$NAME-warm" 1500)"
[ "$st" = UPDATE_COMPLETE ] || die "the UserData update is $st: $(B cloudformation describe-stacks --stack-name "$NAME-warm" --query 'Stacks[0].StackStatusReason' --output text 2>&1 | head -c 300)"
state="$(B ec2 describe-instances --instance-ids "$IID" --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null)"
[ "$state" = running ] || die "after the update the instance is '$state', want running"
ok "UPDATE_COMPLETE, $IID running on its new UserData"

# --- 4. DENIAL: a user with no policy may not update the stack ---------------------------------------
log "4. a user of the member account with no policy is refused UpdateStack"
B iam create-user --user-name "$NAME-nopol" >/dev/null 2>"$TMP/err" || die "create-user: $(cat "$TMP/err")"
CLEAN+=("B iam delete-user --user-name $NAME-nopol")
B iam create-access-key --user-name "$NAME-nopol" --output json >"$TMP/key.json" 2>"$TMP/err" || die "create-access-key: $(cat "$TMP/err")"
read -r NAK NSK < <(python3 -c 'import json,sys; k=json.load(open(sys.argv[1]))["AccessKey"]; print(k["AccessKeyId"], k["SecretAccessKey"])' "$TMP/key.json")
CLEAN+=("B iam delete-access-key --user-name $NAME-nopol --access-key-id $NAK")
sleep "$SETTLE"
if AWS_ACCESS_KEY_ID="$NAK" AWS_SECRET_ACCESS_KEY="$NSK" AWS_SESSION_TOKEN="" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" \
  cloudformation update-stack --stack-name "$NAME-warm" --template-body "file://$TMP/warm.yaml" \
  --parameters "ParameterKey=Script,ParameterValue=$(userdata 'echo third')" >/dev/null 2>"$TMP/deny"; then
  die "a user with no policy updated the stack"
fi
grep -q AccessDenied "$TMP/deny" || die "the refusal is not AccessDenied: $(tail -c 300 "$TMP/deny")"
ok "UpdateStack by a user with no policy: AccessDenied"

for s in "$NAME-warm" "$NAME-big"; do B cloudformation delete-stack --stack-name "$s" >/dev/null 2>&1; done
for s in "$NAME-warm" "$NAME-big"; do
  for _ in $(seq 1 60); do B cloudformation describe-stacks --stack-name "$s" >/dev/null 2>&1 || break; sleep 5; done
done
printf '✓ PASS — an instance beyond its account'"'"'s storage failed at once with EC2'"'"'s VolumeLimitExceeded and its stack rolled back; an instance that shut itself down was started on its new UserData by a stack update (UPDATE_COMPLETE); a user with no policy was refused UpdateStack.\n'
