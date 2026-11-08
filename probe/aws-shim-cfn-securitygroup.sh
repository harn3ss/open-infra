#!/usr/bin/env bash
# Probe: a security group follows AWS's semantics (#374) — a group with no inbound rules denies inbound —
# through the aws-shim's CloudFormation front door, with the real AWS CLI.
#
# One instance, one group:
#   1. the group allows SSH (tcp 22) from anywhere: a connection from inside the account reaches the
#      instance's port 22 (the control: the path works);
#   2. a stack update removes the group's inbound rules, leaving AWS's default egress rule (IpProtocol -1,
#      which deploys now): the same connection is refused;
#   3. DENIAL: a principal whose policy allows only cloudformation:DescribeStacks is refused
#      ec2 describe-security-groups with UnauthorizedOperation.
#
# Needs: aws (v2), kubectl (a throwaway admin, removed on exit, and the in-cluster connection test); a
# deployed shim with the CloudFormation, EC2, IAM and STS front doors; room for one t3.small instance.
# Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-cfn-securitygroup.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
CFN_NS="${CFN_NS:-open-infra-cfn}"
TESTIMAGE="${TESTIMAGE:-ghcr.io/cloudnative-pg/postgresql:17.4}" # has bash, for /dev/tcp
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
export AWS_REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
STACK="sgp-$SFX"; ROLE="sgp-reader-$SFX"

log()  { printf '▸ %s\n' "$*"; }
ok()   { printf '▸   ✓ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for t in aws kubectl; do command -v "$t" >/dev/null || inconclusive "$t is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
W="$(mktemp -d)"
A=(aws --endpoint-url "$ENDPOINT" --no-cli-pager)

CREATED_USERS=(); CREATED_KEYS=(); ROLE_MADE=""
cleanup() {
  set +e
  unset AWS_SESSION_TOKEN
  [ -n "${ADMIN_AK:-}" ] && export AWS_ACCESS_KEY_ID="$ADMIN_AK" AWS_SECRET_ACCESS_KEY="$ADMIN_SK"
  kubectl -n "$CFN_NS" delete pod -l "probe=sgp-$SFX" --ignore-not-found >/dev/null 2>&1
  if "${A[@]}" cloudformation describe-stacks --stack-name "$STACK" >/dev/null 2>&1; then
    for _ in $(seq 1 60); do
      st="$("${A[@]}" cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
      case "$st" in *_IN_PROGRESS) sleep 5 ;; *) break ;; esac
    done
    "${A[@]}" cloudformation delete-stack --stack-name "$STACK" >/dev/null 2>&1
    for _ in $(seq 1 120); do "${A[@]}" cloudformation describe-stacks --stack-name "$STACK" >/dev/null 2>&1 || break; sleep 5; done
  fi
  if [ -n "$ROLE_MADE" ]; then
    "${A[@]}" iam delete-role-policy --role-name "$ROLE" --policy-name read >/dev/null 2>&1
    "${A[@]}" iam delete-role --role-name "$ROLE" >/dev/null 2>&1
  fi
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1; done
  for k in "${CREATED_KEYS[@]:-}"; do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1; done
  rm -rf "$W"
}
trap cleanup EXIT

# mint_key <owner> <group>: a throwaway User and access key, removed on exit; sets MK_AK / MK_SK. Called
# directly, never inside $(...), so the cleanup list reaches the trap.
mint_key() {
  local owner="$1" group="$2" kname
  MK_AK="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  MK_SK="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  printf 'apiVersion: iam.openinfra.dev/v1\nkind: User\nmetadata: { name: "%s", namespace: "%s" }\nspec: { displayName: "%s", groups: ["%s"], source: local }\n' \
    "$owner" "$USERS_NS" "$owner" "$group" | kubectl apply -f - >/dev/null || inconclusive "could not mint User $owner"
  CREATED_USERS+=("$owner")
  kname="iam-ak-$(printf '%s' "$MK_AK" | sha256sum | cut -c1-40)"
  kubectl -n "$SHIM_NS" create secret generic "$kname" --from-literal=accessKeyId="$MK_AK" --from-literal=secretKey="$MK_SK" \
    --from-literal=owner="$owner" >/dev/null || inconclusive "could not mint a key for $owner"
  CREATED_KEYS+=("$kname")
}
OWNER=""
if [ -z "${AWS_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_SECRET_ACCESS_KEY:-}" ]; then
  OWNER="sgp-admin-$SFX"
  mint_key "$OWNER" admins
  export AWS_ACCESS_KEY_ID="$MK_AK" AWS_SECRET_ACCESS_KEY="$MK_SK"
  log "minted a throwaway openinfra:admins deployer ($OWNER)"
fi
ADMIN_AK="$AWS_ACCESS_KEY_ID"; ADMIN_SK="$AWS_SECRET_ACCESS_KEY"
ACCOUNT=""
for _ in $(seq 1 24); do
  ACCOUNT="$("${A[@]}" sts get-caller-identity --query Account --output text 2>/dev/null)" && break
  sleep 5
done
[ -n "$ACCOUNT" ] || inconclusive "the deployer's key never reached the shim"
ME="$("${A[@]}" sts get-caller-identity --query Arn --output text)"
if [ -n "$OWNER" ]; then # the stack writes as the deployer: wait for its compiled control-plane grants
  for i in $(seq 1 60); do
    allowed="$(printf '{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"openinfra:%s:%s","resourceAttributes":{"group":"openinfra.dev","resource":"virtualmachines","verb":"create","namespace":"%s"}}}' \
      "$ACCOUNT" "$OWNER" "$CFN_NS" | kubectl create -o jsonpath='{.status.allowed}' -f - 2>/dev/null || true)"
    [ "$allowed" = true ] && break
    [ "$i" = 60 ] && inconclusive "the deployer's control-plane grants were not compiled within 5 minutes"
    sleep 5
  done
fi

# template <ingress-yaml>: one group (AWS's default egress rule written out) and one instance in it.
template() {
  cat <<YAML
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Group:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: sg probe
$1
      SecurityGroupEgress:
        - { IpProtocol: "-1", CidrIp: 0.0.0.0/0 }
  Box:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      InstanceType: t3.small
      SecurityGroupIds: [!GetAtt Group.GroupId]
      Tags: [{ Key: Name, Value: sg-probe }]
Outputs:
  InstanceId: { Value: !Ref Box }
YAML
}
template "      SecurityGroupIngress:
        - { IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: 0.0.0.0/0 }" >"$W/open.yaml"
template "" >"$W/closed.yaml"

# reaches <ip>: OPEN when port 22 accepts a connection from a pod in the account's namespace, else CLOSED.
reaches() {
  kubectl -n "$CFN_NS" run "sgp-${SFX}-${RANDOM}" --image="$TESTIMAGE" --restart=Never --rm -i --labels="probe=sgp-$SFX" \
    --command --timeout=90s -- bash -c "timeout 5 bash -c '</dev/tcp/$1/22' 2>/dev/null && echo OPEN || echo CLOSED" 2>/dev/null \
    | grep -o 'OPEN\|CLOSED' | head -1 || true
}
wait_stack() {
  local st=""
  for _ in $(seq 1 120); do
    st="$("${A[@]}" cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
    case "$st" in *_IN_PROGRESS|"") sleep 5 ;; *) break ;; esac
  done
  printf '%s' "$st"
}

log "1. an instance whose group allows SSH from anywhere"
"${A[@]}" cloudformation create-stack --stack-name "$STACK" --template-body "file://$W/open.yaml" >/dev/null || fail "create-stack was refused"
st="$(wait_stack)"
[ "$st" = CREATE_COMPLETE ] || fail "the stack did not create: $st $("${A[@]}" cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatusReason' --output text 2>/dev/null)"
IID="$("${A[@]}" cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue" --output text)"
IP=""
for _ in $(seq 1 60); do
  IP="$("${A[@]}" ec2 describe-instances --instance-ids "$IID" --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text 2>/dev/null || true)"
  [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && break
  sleep 5
done
[[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || inconclusive "the instance has no private address (is it running?)"
r=""
for _ in $(seq 1 40); do # the instance boots and starts sshd
  r="$(reaches "$IP")"
  [ "$r" = OPEN ] && break
  sleep 10
done
[ "$r" = OPEN ] || inconclusive "port 22 never opened with an SSH rule (the instance did not boot, or the path from the account is closed)"
ok "with the SSH rule, port 22 accepts a connection from inside the account"

log "2. the group's inbound rules removed: an AWS group with no inbound rules denies inbound"
"${A[@]}" cloudformation update-stack --stack-name "$STACK" --template-body "file://$W/closed.yaml" >/dev/null || fail "update-stack was refused"
st="$(wait_stack)"
[ "$st" = UPDATE_COMPLETE ] || fail "the update did not complete: $st $("${A[@]}" cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatusReason' --output text 2>/dev/null)"
for _ in $(seq 1 24); do
  r="$(reaches "$IP")"
  [ "$r" = CLOSED ] && break
  sleep 5
done
[ "$r" = CLOSED ] || fail "an instance whose group has no inbound rules still accepts connections (fail-open)"
ok "with no inbound rules, port 22 refuses the connection; the group's -1 egress rule deployed"

log "3. DENIAL: a principal that may only describe stacks"
"${A[@]}" iam create-role --role-name "$ROLE" \
  --assume-role-policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"$ME\"},\"Action\":\"sts:AssumeRole\"}]}" >/dev/null \
  || inconclusive "iam create-role failed"
ROLE_MADE=1
"${A[@]}" iam put-role-policy --role-name "$ROLE" --policy-name read \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:DescribeStacks"],"Resource":"*"}]}' >/dev/null \
  || inconclusive "iam put-role-policy failed"
ROLE_ARN="$("${A[@]}" iam get-role --role-name "$ROLE" --query Role.Arn --output text)"
for i in $(seq 1 24); do
  dec="$("${A[@]}" iam simulate-principal-policy --policy-source-arn "$ROLE_ARN" --action-names cloudformation:DescribeStacks \
          --query 'EvaluationResults[0].EvalDecision' --output text 2>/dev/null || true)"
  [ "$dec" = allowed ] && break
  [ "$i" = 24 ] && inconclusive "the role's policy did not take effect within 2 minutes"
  sleep 5
done
CREDS="$("${A[@]}" sts assume-role --role-arn "$ROLE_ARN" --role-session-name sgp --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text)" \
  || inconclusive "sts assume-role failed"
read -r rak rsk rst <<<"$CREDS"
if AWS_ACCESS_KEY_ID="$rak" AWS_SECRET_ACCESS_KEY="$rsk" AWS_SESSION_TOKEN="$rst" \
   "${A[@]}" ec2 describe-security-groups >/dev/null 2>"$W/deny.err"; then
  fail "a principal without ec2:DescribeSecurityGroups described security groups"
fi
grep -q "UnauthorizedOperation" "$W/deny.err" || fail "the refusal is not EC2's UnauthorizedOperation: $(tail -c 300 "$W/deny.err")"
ok "refused: UnauthorizedOperation"

printf '✓ PASS — an instance whose security group allows SSH accepts a connection from inside the account; with the group'"'"'s inbound rules removed (AWS: none allows nothing) the same connection is refused, and the group'"'"'s -1 egress rule deploys; ec2:DescribeSecurityGroups is enforced\n'
