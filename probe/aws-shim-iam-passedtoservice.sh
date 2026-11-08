#!/usr/bin/env bash
# Probe: iam:PassedToService (#403) — a user whose PassRole comes from AWSLambda_FullAccess (iam:PassRole
# where iam:PassedToService is lambda.amazonaws.com) passes a role to Lambda and to no other service,
# through the aws-shim with the real AWS CLI.
#
# The user U is made with the IAM API: AWSLambda_FullAccess attached, plus an inline policy for what the
# probe's other calls need that AWSLambda_FullAccess does not carry (CloudFormation stacks, an in-stack
# role, an instance, a state machine) — none of it iam:PassRole. Asserts:
#   1. U's create-function naming an execution role succeeds (the Lambda API's iam:PassRole, decided with
#      iam:PassedToService lambda.amazonaws.com);
#   2. U's CloudFormation stack whose AWS::Lambda::Function names that role reaches CREATE_COMPLETE (the
#      stack writes the Function as U; the admission check accepts U's compiled passrole:lambda.amazonaws.com),
#      and so does U's console (signed in with a login profile, creating a Function through its resource
#      API, as U);
#   3. U's stack that gives an instance an in-stack role is refused passing it (ec2.amazonaws.com) and rolls
#      back;
#   4. DENIAL: U's create-state-machine naming the role is refused with AccessDeniedException naming
#      iam:PassRole (states.amazonaws.com is not Lambda).
#
# Needs: aws (v2), kubectl (to mint a throwaway admin, removed on exit); a deployed shim with the IAM, STS,
# Lambda, Step Functions and CloudFormation front doors, and the IAM compiler. Exit 0 = pass, 1 = a real
# failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-iam-passedtoservice.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
CFN_NS="${CFN_NS:-open-infra-cfn}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
CONSOLE="${CONSOLE_ENDPOINT:-}"
CONSOLE_PF=""
export AWS_REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
U="pts-user-$SFX"; EXEC="pts-exec-$SFX"; FN="pts-fn-$SFX"; SM="pts-sm-$SFX"
FNSTACK="pts-fn-$SFX"; VMSTACK="pts-vm-$SFX"

log()  { printf '▸ %s\n' "$*"; }
ok()   { printf '▸   ✓ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for t in aws kubectl python3 curl; do command -v "$t" >/dev/null || inconclusive "$t is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
W="$(mktemp -d)"
A=(aws --endpoint-url "$ENDPOINT" --no-cli-pager)

CREATED_USERS=(); CREATED_KEYS=(); U_MADE=""; U_AK=""; EXEC_MADE=""
cleanup() {
  set +e
  unset AWS_SESSION_TOKEN
  [ -n "${ADMIN_AK:-}" ] && export AWS_ACCESS_KEY_ID="$ADMIN_AK" AWS_SECRET_ACCESS_KEY="$ADMIN_SK"
  "${A[@]}" lambda delete-function --function-name "$FN" >/dev/null 2>&1
  for s in "$FNSTACK" "$VMSTACK"; do
    if "${A[@]}" cloudformation describe-stacks --stack-name "$s" >/dev/null 2>&1; then
      for _ in $(seq 1 60); do
        st="$("${A[@]}" cloudformation describe-stacks --stack-name "$s" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
        case "$st" in *_IN_PROGRESS) sleep 5 ;; *) break ;; esac
      done
      "${A[@]}" cloudformation delete-stack --stack-name "$s" >/dev/null 2>&1
      for _ in $(seq 1 90); do "${A[@]}" cloudformation describe-stacks --stack-name "$s" >/dev/null 2>&1 || break; sleep 4; done
    fi
  done
  kubectl -n default delete functions.openinfra.dev "$FN-console" --ignore-not-found >/dev/null 2>&1
  [ -n "$CONSOLE_PF" ] && kill "$CONSOLE_PF" 2>/dev/null
  if [ -n "$U_MADE" ]; then
    "${A[@]}" iam delete-login-profile --user-name "$U" >/dev/null 2>&1
    [ -n "$U_AK" ] && "${A[@]}" iam delete-access-key --user-name "$U" --access-key-id "$U_AK" >/dev/null 2>&1
    "${A[@]}" iam delete-user-policy --user-name "$U" --policy-name stacks >/dev/null 2>&1
    "${A[@]}" iam detach-user-policy --user-name "$U" --policy-arn arn:aws:iam::aws:policy/AWSLambda_FullAccess >/dev/null 2>&1
    "${A[@]}" iam delete-user --user-name "$U" >/dev/null 2>&1
  fi
  [ -n "$EXEC_MADE" ] && "${A[@]}" iam delete-role --role-name "$EXEC" >/dev/null 2>&1
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
if [ -z "${AWS_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_SECRET_ACCESS_KEY:-}" ]; then
  mint_key "pts-admin-$SFX" admins
  export AWS_ACCESS_KEY_ID="$MK_AK" AWS_SECRET_ACCESS_KEY="$MK_SK"
  log "minted a throwaway openinfra:admins caller (pts-admin-$SFX)"
fi
ADMIN_AK="$AWS_ACCESS_KEY_ID"; ADMIN_SK="$AWS_SECRET_ACCESS_KEY"
for i in $(seq 1 24); do # a freshly minted caller's authority takes a minute or so to reach every check
  ACCOUNT="$("${A[@]}" sts get-caller-identity --query Account --output text 2>/dev/null)" && break
  [ "$i" = 24 ] && inconclusive "sts get-caller-identity never succeeded"
  sleep 5
done

log "the execution role, and user $U with AWSLambda_FullAccess"
"${A[@]}" iam create-role --role-name "$EXEC" \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":["lambda.amazonaws.com","states.amazonaws.com"]},"Action":"sts:AssumeRole"}]}' \
  >/dev/null || inconclusive "iam create-role failed"
EXEC_MADE=1
EXEC_ARN="arn:aws:iam::$ACCOUNT:role/$EXEC"
"${A[@]}" iam create-user --user-name "$U" >/dev/null || inconclusive "iam create-user failed"
U_MADE=1
"${A[@]}" iam attach-user-policy --user-name "$U" --policy-arn arn:aws:iam::aws:policy/AWSLambda_FullAccess \
  || inconclusive "attaching AWSLambda_FullAccess failed"
"${A[@]}" iam put-user-policy --user-name "$U" --policy-name stacks --policy-document '{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Action":["cloudformation:*","ec2:RunInstances","ec2:TerminateInstances","ec2:Describe*","ec2:CreateSecurityGroup","ec2:DeleteSecurityGroup",
   "iam:CreateRole","iam:DeleteRole","iam:GetRole","iam:CreateInstanceProfile","iam:DeleteInstanceProfile","iam:AddRoleToInstanceProfile",
   "iam:RemoveRoleFromInstanceProfile","states:CreateStateMachine","states:DeleteStateMachine","states:DescribeStateMachine"],"Resource":"*"}]}' \
  || inconclusive "iam put-user-policy failed"
"${A[@]}" iam create-access-key --user-name "$U" --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text >"$W/key" \
  || inconclusive "iam create-access-key failed"
read -r U_AK U_SK <"$W/key"; rm -f "$W/key"
as_u() { AWS_ACCESS_KEY_ID="$U_AK" AWS_SECRET_ACCESS_KEY="$U_SK" "${A[@]}" "$@"; }

# U's policies reach the evaluator (simulate) and the compiled control plane (the per-service verb).
U_ARN="arn:aws:iam::$ACCOUNT:user/$U"
for i in $(seq 1 36); do
  dec="$("${A[@]}" iam simulate-principal-policy --policy-source-arn "$U_ARN" --action-names lambda:CreateFunction \
          --query 'EvaluationResults[0].EvalDecision' --output text 2>/dev/null || true)"
  [ "$dec" = allowed ] && break
  [ "$i" = 36 ] && inconclusive "U's policies did not take effect within 3 minutes"
  sleep 5
done
# may_pass <verb>: a SubjectAccessReview for U's compiled identity (an IAM principal cannot run kubectl's
# discovery, so kubectl auth can-i --as cannot ask for it).
may_pass() {
  printf '{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"openinfra:%s:%s","resourceAttributes":{"group":"iam.openinfra.dev","resource":"roles","verb":"%s","namespace":"%s","name":"%s"}}}' \
    "$ACCOUNT" "$U" "$1" "$CFN_NS" "$EXEC" | kubectl create -o jsonpath='{.status.allowed}' -f - 2>/dev/null || true
}
for i in $(seq 1 60); do
  [ "$(may_pass passrole:lambda.amazonaws.com)" = true ] && break
  [ "$i" = 60 ] && inconclusive "the IAM compiler did not compile U's passrole:lambda.amazonaws.com within 5 minutes"
  sleep 5
done
[ "$(may_pass passrole)" = true ] && fail "a Lambda-only PassRole was compiled into the any-service passrole verb"
[ "$(may_pass passrole:ec2.amazonaws.com)" = true ] && fail "a Lambda-only PassRole was compiled into EC2's verb"
ok "U's PassRole is compiled as passrole:lambda.amazonaws.com, not passrole"

log "1. U's create-function names the role"
mkzip() { python3 -c 'import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],"w"); z.writestr("index.js","exports.handler = async () => ({ ok: true });\n"); z.close()' "$1"; }
mkzip "$W/fn.zip"
for i in $(seq 1 6); do
  as_u lambda create-function --function-name "$FN" --runtime nodejs22.x --handler index.handler --role "$EXEC_ARN" \
    --zip-file "fileb://$W/fn.zip" >/dev/null 2>"$W/c.err" && break
  [ "$i" = 6 ] && fail "U's create-function was refused: $(tail -c 400 "$W/c.err")"
  sleep 10
done
ok "created $FN with role $EXEC"

log "2. U's stack whose function names the role"
cat > "$W/fn.yaml" <<YAML
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: nodejs22.x
      Handler: index.handler
      Role: $EXEC_ARN
      Code:
        ZipFile: |
          exports.handler = async () => ({ ok: true });
YAML
as_u cloudformation deploy --template-file "$W/fn.yaml" --stack-name "$FNSTACK" >"$W/d1" 2>&1 \
  || fail "U's function stack did not deploy: $(tail -c 500 "$W/d1") $(as_u cloudformation describe-stacks --stack-name "$FNSTACK" --query 'Stacks[0].StackStatusReason' --output text 2>/dev/null)"
ok "CREATE_COMPLETE"

log "2b. U's console creates a function naming the role"
if [ -z "$CONSOLE" ]; then
  port=$(( 20000 + RANDOM % 20000 ))
  kubectl -n "$USERS_NS" port-forward svc/console "$port:80" >/dev/null 2>&1 &
  CONSOLE_PF=$!
  CONSOLE="http://127.0.0.1:$port"
  for _ in $(seq 1 20); do curl -fsS -m 2 "$CONSOLE/healthz" >/dev/null 2>&1 && break; sleep 1; done
fi
curl -fsS -m 5 "$CONSOLE/healthz" >/dev/null 2>&1 || inconclusive "console not reachable at $CONSOLE (set CONSOLE_ENDPOINT)"
PW="Pts-$(head -c 12 /dev/urandom | base64 | tr -d '/+=' | head -c 16)-9x"
"${A[@]}" iam create-login-profile --user-name "$U" --password "$PW" --no-password-reset-required >/dev/null \
  || inconclusive "iam create-login-profile failed"
JAR="$W/jar"
code=""
for _ in $(seq 1 12); do # the console reads the login profile through an informer
  code="$(curl -s -m 15 -c "$JAR" -o "$W/login" -w '%{http_code}' -H 'Content-Type: application/json' \
    -d "{\"Username\":\"$U\",\"Password\":\"$PW\"}" "$CONSOLE/api/auth/login")"
  [ "$code" = 200 ] && break
  sleep 5
done
unset PW
[ "$code" = 200 ] || inconclusive "U could not sign in to the console (HTTP $code)"
cat > "$W/fn-console.json" <<JSON
{"apiVersion":"openinfra.dev/v1","kind":"Function","metadata":{"name":"$FN-console","namespace":"default"},
 "spec":{"image":"ghcr.io/harn3ss/open-infra-lambda-nodejs:latest","role":"$EXEC_ARN","expose":false}}
JSON
code="$(curl -s -m 30 -b "$JAR" -o "$W/created" -w '%{http_code}' -H 'Content-Type: application/json' -H 'X-Openinfra-Console: 1' \
  --data-binary "@$W/fn-console.json" "$CONSOLE/api/k8s/apis/openinfra.dev/v1/namespaces/default/functions")"
[ "$code" = 201 ] || fail "U's console create of a Function naming the role was refused (HTTP $code): $(head -c 400 "$W/created")"
kubectl -n default delete functions.openinfra.dev "$FN-console" --ignore-not-found >/dev/null 2>&1
ok "the console created it (HTTP 201)"

log "3. U's stack that gives an instance a role is refused passing it"
cat > "$W/vm.yaml" <<'YAML'
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: sts:AssumeRole }
  Profile:
    Type: AWS::IAM::InstanceProfile
    Properties: { Roles: [!Ref Role] }
  Box:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      InstanceType: t3.small
      IamInstanceProfile: !Ref Profile
YAML
as_u cloudformation create-stack --stack-name "$VMSTACK" --template-body "file://$W/vm.yaml" --capabilities CAPABILITY_IAM >/dev/null 2>"$W/v.err" \
  || fail "create-stack $VMSTACK was refused outright: $(tail -c 300 "$W/v.err")"
st=""
for _ in $(seq 1 90); do
  st="$(as_u cloudformation describe-stacks --stack-name "$VMSTACK" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
  case "$st" in *_IN_PROGRESS|"") sleep 5 ;; *) break ;; esac
done
[ "$st" = ROLLBACK_COMPLETE ] || fail "passing a role to an instance must roll the stack back, got '$st'"
as_u cloudformation describe-stack-events --stack-name "$VMSTACK" --output json >"$W/ev" 2>/dev/null || true
as_u cloudformation describe-stacks --stack-name "$VMSTACK" --query 'Stacks[0].StackStatusReason' --output text >>"$W/ev" 2>/dev/null || true
grep -qi "PassRole" "$W/ev" || fail "the rollback is not the PassRole refusal: $(tail -c 600 "$W/ev")"
ok "ROLLBACK_COMPLETE: iam:PassRole denied for the instance's role"

log "4. DENIAL: U's create-state-machine naming the role"
if as_u stepfunctions create-state-machine --name "$SM" --role-arn "$EXEC_ARN" \
     --definition '{"StartAt":"Done","States":{"Done":{"Type":"Pass","End":true}}}' >/dev/null 2>"$W/s.err"; then
  as_u stepfunctions delete-state-machine --state-machine-arn "arn:aws:states:$AWS_REGION:$ACCOUNT:stateMachine:$SM" >/dev/null 2>&1
  fail "a Lambda-only PassRole passed a role to Step Functions"
fi
grep -q "AccessDeniedException" "$W/s.err" && grep -q "iam:PassRole" "$W/s.err" \
  || fail "the refusal is not AccessDeniedException naming iam:PassRole: $(tail -c 300 "$W/s.err")"
ok "refused: AccessDeniedException naming iam:PassRole"

printf '✓ PASS — a user whose PassRole is AWSLambda_FullAccess'"'"'s (iam:PassedToService lambda.amazonaws.com) gives a function a role through the Lambda API and CloudFormation, and is refused passing a role to an instance and to a state machine\n'
