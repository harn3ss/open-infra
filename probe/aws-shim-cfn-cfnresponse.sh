#!/usr/bin/env bash
# Probe: custom-resource handlers written as AWS documents them — inline code using cfn-response (Node.js)
# and cfnresponse (Python) — deploy unchanged through the aws-shim's CloudFormation front door (#404), with
# the real AWS CLI.
#
# Asserts:
#   1. a stack whose two custom resources are backed by inline handlers that PUT their response with
#      cfn-response / cfnresponse reaches CREATE_COMPLETE, and each response's Data resolves Fn::GetAtt
#      for a dependent (a function's environment variables);
#   2. a handler that sends FAILED rolls its stack back (ROLLBACK_COMPLETE), naming the custom resource;
#   3. DENIAL: a principal whose policy allows only cloudformation:DescribeStacks is refused create-stack
#      with AccessDenied.
#
# Needs: aws (v2), kubectl (to mint a throwaway admin, removed on exit), python3; a deployed shim with the
# CloudFormation, Lambda, IAM and STS front doors. Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-cfn-cfnresponse.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
export AWS_REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
STACK="cfnr-$SFX"; FAILSTACK="cfnr-fail-$SFX"; DENYSTACK="cfnr-deny-$SFX"; ROLE="cfnr-reader-$SFX"

log()  { printf '▸ %s\n' "$*"; }
ok()   { printf '▸   ✓ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for t in aws kubectl python3; do command -v "$t" >/dev/null || inconclusive "$t is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
W="$(mktemp -d)"
A=(aws --endpoint-url "$ENDPOINT" --no-cli-pager)

CREATED_USERS=(); CREATED_KEYS=(); ROLE_MADE=""
cleanup() {
  set +e
  unset AWS_SESSION_TOKEN
  [ -n "${ADMIN_AK:-}" ] && export AWS_ACCESS_KEY_ID="$ADMIN_AK" AWS_SECRET_ACCESS_KEY="$ADMIN_SK"
  for s in "$STACK" "$FAILSTACK" "$DENYSTACK"; do
    if "${A[@]}" cloudformation describe-stacks --stack-name "$s" >/dev/null 2>&1; then
      for _ in $(seq 1 60); do
        st="$("${A[@]}" cloudformation describe-stacks --stack-name "$s" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
        case "$st" in *_IN_PROGRESS) sleep 5 ;; *) break ;; esac
      done
      "${A[@]}" cloudformation delete-stack --stack-name "$s" >/dev/null 2>&1
      for _ in $(seq 1 60); do "${A[@]}" cloudformation describe-stacks --stack-name "$s" >/dev/null 2>&1 || break; sleep 3; done
    fi
  done
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
if [ -z "${AWS_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_SECRET_ACCESS_KEY:-}" ]; then
  mint_key "cfnr-admin-$SFX" admins
  export AWS_ACCESS_KEY_ID="$MK_AK" AWS_SECRET_ACCESS_KEY="$MK_SK"
  log "minted a throwaway openinfra:admins deployer (cfnr-admin-$SFX)"
fi
ADMIN_AK="$AWS_ACCESS_KEY_ID"; ADMIN_SK="$AWS_SECRET_ACCESS_KEY"
for i in $(seq 1 24); do # a freshly minted caller's authority takes a minute or so to reach every check
  ME="$("${A[@]}" sts get-caller-identity --query Arn --output text 2>/dev/null)" && break
  [ "$i" = 24 ] && inconclusive "sts get-caller-identity never succeeded"
  sleep 5
done

# The handlers are the AWS documentation's shape: Node.js's callback-less function(event, context) that
# ends with response.send, and Python's cfnresponse.send.
cat > "$W/ok.yaml" <<'YAML'
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Exec:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement: [{Effect: Allow, Principal: {Service: lambda.amazonaws.com}, Action: "sts:AssumeRole"}]
  NodeHandler:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: nodejs22.x
      Handler: index.handler
      Timeout: 60
      Role: !GetAtt Exec.Arn
      Code:
        ZipFile: |
          var response = require('cfn-response');
          exports.handler = function (event, context) {
            var name = event.ResourceProperties.Name || '';
            response.send(event, context, response.SUCCESS, { Greeting: 'hello from node, ' + name }, 'node-' + name);
          };
  PythonHandler:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Timeout: 60
      Role: !GetAtt Exec.Arn
      Code:
        ZipFile: |
          import cfnresponse
          def handler(event, context):
              name = event['ResourceProperties'].get('Name', '')
              cfnresponse.send(event, context, cfnresponse.SUCCESS, {'Greeting': 'hello from python, ' + name})
  NodeGreeting:
    Type: Custom::Greeting
    Properties: { ServiceToken: !GetAtt NodeHandler.Arn, Name: probe }
  PythonGreeting:
    Type: Custom::Greeting
    Properties: { ServiceToken: !GetAtt PythonHandler.Arn, Name: probe }
  Consumer:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: nodejs22.x
      Handler: index.handler
      Role: !GetAtt Exec.Arn
      Environment:
        Variables:
          NODE_GREETING: !GetAtt NodeGreeting.Greeting
          PYTHON_GREETING: !GetAtt PythonGreeting.Greeting
      Code:
        ZipFile: |
          exports.handler = async () => ({ node: process.env.NODE_GREETING, python: process.env.PYTHON_GREETING });
Outputs:
  Consumer: { Value: !Ref Consumer }
  NodeId: { Value: !Ref NodeGreeting }
YAML

# wait_stack <stack>: its status once no operation is in progress.
wait_stack() {
  local st=""
  for _ in $(seq 1 120); do
    st="$("${A[@]}" cloudformation describe-stacks --stack-name "$1" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
    case "$st" in *_IN_PROGRESS|"") sleep 5 ;; *) break ;; esac
  done
  printf '%s' "$st"
}

log "1. inline cfn-response and cfnresponse handlers, deployed with a change set (aws cloudformation deploy)"
# A change set shows the custom resources' Data as known after apply, as AWS's does; executing it creates the
# stack resource by resource.
for i in $(seq 1 5); do # a freshly minted deployer's authority reaches every check within a minute or so
  if "${A[@]}" cloudformation deploy --stack-name "$STACK" --template-file "$W/ok.yaml" --capabilities CAPABILITY_IAM >"$W/d" 2>&1; then
    st="$(wait_stack "$STACK")"
    [ "$st" = CREATE_COMPLETE ] && break
  fi
  [ "$i" = 5 ] && fail "the stack did not deploy: $(tail -c 600 "$W/d") ${st:-} $("${A[@]}" cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatusReason' --output text 2>/dev/null)"
  "${A[@]}" cloudformation delete-stack --stack-name "$STACK" >/dev/null 2>&1
  for _ in $(seq 1 60); do "${A[@]}" cloudformation describe-stacks --stack-name "$STACK" >/dev/null 2>&1 || break; sleep 3; done
  sleep 20
done
out() { "${A[@]}" cloudformation describe-stacks --stack-name "$1" --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text; }
CONSUMER="$(out "$STACK" Consumer)"; NODEID="$(out "$STACK" NodeId)"
[ "$NODEID" = "node-probe" ] || fail "the node handler's PhysicalResourceId is not the resource's Ref: '$NODEID'"
"${A[@]}" lambda get-function-configuration --function-name "$CONSUMER" --query 'Environment.Variables' --output json >"$W/env.json" \
  || fail "get-function-configuration $CONSUMER failed"
python3 - "$W/env.json" <<'PY' || fail "the custom resources' Data did not resolve Fn::GetAtt: $(cat "$W/env.json")"
import json, sys
v = json.load(open(sys.argv[1]))
assert v.get("NODE_GREETING") == "hello from node, probe" and v.get("PYTHON_GREETING") == "hello from python, probe", v
PY
ok "CREATE_COMPLETE; Data resolved Fn::GetAtt (node and python), and the node response's PhysicalResourceId is the Ref"

log "2. a handler that sends FAILED rolls its stack back"
cat > "$W/fail.yaml" <<'YAML'
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Exec:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement: [{Effect: Allow, Principal: {Service: lambda.amazonaws.com}, Action: "sts:AssumeRole"}]
  Refuser:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: nodejs22.x
      Handler: index.handler
      Timeout: 60
      Role: !GetAtt Exec.Arn
      Code:
        ZipFile: |
          var response = require('cfn-response');
          exports.handler = function (event, context) {
            var status = event.RequestType === 'Delete' ? response.SUCCESS : response.FAILED;
            response.send(event, context, status, {});
          };
  Refused:
    Type: Custom::Refused
    Properties: { ServiceToken: !GetAtt Refuser.Arn }
YAML
"${A[@]}" cloudformation create-stack --stack-name "$FAILSTACK" --template-body "file://$W/fail.yaml" --capabilities CAPABILITY_IAM >/dev/null \
  || fail "create-stack $FAILSTACK was refused"
st=""
for _ in $(seq 1 90); do
  st="$("${A[@]}" cloudformation describe-stacks --stack-name "$FAILSTACK" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
  case "$st" in *_IN_PROGRESS|"") sleep 5 ;; *) break ;; esac
done
[ "$st" = "ROLLBACK_COMPLETE" ] || fail "a FAILED response must roll the stack back, got '$st'"
"${A[@]}" cloudformation describe-stacks --stack-name "$FAILSTACK" --query 'Stacks[0].StackStatusReason' --output text >"$W/reason" 2>/dev/null || true
"${A[@]}" cloudformation describe-stack-events --stack-name "$FAILSTACK" --output json >"$W/events" 2>/dev/null || true
grep -q "Refused" "$W/reason" "$W/events" || fail "the rollback does not name the custom resource: $(cat "$W/reason")"
ok "ROLLBACK_COMPLETE, naming the custom resource"

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
CREDS="$("${A[@]}" sts assume-role --role-arn "$ROLE_ARN" --role-session-name cfnr --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text)" \
  || inconclusive "sts assume-role failed"
read -r rak rsk rst <<<"$CREDS"
if AWS_ACCESS_KEY_ID="$rak" AWS_SECRET_ACCESS_KEY="$rsk" AWS_SESSION_TOKEN="$rst" \
   "${A[@]}" cloudformation create-stack --stack-name "$DENYSTACK" --template-body "file://$W/ok.yaml" --capabilities CAPABILITY_IAM >/dev/null 2>"$W/deny.err"; then
  fail "a principal without cloudformation:CreateStack created a stack"
fi
grep -q "AccessDenied" "$W/deny.err" || fail "the refusal is not AccessDenied: $(tail -c 300 "$W/deny.err")"
ok "refused: AccessDenied"

printf '✓ PASS — inline custom-resource handlers using cfn-response (Node.js) and cfnresponse (Python) deploy unchanged: their PUT responses decide the resources and their Data resolves Fn::GetAtt; a FAILED response rolls the stack back; cloudformation:CreateStack is enforced\n'
