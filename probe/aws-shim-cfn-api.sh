#!/usr/bin/env bash
# Compatibility probe for the CloudFormation surface beyond create/update/delete (#347 items H, I, M).
#
# It asserts, over real round-trips against a deployed shim:
#   - OUTPUTS resolve for the common types: a network stack exports its VPC and both subnets (3 of 3),
#     and an app stack that IMPORTS them deploys; its Outputs (queue URL + ARN, parameter name, bucket ARN
#     + regional domain name) are all present; ListImports names the importing stack
#   - an Output naming an attribute open-infra does not provide is REFUSED at validation (nothing created)
#   - parameter values are refused in AWS's words before anything is created: an undeclared key, a
#     missing value, a value outside AllowedValues, an AWS::EC2::Subnet::Id that names no subnet
#   - a CreationPolicy ResourceSignal on a WaitCondition holds the stack CREATE_IN_PROGRESS until
#     SignalResource sends SUCCESS; a FAILURE signal fails the create (rolled back to ROLLBACK_COMPLETE, events say why)
#   - DescribeStackEvents (newest first, per resource), ListStackResources (AWS types, physical ids),
#     DescribeStackResource (Metadata, what cfn-init reads), ValidateTemplate with a parameter that has
#     no default (accepted, as on AWS)
#   - TemplateURL: a template uploaded to the shim's own S3 deploys by URL, including a NESTED stack whose
#     child template is in S3 too, named by a Fn::Sub (Fn::GetAtt Child.Outputs.X resolves); the nested
#     stack is a stack of its own (the parent's resource and Ref are its StackId; it names its ParentId
#     and RootId; it is not deleted on its own) and is deleted with its parent
#   - deleted stacks are kept: both read DELETE_COMPLETE by their StackIds and are listed with
#     --stack-status-filter DELETE_COMPLETE; a stack re-created under the name gets a new StackId, and the
#     deleted one's StackId never acts on it (DeleteStack with it is a no-op)
#   - a Retain bucket a rolled-back create kept: re-creating the stack with its BucketName is refused (the
#     name is taken), and with a new BucketName completes beside it
#
# On-demand (needs a deployed shim with the CloudFormation front door, kube-ovn VPC kinds, and an
# openinfra:admins caller). Exit 0 = pass, 1 = a real failure, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-cfn-api.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
CFN_NS="${CFN_NS:-open-infra-cfn}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 3 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"
# A /16 for the probe's VPC that is unlikely to meet the cluster's own ranges.
OCTET="$(( 200 + $(printf '%d' "0x${SFX:0:2}") % 50 ))"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v python3 >/dev/null || inconclusive "python3 is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
kubectl get ns "$CFN_NS" >/dev/null 2>&1 || inconclusive "CFN namespace ${CFN_NS} missing"

NET="cfnapi-net-$SFX"; APP="cfnapi-app-$SFX"; BAD="cfnapi-bad-$SFX"; FAILST="cfnapi-fail-$SFX"; NEST="cfnapi-nest-$SFX"
RET="cfnapi-ret-$SFX"
BUCKET="cfnapi-$SFX-tmpl"
STACKS=("$RET" "$NEST" "$FAILST" "$APP" "$NET")
CREATED_USERS=(); CREATED_KEYS=()
AK=""; SK=""

cfn() { AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager cloudformation "$@"; }
s3()  { AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager s3 "$@"; }

cleanup() {
  [ -n "$AK" ] && s3 rm "s3://$BUCKET" --recursive >/dev/null 2>&1 || true
  for s in "${STACKS[@]}"; do
    [ -n "$AK" ] && cfn delete-stack --stack-name "$s" >/dev/null 2>&1 || true
    for _ in $(seq 1 60); do
      st="$(cfn describe-stacks --stack-name "$s" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
      case "$st" in ""|DELETE_COMPLETE|*DELETE_FAILED) break;; esac
      sleep 3
    done
  done
  for s in "${STACKS[@]}" "$BAD"; do
    kubectl -n "$SHIM_NS" delete secret "cfn-stack-$s" "cfn-events-$s" "cfn-signals-$s" "noecho-cfn-stack-$s" --ignore-not-found >/dev/null 2>&1 || true
  done
  # The deleted-stack records this run's stacks left (kept 90 days otherwise), nested children included.
  kubectl -n "$SHIM_NS" get secret -l app.kubernetes.io/managed-by=cfn-deleted -o name 2>/dev/null \
    | grep -E "/cfn-deleted-cfnapi-[a-z]+-$SFX" | xargs -r kubectl -n "$SHIM_NS" delete >/dev/null 2>&1 || true
  # The bucket section 7's failed create retained (no stack owns it any more; the reaper removes the empty bucket).
  kubectl -n "$CFN_NS" delete buckets.openinfra.dev -l "cfn.openinfra.dev/stack=$RET" --ignore-not-found >/dev/null 2>&1 || true
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for k in "${CREATED_KEYS[@]:-}";  do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
  rm -rf "$TMP"
}
trap cleanup EXIT

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }
mint_key() { # <owner> <group>
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
  kubectl -n "$SHIM_NS" create secret generic "$name" --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  CREATED_KEYS+=("$name")
  AK="$ak"; SK="$sk"
}

poll() { # <stack> <want> [timeout-iterations] -> prints the last status; 0 when reached
  local s="$1" want="$2" t="${3:-200}" st=""
  for _ in $(seq 1 "$t"); do
    st="$(cfn describe-stacks --stack-name "$s" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
    [ "$st" = "$want" ] && { printf '%s' "$st"; return 0; }
    case "$st" in *_COMPLETE|*_FAILED) [ "$st" != "$want" ] && { printf '%s' "$st"; return 1; };; esac
    sleep 3
  done
  printf '%s' "$st"; return 1
}
outputs() { cfn describe-stacks --stack-name "$1" --query 'Stacks[0].Outputs' --output json; }
output() { outputs "$1" | python3 -c "import json,sys; print(next((o['OutputValue'] for o in json.load(sys.stdin) or [] if o['OutputKey']=='$2'), ''))"; }

log "minting an openinfra:admins deployer"
# await_control_plane <user> <verb> <group> <resource> [namespace]: once IAM policy decides (enforce), a
# caller acts on the cluster as its account identity, whose control-plane rights the IAM compiler compiles a
# pass after the principal is made (and the authorization webhook reloads within 30 s): wait until they have
# arrived, as an AWS client retries while a new principal propagates. Asked as a SubjectAccessReview about
# that identity (the identity itself may not ask the API server about itself). Nothing to wait for in legacy
# and shadow.
await_control_plane() {
  local user="$1" verb="$2" group="$3" resource="$4" ns="${5:-}"
  [ "$(kubectl -n "$SHIM_NS" get configmap openinfra-iam -o jsonpath='{.data.IAM_AUTHZ}' 2>/dev/null)" = enforce ] || return 0
  local acct; acct="$(kubectl -n "$SHIM_NS" get configmap openinfra-aws-identity -o jsonpath='{.data.ACCOUNT_ID}' 2>/dev/null)"
  acct="${acct:-000000000000}"
  local _ ok
  for _ in $(seq 1 60); do
    ok="$(kubectl create -o jsonpath='{.status.allowed}' -f - 2>/dev/null <<SAR
apiVersion: authorization.k8s.io/v1
kind: SubjectAccessReview
spec:
  user: "openinfra:$acct:$user"
  resourceAttributes: { verb: "$verb", group: "$group", resource: "$resource", namespace: "$ns" }
SAR
)"
    [ "$ok" = true ] && return 0
    sleep 3
  done
  inconclusive "the IAM compiler had not compiled $user's control-plane rights after 180 s"
}

mint_key "cfnapi-admin-$SFX" "admins"
await_control_plane "cfnapi-admin-$SFX" create openinfra.dev applications "${CFN_NAMESPACE:-open-infra-cfn}"
sleep 20 # the key reaches the shim's key cache

# --- 1. a network stack exports its VPC and both subnets ---------------------------------------------
cat > "$TMP/net.yaml" <<YAML
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties: { CidrBlock: 10.$OCTET.0.0/16 }
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties: { VpcId: !Ref Vpc, CidrBlock: 10.$OCTET.1.0/24 }
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties: { VpcId: !Ref Vpc, CidrBlock: 10.$OCTET.2.0/24 }
Outputs:
  VpcId:   { Value: !Ref Vpc, Export: { Name: !Sub "\${AWS::StackName}-vpc" } }
  SubnetA: { Value: !Ref SubnetA, Export: { Name: !Sub "\${AWS::StackName}-subnet-a" } }
  SubnetB: { Value: !GetAtt SubnetB.SubnetId, Export: { Name: !Sub "\${AWS::StackName}-subnet-b" } }
YAML
log "create-stack $NET (VPC + 2 subnets, 3 exports)"
cfn create-stack --stack-name "$NET" --template-body "file://$TMP/net.yaml" >/dev/null || fail "create-stack $NET"
st="$(poll "$NET" CREATE_COMPLETE)" || fail "$NET did not complete: $st"
n="$(outputs "$NET" | python3 -c 'import json,sys; print(len([o for o in json.load(sys.stdin) or [] if o.get("ExportName")]))')"
[ "$n" = 3 ] || fail "the network stack must export 3 of 3 (VPC + 2 subnets), got $n"
log "  ✓ 3 of 3 exports"

# --- 2. an app stack imports them; its Outputs resolve; a signal-waiting WaitCondition ---------------
cat > "$TMP/app.yaml" <<YAML
Resources:
  AppSG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: app, VpcId: !ImportValue $NET-vpc }
  Jobs:
    Type: AWS::SQS::Queue
    Properties: { QueueName: cfnapi-$SFX-jobs }
  Flag:
    Type: AWS::SSM::Parameter
    Metadata:
      AWS::CloudFormation::Init: { config: { commands: { hello: { command: "echo hi" } } } }
    Properties: { Name: /cfnapi-$SFX/flag, Type: String, Value: "on" }
  Tmpl:
    Type: AWS::S3::Bucket
    Properties: { BucketName: $BUCKET }
  Ready:
    Type: AWS::CloudFormation::WaitCondition
    DependsOn: Flag
    CreationPolicy: { ResourceSignal: { Count: 1, Timeout: PT10M } }
Outputs:
  QueueUrl:   { Value: !Ref Jobs }
  QueueArn:   { Value: !GetAtt Jobs.Arn }
  ParamName:  { Value: !Ref Flag }
  BucketArn:  { Value: !GetAtt Tmpl.Arn }
  BucketHost: { Value: !GetAtt Tmpl.RegionalDomainName }
  GroupId:    { Value: !GetAtt AppSG.GroupId }
YAML
log "create-stack $APP (imports the VPC; waits for one resource signal)"
cfn create-stack --stack-name "$APP" --template-body "file://$TMP/app.yaml" >/dev/null || fail "create-stack $APP"
for _ in $(seq 1 100); do
  rs="$(cfn describe-stack-resources --stack-name "$APP" --logical-resource-id Ready --query 'StackResources[0].ResourceStatus' --output text 2>/dev/null || true)"
  [ "$rs" = CREATE_IN_PROGRESS ] && break
  sleep 3
done
[ "$(cfn describe-stacks --stack-name "$APP" --query 'Stacks[0].StackStatus' --output text)" = CREATE_IN_PROGRESS ] \
  || fail "the stack must wait for its resource signal (CREATE_IN_PROGRESS)"
sleep 6
[ "$(cfn describe-stacks --stack-name "$APP" --query 'Stacks[0].StackStatus' --output text)" = CREATE_IN_PROGRESS ] \
  || fail "the stack completed without its signal"
cfn signal-resource --stack-name "$APP" --logical-resource-id Ready --unique-id probe-1 --status SUCCESS || fail "signal-resource"
st="$(poll "$APP" CREATE_COMPLETE)" || fail "$APP did not complete after its signal: $st"
log "  ✓ held for its signal, then CREATE_COMPLETE"
for k in QueueUrl QueueArn ParamName BucketArn BucketHost GroupId; do
  [ -n "$(output "$APP" "$k")" ] || fail "Output $k is missing (outputs: $(outputs "$APP"))"
done
case "$(output "$APP" QueueUrl)" in */cfnapi-$SFX-jobs) ;; *) fail "QueueUrl: $(output "$APP" QueueUrl)";; esac
case "$(output "$APP" QueueArn)" in arn:aws:sqs:*:cfnapi-$SFX-jobs) ;; *) fail "QueueArn: $(output "$APP" QueueArn)";; esac
[ "$(output "$APP" ParamName)" = "/cfnapi-$SFX/flag" ] || fail "ParamName"
[ "$(output "$APP" BucketArn)" = "arn:aws:s3:::$BUCKET" ] || fail "BucketArn: $(output "$APP" BucketArn)"
log "  ✓ every Output resolves (queue URL + ARN, parameter name, bucket ARN + domain, group id)"
cfn list-imports --export-name "$NET-vpc" --query 'Imports' --output text | grep -qw "$APP" || fail "ListImports must name $APP"
log "  ✓ ListImports names the importing stack"

# --- 3. events, resources, metadata --------------------------------------------------------------------
ev="$(cfn describe-stack-events --stack-name "$APP" --output json)"
printf '%s' "$ev" | python3 -c '
import json, sys
evs = json.load(sys.stdin)["StackEvents"]
assert evs[0]["ResourceType"] == "AWS::CloudFormation::Stack" and evs[0]["ResourceStatus"] == "CREATE_COMPLETE", evs[0]
seen = {(e["LogicalResourceId"], e["ResourceStatus"]) for e in evs}
for r in ("AppSG", "Jobs", "Flag", "Tmpl", "Ready"):
    assert (r, "CREATE_IN_PROGRESS") in seen and (r, "CREATE_COMPLETE") in seen, r
' || fail "DescribeStackEvents must show each resource's transitions, newest first"
log "  ✓ DescribeStackEvents"
cfn list-stack-resources --stack-name "$APP" --output json | python3 -c '
import json, sys
rs = {r["LogicalResourceId"]: r for r in json.load(sys.stdin)["StackResourceSummaries"]}
assert rs["Jobs"]["ResourceType"] == "AWS::SQS::Queue" and rs["Jobs"]["ResourceStatus"] == "CREATE_COMPLETE", rs["Jobs"]
assert rs["Tmpl"]["PhysicalResourceId"].endswith("-tmpl"), rs["Tmpl"]
' || fail "ListStackResources must report AWS types and physical ids"
cfn describe-stack-resource --stack-name "$APP" --logical-resource-id Flag --query 'StackResourceDetail.Metadata' --output text \
  | grep -q 'AWS::CloudFormation::Init' || fail "DescribeStackResource must return the resource's Metadata"
log "  ✓ ListStackResources, DescribeStackResource (Metadata)"

printf 'Parameters:\n  Ami: { Type: String }\nResources:\n  P: { Type: AWS::SSM::Parameter, Properties: { Type: String, Name: /x, Value: !Ref Ami } }\n' > "$TMP/val.yaml"
cfn validate-template --template-body "file://$TMP/val.yaml" >/dev/null || fail "ValidateTemplate must accept a parameter with no default"
log "  ✓ ValidateTemplate without parameter values"

# --- 4. an unresolvable Output is refused before anything is created -----------------------------------
printf 'Resources:\n  Q: { Type: AWS::SQS::Queue }\nOutputs:\n  Nope: { Value: !GetAtt Q.NoSuchAttribute }\n' > "$TMP/bad.yaml"
if out="$(cfn create-stack --stack-name "$BAD" --template-body "file://$TMP/bad.yaml" 2>&1)"; then
  fail "an Output naming an unsupported attribute must be refused at validation"
fi
printf '%s' "$out" | grep -q "does not resolve on open-infra" || fail "the refusal must say the Output does not resolve: $out"
cfn describe-stacks --stack-name "$BAD" >/dev/null 2>&1 && fail "nothing may be recorded for a refused stack"
log "  ✓ an unresolvable Output is refused at validation (nothing created)"

# --- 4b. parameter values are refused as AWS refuses them, before anything is created ------------------
cat > "$TMP/params.yaml" <<'YAML'
Parameters:
  Env: { Type: String, AllowedValues: [dev, prod], Default: dev }
  SubnetId: { Type: "AWS::EC2::Subnet::Id" }
Resources:
  P: { Type: AWS::SSM::Parameter, Properties: { Type: String, Value: !Sub "${Env}-${SubnetId}" } }
YAML
param_refused() { # <want> <parameters…>
  local want="$1"; shift
  local args=(); [ $# -gt 0 ] && args=(--parameters "$@")
  if out="$(cfn create-stack --stack-name "$BAD" --template-body "file://$TMP/params.yaml" ${args[@]+"${args[@]}"} 2>&1)"; then
    fail "create-stack with parameters [$*] must be refused ($want)"
  fi
  printf '%s' "$out" | grep -qF "$want" || fail "the refusal must say '$want': $out"
  cfn describe-stacks --stack-name "$BAD" >/dev/null 2>&1 && fail "nothing may be recorded for a refused stack"
  return 0
}
SUBNET_A="$(output "$NET" SubnetA)"
param_refused "Parameters: [Bogus] do not exist in the template" ParameterKey=SubnetId,ParameterValue="$SUBNET_A" ParameterKey=Bogus,ParameterValue=x
param_refused "Parameters: [SubnetId] must have values"
param_refused "Parameter 'Env' must be one of AllowedValues" ParameterKey=SubnetId,ParameterValue="$SUBNET_A" ParameterKey=Env,ParameterValue=stage
param_refused "parameter value cfnapi-nosuch-$SFX for parameter name SubnetId does not exist" ParameterKey=SubnetId,ParameterValue="cfnapi-nosuch-$SFX"
log "  ✓ an undeclared parameter, a missing value, a value outside AllowedValues and a subnet that does not exist are refused in AWS's words"

# --- 5. a FAILURE signal fails the create ---------------------------------------------------------------
printf 'Resources:\n  P: { Type: AWS::SSM::Parameter, Properties: { Name: /cfnapi-%s/f, Type: String, Value: x } }\n  W:\n    Type: AWS::CloudFormation::WaitCondition\n    DependsOn: P\n    CreationPolicy: { ResourceSignal: { Count: 1, Timeout: PT10M } }\n' "$SFX" > "$TMP/fail.yaml"
cfn create-stack --stack-name "$FAILST" --template-body "file://$TMP/fail.yaml" >/dev/null || fail "create-stack $FAILST"
for _ in $(seq 1 100); do
  rs="$(cfn describe-stack-resources --stack-name "$FAILST" --logical-resource-id W --query 'StackResources[0].ResourceStatus' --output text 2>/dev/null || true)"
  [ "$rs" = CREATE_IN_PROGRESS ] && break
  sleep 3
done
cfn signal-resource --stack-name "$FAILST" --logical-resource-id W --unique-id probe-f --status FAILURE || fail "signal-resource FAILURE"
st="$(poll "$FAILST" ROLLBACK_COMPLETE)" || fail "a FAILURE signal must fail the create (rolled back: ROLLBACK_COMPLETE), got $st"
cfn describe-stack-events --stack-name "$FAILST" --query 'StackEvents[?ResourceStatus==`CREATE_FAILED`].ResourceStatusReason' --output text \
  | grep -q "FAILURE signal" || fail "the events must say a FAILURE signal failed it"
log "  ✓ a FAILURE signal fails the create, and the events say why"

# --- 6. TemplateURL, with a nested stack (a stack of its own) -------------------------------------------
printf 'Parameters:\n  Name: { Type: String }\nResources:\n  Q: { Type: AWS::SQS::Queue, Properties: { QueueName: !Ref Name } }\nOutputs:\n  ChildQueue: { Value: !GetAtt Q.QueueName }\n' > "$TMP/child.yaml"
cat > "$TMP/parent.yaml" <<YAML
Parameters:
  Base: { Type: String, Default: "$ENDPOINT/$BUCKET" }
Resources:
  Child:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: !Sub "\${Base}/child.yaml"
      Parameters: { Name: cfnapi-$SFX-child }
Outputs:
  FromChild: { Value: !GetAtt Child.Outputs.ChildQueue }
  ChildId:   { Value: !Ref Child }
YAML
s3 cp "$TMP/child.yaml" "s3://$BUCKET/child.yaml" >/dev/null || fail "uploading the child template"
s3 cp "$TMP/parent.yaml" "s3://$BUCKET/parent.yaml" >/dev/null || fail "uploading the parent template"
cfn create-stack --stack-name "$NEST" --template-url "$ENDPOINT/$BUCKET/parent.yaml" >/dev/null || fail "create-stack --template-url"
st="$(poll "$NEST" CREATE_COMPLETE)" || fail "$NEST (TemplateURL + nested stack) did not complete: $st"
[ "$(output "$NEST" FromChild)" = "cfnapi-$SFX-child" ] || fail "Fn::GetAtt Child.Outputs.ChildQueue: $(output "$NEST" FromChild)"
log "  ✓ TemplateURL from the shim's S3 (a Fn::Sub), with a nested stack's Outputs"
# The nested stack is a stack of its own: the parent's resource is its StackId, and it names its parent.
NEST_ID="$(cfn describe-stacks --stack-name "$NEST" --query 'Stacks[0].StackId' --output text)"
CHILD_ID="$(cfn describe-stack-resources --stack-name "$NEST" --logical-resource-id Child --query 'StackResources[0].PhysicalResourceId' --output text)"
case "$CHILD_ID" in "arn:aws:cloudformation:"*":stack/$NEST-child-"*) ;; *) fail "the nested stack resource's physical id must be the child's StackId, got $CHILD_ID";; esac
[ "$(output "$NEST" ChildId)" = "$CHILD_ID" ] || fail "Ref Child must be the child's StackId: $(output "$NEST" ChildId)"
CHILD="$(printf '%s' "$CHILD_ID" | cut -d/ -f2)"
[ "$(cfn describe-stacks --stack-name "$CHILD_ID" --query 'Stacks[0].[StackStatus,ParentId,RootId]' --output text)" = "$(printf 'CREATE_COMPLETE\t%s\t%s' "$NEST_ID" "$NEST_ID")" ] \
  || fail "the child must be CREATE_COMPLETE naming its parent and root: $(cfn describe-stacks --stack-name "$CHILD_ID" --output json)"
cfn list-stacks --query "StackSummaries[?StackName=='$CHILD'].ParentId" --output text | grep -qF "$NEST_ID" || fail "ListStacks must list the child with its ParentId"
log "  ✓ the nested stack is a stack of its own ($CHILD), naming its parent and root"
out="$(cfn delete-stack --stack-name "$CHILD" 2>&1)" && fail "a nested stack must not be deleted on its own"
printf '%s' "$out" | grep -q "nested stack" || fail "the refusal must say it is a nested stack: $out"
# Deleted with its parent; both are then kept as deleted stacks, readable by their StackIds.
delete_parent() {
  cfn delete-stack --stack-name "$NEST" >/dev/null || fail "delete-stack $NEST"
  for _ in $(seq 1 100); do
    st="$(cfn describe-stacks --stack-name "$NEST" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
    case "$st" in "") return 0;; *DELETE_FAILED) fail "delete-stack $NEST: $st";; esac
    sleep 3
  done
  fail "delete-stack $NEST did not finish"
}
delete_parent
cfn describe-stacks --stack-name "$CHILD" >/dev/null 2>&1 && fail "the nested stack must be deleted with its parent"
[ "$(cfn describe-stacks --stack-name "$NEST_ID" --query 'Stacks[0].StackStatus' --output text)" = DELETE_COMPLETE ] || fail "the deleted parent must read DELETE_COMPLETE by its StackId"
[ "$(cfn describe-stacks --stack-name "$CHILD_ID" --query 'Stacks[0].StackStatus' --output text)" = DELETE_COMPLETE ] || fail "the deleted child must read DELETE_COMPLETE by its StackId"
cfn describe-stack-events --stack-name "$NEST_ID" --query 'StackEvents[0].ResourceStatus' --output text | grep -qx DELETE_COMPLETE || fail "the deleted parent's events must end DELETE_COMPLETE"
n="$(cfn list-stacks --stack-status-filter DELETE_COMPLETE --query "length(StackSummaries[?StackId=='$NEST_ID' || StackId=='$CHILD_ID'])" --output text)"
[ "$n" = 2 ] || fail "ListStacks must list both deleted stacks, got $n"
log "  ✓ deleted with its parent; both listed DELETE_COMPLETE and readable by their StackIds"
# Re-created under the deleted stack's name: a new StackId; the deleted one stays known by its own.
cfn create-stack --stack-name "$NEST" --template-url "$ENDPOINT/$BUCKET/parent.yaml" >/dev/null || fail "re-create-stack $NEST"
st="$(poll "$NEST" CREATE_COMPLETE)" || fail "re-created $NEST did not complete: $st"
NEW_ID="$(cfn describe-stacks --stack-name "$NEST" --query 'Stacks[0].StackId' --output text)"
[ "$NEW_ID" != "$NEST_ID" ] || fail "a re-created stack must get a new StackId"
[ "$(cfn describe-stacks --stack-name "$NEST_ID" --query 'Stacks[0].StackStatus' --output text)" = DELETE_COMPLETE ] || fail "the deleted stack must still read by its own StackId"
cfn delete-stack --stack-name "$NEST_ID" >/dev/null || fail "delete-stack by a deleted stack's StackId must be a no-op"
sleep 3
[ "$(cfn describe-stacks --stack-name "$NEST" --query 'Stacks[0].StackStatus' --output text)" = CREATE_COMPLETE ] || fail "a deleted stack's StackId must never act on the stack now using its name"
log "  ✓ re-created with a new StackId; the deleted stack's StackId reads it and never acts on the new one"

# --- 7. a Retain bucket a failed create kept does not block re-creating the stack ----------------------
# The create fails (a FAILURE signal) and rolls back, keeping its Retain bucket, which no stack owns any
# more. Re-created with the same BucketName it is refused (the name is taken, as on AWS); with a new
# BucketName it completes beside the retained bucket.
ret_tmpl() { # <bucket name>
  printf 'Resources:\n  Data:\n    Type: AWS::S3::Bucket\n    DeletionPolicy: Retain\n    Properties: { BucketName: %s }\n  W:\n    Type: AWS::CloudFormation::WaitCondition\n    DependsOn: Data\n    CreationPolicy: { ResourceSignal: { Count: 1, Timeout: PT10M } }\n' "$1"
}
signal_when_waiting() { # <stack> <status>
  for _ in $(seq 1 100); do
    rs="$(cfn describe-stack-resources --stack-name "$1" --logical-resource-id W --query 'StackResources[0].ResourceStatus' --output text 2>/dev/null || true)"
    [ "$rs" = CREATE_IN_PROGRESS ] && break
    sleep 3
  done
  cfn signal-resource --stack-name "$1" --logical-resource-id W --unique-id "probe-$2" --status "$2" || fail "signal-resource $2 on $1"
}
delete_and_wait() { # <stack>
  cfn delete-stack --stack-name "$1" >/dev/null || fail "delete-stack $1"
  for _ in $(seq 1 100); do
    st="$(cfn describe-stacks --stack-name "$1" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
    case "$st" in ""|DELETE_COMPLETE) return 0;; *DELETE_FAILED) fail "delete-stack $1: $st";; esac
    sleep 3
  done
  fail "delete-stack $1 did not finish"
}
ret_tmpl "cfnapi-$SFX-ret-a" > "$TMP/ret-a.yaml"
cfn create-stack --stack-name "$RET" --template-body "file://$TMP/ret-a.yaml" >/dev/null || fail "create-stack $RET"
signal_when_waiting "$RET" FAILURE
st="$(poll "$RET" ROLLBACK_COMPLETE)" || fail "the failed create must end ROLLBACK_COMPLETE, got $st"
kubectl -n "$CFN_NS" get buckets.openinfra.dev -l "cfn.openinfra.dev/stack=$RET" -o name | grep -q . || fail "the rollback must keep the Retain bucket"
delete_and_wait "$RET"
# The same BucketName: still the retained bucket's.
cfn create-stack --stack-name "$RET" --template-body "file://$TMP/ret-a.yaml" >/dev/null || fail "create-stack $RET (same BucketName)"
st="$(poll "$RET" ROLLBACK_COMPLETE)" || fail "re-creating with the retained bucket's BucketName must fail, got $st"
cfn describe-stack-events --stack-name "$RET" --query 'StackEvents[?ResourceStatus==`CREATE_FAILED`].ResourceStatusReason' --output text \
  | grep -q "left behind" || fail "the events must say the BucketName is the retained bucket's"
delete_and_wait "$RET"
# A new BucketName: completes, beside the retained bucket.
ret_tmpl "cfnapi-$SFX-ret-b" > "$TMP/ret-b.yaml"
cfn create-stack --stack-name "$RET" --template-body "file://$TMP/ret-b.yaml" >/dev/null || fail "create-stack $RET (new BucketName)"
signal_when_waiting "$RET" SUCCESS
st="$(poll "$RET" CREATE_COMPLETE)" || fail "re-creating with a new BucketName must complete beside the retained bucket, got $st"
[ "$(kubectl -n "$CFN_NS" get buckets.openinfra.dev -l "cfn.openinfra.dev/stack=$RET" -o name | wc -l)" -eq 2 ] \
  || fail "the retained bucket and the re-created stack's must both exist"
log "  ✓ a Retain bucket a failed create kept is refused by name, and does not block a re-created stack with a new BucketName"

printf '✓ PASS — the CloudFormation API surface: Outputs resolve and cross-stack exports import; an unresolvable Output is refused; resource signals (SUCCESS and FAILURE) are waited for; DescribeStackEvents, ListStackResources, DescribeStackResource, ListImports and ValidateTemplate answer as on AWS; TemplateURL and nested stacks deploy from the shim'"'"'s S3.\n'
