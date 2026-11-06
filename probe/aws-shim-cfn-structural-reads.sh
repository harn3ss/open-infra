#!/usr/bin/env bash
# Compatibility probe: a stack's structural resources read back through their own AWS APIs.
#
# A stack's internet gateway, its VPC attachment, a route table, its route and its subnet association, a VPC
# endpoint and an instance profile provision nothing of their own on open-infra (the gateway and routes are
# part of the kind: Vpc, the endpoint is a kind: VpcEndpoint, the profile only carries the instance's role).
# This deploys a small stack of them with the real AWS CLI and reads each one back through the API AWS
# serves it from, asserting the id each read answers is the stack's Ref for it — the PhysicalResourceId
# DescribeStackResources lists, and the stack's Outputs:
#   - ec2 describe-internet-gateways: the gateway by its Ref, attached to the stack's VPC (the attachment)
#   - ec2 describe-route-tables: the table by its Ref, in the VPC, with the 0.0.0.0/0 route to the gateway
#     (the route's Ref is "<table>|0.0.0.0/0") and the subnet association by its Ref; the VPC's main table
#   - ec2 describe-network-acls: the VPC's default network ACL, associated with the stack's subnet (a stack's
#     SubnetNetworkAclAssociation is refused at plan time, so the read is of the ACL that governs the subnet)
#   - ec2 describe-vpc-endpoints: the endpoint by its Ref, with AWS's service name, in the VPC
#   - iam get-instance-profile / list-instance-profiles / list-instance-profiles-for-role: the profile by its
#     Ref, its ARN the stack's Fn::GetAtt Arn, under its path, carrying the stack's role
# and the NEGATIVES:
#   - an id that does not exist is each API's NotFound (InvalidInternetGatewayID.NotFound,
#     InvalidRouteTableID.NotFound, InvalidNetworkAclID.NotFound, InvalidVpcEndpointId.NotFound, NoSuchEntity)
#   - a principal with no grant is refused (UnauthorizedOperation / AccessDenied) whether or not the id exists
#   - once the stack is deleted, its gateway, table and profile are gone too
#
# On-demand (needs a deployed shim with the CloudFormation front door, the kube-ovn VPC kinds and kind:
# VpcEndpoint, and an openinfra:admins caller). Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-cfn-structural-reads.sh
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
OCTET="$(( 150 + $(printf '%d' "0x${SFX:0:2}") % 50 ))"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v python3 >/dev/null || inconclusive "python3 is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
kubectl get ns "$CFN_NS" >/dev/null 2>&1 || inconclusive "CFN namespace ${CFN_NS} missing"
kubectl get crd vpcs.openinfra.dev subnets.openinfra.dev vpcendpoints.openinfra.dev >/dev/null 2>&1 \
  || inconclusive "the kube-ovn VPC kinds (kind: Vpc, Subnet, VpcEndpoint) are not installed"

STACK="structural-$SFX"
CREATED_USERS=(); CREATED_KEYS=()
AK=""; SK=""

as()  { local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager "$@"; }
cfn() { as "$AK" "$SK" cloudformation "$@"; }
ec2() { as "$AK" "$SK" ec2 "$@"; }
iamc() { as "$AK" "$SK" iam "$@"; }

stack_status() { cfn describe-stacks --stack-name "$1" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true; }

cleanup() {
  if [ -n "$AK" ]; then
    cfn delete-stack --stack-name "$STACK" >/dev/null 2>&1 || true
    for _ in $(seq 1 60); do
      case "$(stack_status "$STACK")" in ""|DELETE_COMPLETE|*DELETE_FAILED) break;; esac
      sleep 3
    done
  fi
  kubectl -n "$SHIM_NS" delete secret "cfn-stack-$STACK" "cfn-events-$STACK" "cfn-signals-$STACK" --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$SHIM_NS" get secret -l app.kubernetes.io/managed-by=cfn-deleted -o name 2>/dev/null \
    | grep -E "/cfn-deleted-$STACK" | xargs -r kubectl -n "$SHIM_NS" delete >/dev/null 2>&1 || true
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for k in "${CREATED_KEYS[@]:-}";  do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
  rm -rf "$TMP"
}
trap cleanup EXIT

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }
mint_key() { # <owner> <group> -> MK_AK / MK_SK (runs in THIS shell so CREATED_* reach cleanup)
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
  MK_AK="$ak"; MK_SK="$sk"
}

# await_control_plane <user> <verb> <group> <resource> [namespace]: in enforce a caller acts on the cluster
# as its account identity, whose rights the IAM compiler compiles a pass after the principal is made: wait
# for them, as an AWS client retries while a new principal propagates. Nothing to wait for in legacy/shadow.
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

log "minting an openinfra:admins deployer and a principal with no grant"
mint_key "structural-admin-$SFX" "admins"; AK="$MK_AK"; SK="$MK_SK"
mint_key "structural-nobody-$SFX" "nobody"; NAK="$MK_AK"; NSK="$MK_SK"
await_control_plane "structural-admin-$SFX" create openinfra.dev applications "$CFN_NS"
sleep 20 # the keys reach the shim's key cache

# --- 1. the stack ----------------------------------------------------------------------------------------
cat > "$TMP/stack.yaml" <<YAML
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties: { CidrBlock: 10.$OCTET.0.0/16 }
  PublicSubnet:
    Type: AWS::EC2::Subnet
    Properties: { VpcId: !Ref Vpc, CidrBlock: 10.$OCTET.1.0/24 }
  Igw:
    Type: AWS::EC2::InternetGateway
    Properties:
      Tags: [{ Key: Name, Value: structural-$SFX }]
  IgwAttach:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties: { VpcId: !Ref Vpc, InternetGatewayId: !Ref Igw }
  PublicRT:
    Type: AWS::EC2::RouteTable
    Properties: { VpcId: !Ref Vpc }
  DefaultRoute:
    Type: AWS::EC2::Route
    DependsOn: IgwAttach
    Properties: { RouteTableId: !Ref PublicRT, DestinationCidrBlock: 0.0.0.0/0, GatewayId: !Ref Igw }
  PublicAssoc:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties: { SubnetId: !Ref PublicSubnet, RouteTableId: !Ref PublicRT }
  S3Endpoint:
    Type: AWS::EC2::VPCEndpoint
    Properties: { VpcId: !Ref Vpc, VpcEndpointType: Gateway, ServiceName: !Sub "com.amazonaws.\${AWS::Region}.s3" }
  InstanceRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement: [{ Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: sts:AssumeRole }]
  InstanceProfile:
    Type: AWS::IAM::InstanceProfile
    Properties: { Path: /structural/, Roles: [!Ref InstanceRole] }
Outputs:
  IgwId:        { Value: !Ref Igw }
  RouteTableId: { Value: !GetAtt PublicRT.RouteTableId }
  EndpointId:   { Value: !Ref S3Endpoint }
  ProfileName:  { Value: !Ref InstanceProfile }
  ProfileArn:   { Value: !GetAtt InstanceProfile.Arn }
YAML
log "create-stack $STACK (VPC, subnet, internet gateway + attachment, route table + route + association, S3 endpoint, instance profile)"
cfn create-stack --stack-name "$STACK" --template-body "file://$TMP/stack.yaml" --capabilities CAPABILITY_IAM >/dev/null || fail "create-stack $STACK"
st=""
for _ in $(seq 1 200); do
  st="$(stack_status "$STACK")"
  case "$st" in CREATE_COMPLETE) break;; *_COMPLETE|*_FAILED) fail "$STACK did not complete: $st ($(cfn describe-stack-events --stack-name "$STACK" --query 'StackEvents[?ends_with(ResourceStatus, `FAILED`)].[LogicalResourceId,ResourceStatusReason]' --output text 2>/dev/null | head -5))";; esac
  sleep 3
done
[ "$st" = CREATE_COMPLETE ] || fail "$STACK did not complete in time: $st"
log "  ✓ CREATE_COMPLETE"

# The stack's Refs: each resource's PhysicalResourceId, and the Outputs.
cfn describe-stack-resources --stack-name "$STACK" --output json > "$TMP/resources.json" || fail "describe-stack-resources"
cfn describe-stacks --stack-name "$STACK" --query 'Stacks[0].Outputs' --output json > "$TMP/outputs.json" || fail "describe-stacks"
phys() { python3 - "$TMP/resources.json" "$1" <<'PY'
import json, sys
rs = {r["LogicalResourceId"]: r.get("PhysicalResourceId", "") for r in json.load(open(sys.argv[1]))["StackResources"]}
print(rs.get(sys.argv[2], ""))
PY
}
output() { python3 -c 'import json,sys; print(next((o["OutputValue"] for o in json.load(open(sys.argv[1])) or [] if o["OutputKey"]==sys.argv[2]), ""))' "$TMP/outputs.json" "$1"; }
VPC="$(phys Vpc)"; SUBNET="$(phys PublicSubnet)"; IGW="$(phys Igw)"; ATTACH="$(phys IgwAttach)"; RT="$(phys PublicRT)"
ROUTE="$(phys DefaultRoute)"; ASSOC="$(phys PublicAssoc)"; EP="$(phys S3Endpoint)"; ROLE="$(phys InstanceRole)"; PROF="$(phys InstanceProfile)"
for v in VPC SUBNET IGW ATTACH RT ROUTE ASSOC EP ROLE PROF; do
  [ -n "${!v}" ] || fail "DescribeStackResources lists no PhysicalResourceId for $v ($(cat "$TMP/resources.json" | head -c 600))"
done
[ "$(output IgwId)" = "$IGW" ] && [ "$(output RouteTableId)" = "$RT" ] && [ "$(output EndpointId)" = "$EP" ] && [ "$(output ProfileName)" = "$PROF" ] \
  || fail "the Outputs (the Refs) must equal the PhysicalResourceIds: $(cat "$TMP/outputs.json")"
[ "$ROUTE" = "$RT|0.0.0.0/0" ] || fail "the route's Ref is $ROUTE, want $RT|0.0.0.0/0 (its table and destination)"
log "  ✓ Refs: igw $IGW, rtb $RT, assoc $ASSOC, endpoint $EP, profile $PROF"

# --- 2. EC2: the gateway, the route table, the network ACL, the endpoint ---------------------------------------
log "ec2 describe-internet-gateways: the stack's gateway, attached to its VPC"
ec2 describe-internet-gateways --internet-gateway-ids "$IGW" --output json > "$TMP/igw.json" 2>&1 || fail "describe-internet-gateways: $(head -c 400 "$TMP/igw.json")"
python3 - "$TMP/igw.json" "$IGW" "$VPC" "$STACK" <<'PY' || fail "describe-internet-gateways: $(head -c 600 "$TMP/igw.json")"
import json, sys
gws = json.load(open(sys.argv[1]))["InternetGateways"]
assert [g["InternetGatewayId"] for g in gws] == [sys.argv[2]], gws
atts = gws[0].get("Attachments", [])
assert [a["VpcId"] for a in atts] == [sys.argv[3]] and atts[0]["State"] in ("available", "attaching"), atts
tags = {t["Key"]: t["Value"] for t in gws[0].get("Tags", [])}
assert tags.get("aws:cloudformation:stack-name") == sys.argv[4] and tags.get("aws:cloudformation:logical-id") == "Igw", tags
PY
ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC" --query 'InternetGateways[].InternetGatewayId' --output text \
  | grep -qw "$IGW" || fail "describe-internet-gateways --filters attachment.vpc-id=$VPC must find the gateway"
log "  ✓ $IGW attached to $VPC (the attachment $ATTACH)"

log "ec2 describe-route-tables: the stack's table, its route and its association; the VPC's main table"
ec2 describe-route-tables --route-table-ids "$RT" --output json > "$TMP/rt.json" 2>&1 || fail "describe-route-tables: $(head -c 400 "$TMP/rt.json")"
python3 - "$TMP/rt.json" "$RT" "$VPC" "$IGW" "$ASSOC" "$SUBNET" <<'PY' || fail "describe-route-tables: $(head -c 800 "$TMP/rt.json")"
import json, sys
rt_id, vpc, igw, assoc, subnet = sys.argv[2:7]
rts = json.load(open(sys.argv[1]))["RouteTables"]
assert [r["RouteTableId"] for r in rts] == [rt_id] and rts[0]["VpcId"] == vpc, rts
routes = rts[0]["Routes"]
assert any(r.get("DestinationCidrBlock") == "0.0.0.0/0" and r.get("GatewayId") == igw for r in routes), routes
assert any(r.get("GatewayId") == "local" for r in routes), routes
assocs = rts[0]["Associations"]
assert any(a["RouteTableAssociationId"] == assoc and a.get("SubnetId") == subnet and not a["Main"] for a in assocs), assocs
PY
ec2 describe-route-tables --filters "Name=association.subnet-id,Values=$SUBNET" --query 'RouteTables[].RouteTableId' --output text \
  | grep -qw "$RT" || fail "describe-route-tables --filters association.subnet-id=$SUBNET must find the stack's table"
MAIN="$(ec2 describe-route-tables --filters "Name=vpc-id,Values=$VPC" "Name=association.main,Values=true" --query 'RouteTables[].RouteTableId' --output text)"
[ -n "$MAIN" ] && [ "$MAIN" != "$RT" ] || fail "the VPC must have one main route table, not the stack's: '$MAIN'"
log "  ✓ $RT in $VPC: 0.0.0.0/0 -> $IGW, associated with $SUBNET ($ASSOC); main table $MAIN"

log "ec2 describe-network-acls: the VPC's default ACL governs the stack's subnet"
ec2 describe-network-acls --filters "Name=vpc-id,Values=$VPC" --output json > "$TMP/acl.json" 2>&1 || fail "describe-network-acls: $(head -c 400 "$TMP/acl.json")"
ACL="$(python3 - "$TMP/acl.json" "$SUBNET" <<'PY'
import json, sys
acls = json.load(open(sys.argv[1]))["NetworkAcls"]
d = [a for a in acls if a["IsDefault"]]
assert len(d) == 1, acls
assert any(x["SubnetId"] == sys.argv[2] for x in d[0]["Associations"]), d[0]["Associations"]
assert any(e["RuleNumber"] == 100 and e["RuleAction"] == "allow" for e in d[0]["Entries"]), d[0]["Entries"]
print(d[0]["NetworkAclId"])
PY
)" || fail "describe-network-acls: $(head -c 800 "$TMP/acl.json")"
ec2 describe-network-acls --network-acl-ids "$ACL" --query 'NetworkAcls[].NetworkAclId' --output text | grep -qw "$ACL" || fail "describe-network-acls --network-acl-ids $ACL"
log "  ✓ default ACL $ACL associated with $SUBNET"

log "ec2 describe-vpc-endpoints: the stack's endpoint"
ec2 describe-vpc-endpoints --vpc-endpoint-ids "$EP" --output json > "$TMP/ep.json" 2>&1 || fail "describe-vpc-endpoints: $(head -c 400 "$TMP/ep.json")"
python3 - "$TMP/ep.json" "$EP" "$VPC" "$REGION" <<'PY' || fail "describe-vpc-endpoints: $(head -c 600 "$TMP/ep.json")"
import json, sys
eps = json.load(open(sys.argv[1]))["VpcEndpoints"]
assert [e["VpcEndpointId"] for e in eps] == [sys.argv[2]], eps
e = eps[0]
assert e["VpcId"] == sys.argv[3] and e["ServiceName"] == "com.amazonaws.%s.s3" % sys.argv[4] and e["VpcEndpointType"] == "Gateway", e
assert e["State"] in ("available", "pending"), e["State"]
PY
log "  ✓ $EP: com.amazonaws.$REGION.s3 in $VPC"

# --- 3. IAM: the instance profile ------------------------------------------------------------------------------
log "iam get-instance-profile / list-instance-profiles / list-instance-profiles-for-role"
iamc get-instance-profile --instance-profile-name "$PROF" --output json > "$TMP/prof.json" 2>&1 || fail "get-instance-profile: $(head -c 400 "$TMP/prof.json")"
python3 - "$TMP/prof.json" "$PROF" "$(output ProfileArn)" "$ROLE" <<'PY' || fail "get-instance-profile: $(head -c 600 "$TMP/prof.json")"
import json, sys
p = json.load(open(sys.argv[1]))["InstanceProfile"]
assert p["InstanceProfileName"] == sys.argv[2] and p["Arn"] == sys.argv[3] and p["Path"] == "/structural/", p
assert p["InstanceProfileId"].startswith("AIPA") and p["CreateDate"], p
assert [r["RoleName"] for r in p["Roles"]] == [sys.argv[4]], p["Roles"]
PY
iamc list-instance-profiles --path-prefix /structural/ --query 'InstanceProfiles[].InstanceProfileName' --output text | grep -qw "$PROF" \
  || fail "list-instance-profiles --path-prefix /structural/ must list $PROF"
iamc list-instance-profiles-for-role --role-name "$ROLE" --query 'InstanceProfiles[].InstanceProfileName' --output text | grep -qw "$PROF" \
  || fail "list-instance-profiles-for-role --role-name $ROLE must list $PROF"
log "  ✓ $PROF ($(output ProfileArn)) carries $ROLE"

# --- 4. the negatives ------------------------------------------------------------------------------------------
log "negatives: unknown ids, and a principal with no grant"
expect_err() { # <code> <what> -- <command...>
  local code="$1" what="$2"; shift 3
  local err; err="$("$@" 2>&1 >/dev/null || true)"
  printf '%s' "$err" | grep -q "$code" || fail "$what: want $code, got: $err"
}
expect_err InvalidInternetGatewayID.NotFound "an unknown gateway" -- ec2 describe-internet-gateways --internet-gateway-ids igw-00000000000000000
expect_err InvalidRouteTableID.NotFound "an unknown route table" -- ec2 describe-route-tables --route-table-ids rtb-00000000000000000
expect_err InvalidNetworkAclID.NotFound "an unknown network ACL" -- ec2 describe-network-acls --network-acl-ids acl-00000000000000000
expect_err InvalidVpcEndpointId.NotFound "an unknown endpoint" -- ec2 describe-vpc-endpoints --vpc-endpoint-ids vpce-00000000000000000
expect_err NoSuchEntity "an unknown instance profile" -- iamc get-instance-profile --instance-profile-name "nope-$SFX"
expect_err UnauthorizedOperation "a principal with no grant (the stack's table)" -- as "$NAK" "$NSK" ec2 describe-route-tables --route-table-ids "$RT"
expect_err UnauthorizedOperation "a principal with no grant (gateways)" -- as "$NAK" "$NSK" ec2 describe-internet-gateways
expect_err AccessDenied "a principal with no grant (the stack's profile)" -- as "$NAK" "$NSK" iam get-instance-profile --instance-profile-name "$PROF"
expect_err AccessDenied "a principal with no grant (a profile that does not exist)" -- as "$NAK" "$NSK" iam get-instance-profile --instance-profile-name "nope-$SFX"
log "  ✓ NotFound in each API's words; no grant → refused, whether or not the id exists"

# --- 5. deleted with the stack -----------------------------------------------------------------------------------
log "delete-stack: the gateway, the table and the profile go with it"
cfn delete-stack --stack-name "$STACK" >/dev/null || fail "delete-stack"
for _ in $(seq 1 100); do
  case "$(stack_status "$STACK")" in ""|DELETE_COMPLETE) break;; *DELETE_FAILED) fail "delete-stack: DELETE_FAILED";; esac
  sleep 3
done
expect_err InvalidInternetGatewayID.NotFound "the deleted stack's gateway" -- ec2 describe-internet-gateways --internet-gateway-ids "$IGW"
expect_err InvalidRouteTableID.NotFound "the deleted stack's route table" -- ec2 describe-route-tables --route-table-ids "$RT"
expect_err NoSuchEntity "the deleted stack's instance profile" -- iamc get-instance-profile --instance-profile-name "$PROF"
log "  ✓ gone with the stack"

printf '✓ PASS — a stack'"'"'s internet gateway, route table, route, association, VPC endpoint and instance profile read back through EC2 and IAM by the ids their Refs gave the stack.\n'
