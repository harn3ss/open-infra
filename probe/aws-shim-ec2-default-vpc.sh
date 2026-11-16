#!/usr/bin/env bash
# Live probe: every account has a default VPC, as AWS gives one, and an ECS task can run in it.
#
# As the management account's administrator, through the AWS CLI:
#   - EC2 reports the account's default VPC: DescribeVpcs is-default=true (172.31.0.0/16), DescribeSubnets
#     default-for-az=true (a /20 of it, public), its internet gateway and the main route table's 0.0.0.0/0 to
#     it; DescribeAccountAttributes names it (default-vpc), and CreateDefaultVpc answers
#     DefaultVpcAlreadyExists;
#   - a Fargate service whose NetworkConfiguration names the default subnet runs its task there: DescribeTasks
#     reports its network interface in that subnet, with an address of it;
#   - from inside the task (the operator's view): it resolves DNS, reaches the internet and the AWS endpoint;
#   - a principal with no policy is refused DescribeVpcs with EC2's access-denied error.
#
# Exit 0 pass, 1 fail, 42 inconclusive. Needs the aws CLI, kubectl (KUBECONFIG) and curl; reaches the shim at
# SHIM_ENDPOINT (e.g. a port-forward of svc/aws-shim 4566).
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
STACK_NS="${CFN_NAMESPACE:-open-infra-cfn}" # where the management account's stacks make their resources
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
IMAGE="${ECS_IMAGE:-nginx:1.27-alpine}" # a public image whose entrypoint writes to stdout at start
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for c in aws kubectl curl; do command -v "$c" >/dev/null || inconclusive "$c is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

ADMIN="defvpc-admin-$SFX"; NOPOL="defvpc-nopol-$SFX"; SERVICE="defvpc-$SFX"; FAMILY="defvpc-$SFX"
CREATED_KEYS=(); CREATED_USERS=(); MADE_SERVICE=""
as() { local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$@"; }
cleanup() {
  if [ -n "$MADE_SERVICE" ]; then
    as "$AAK" "$ASK" ecs delete-service --service "$SERVICE" --force >/dev/null 2>&1
    as "$AAK" "$ASK" ecs deregister-task-definition --task-definition "$FAMILY:1" >/dev/null 2>&1
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

log "seeding an administrator and a principal with no policy"
mint_key "$ADMIN" "admins"; AAK="$MK_AK"; ASK="$MK_SK"
mint_key "$NOPOL"; NAK="$MK_AK"; NSK="$MK_SK"
log "waiting 35s for the IAM policy world to load them"
sleep 35

# --- 1. the default VPC, as EC2 reports it --------------------------------------------------------------
read -r VPC VCIDR VDEF <<<"$(as "$AAK" "$ASK" ec2 describe-vpcs --filters Name=is-default,Values=true \
  --query 'Vpcs[0].[VpcId,CidrBlock,IsDefault]' 2>/dev/null)"
case "$VPC" in vpc-*) ;; *) fail "describe-vpcs is-default=true lists no default VPC (got '${VPC}')" ;; esac
[ "$VCIDR" = "172.31.0.0/16" ] && [ "$VDEF" = True ] || fail "the default VPC is ${VCIDR} isDefault=${VDEF}, want 172.31.0.0/16 True"
read -r SUBNET SCIDR SVPC SPUB SDEF <<<"$(as "$AAK" "$ASK" ec2 describe-subnets --filters Name=default-for-az,Values=true \
  --query 'Subnets[0].[SubnetId,CidrBlock,VpcId,MapPublicIpOnLaunch,DefaultForAz]' 2>/dev/null)"
case "$SCIDR" in 172.31.*.0/20) ;; *) fail "the default subnet is '${SCIDR}', want a /20 of 172.31.0.0/16" ;; esac
[ "$SVPC" = "$VPC" ] && [ "$SPUB" = True ] && [ "$SDEF" = True ] || fail "the default subnet ${SUBNET}: vpc ${SVPC} public ${SPUB} default ${SDEF}"
[ "$(as "$AAK" "$ASK" ec2 describe-account-attributes --attribute-names default-vpc --query 'AccountAttributes[0].AttributeValues[0].AttributeValue' 2>/dev/null)" = "$VPC" ] \
  || fail "describe-account-attributes default-vpc does not name ${VPC}"
if as "$AAK" "$ASK" ec2 create-default-vpc >/dev/null 2>"$TMP/cdv"; then fail "create-default-vpc made a second default VPC"; fi
grep -q DefaultVpcAlreadyExists "$TMP/cdv" || fail "create-default-vpc: $(head -c 300 "$TMP/cdv"), want DefaultVpcAlreadyExists"
IGW="$(as "$AAK" "$ASK" ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=${VPC}" --query 'InternetGateways[0].InternetGatewayId' 2>/dev/null)"
case "$IGW" in igw-*) ;; *) fail "the default VPC has no internet gateway (got '${IGW}')" ;; esac
[ "$(as "$AAK" "$ASK" ec2 describe-route-tables --filters "Name=vpc-id,Values=${VPC}" \
  --query "RouteTables[0].Routes[?DestinationCidrBlock=='0.0.0.0/0'].GatewayId | [0]" 2>/dev/null)" = "$IGW" ] \
  || fail "the default VPC's main route table does not send 0.0.0.0/0 to ${IGW}"
log "  ✓ default VPC ${VPC} (172.31.0.0/16, isDefault), default subnet ${SUBNET} (${SCIDR}, defaultForAz, public), gateway ${IGW} on its main route table, default-vpc named, create-default-vpc: DefaultVpcAlreadyExists"

# --- 2. a Fargate service in the default subnet --------------------------------------------------------
as "$AAK" "$ASK" ecs register-task-definition --family "$FAMILY" --requires-compatibilities FARGATE --network-mode awsvpc \
  --cpu 256 --memory 512 --container-definitions '[{"name":"web","image":"'"$IMAGE"'","essential":true,"portMappings":[{"containerPort":80}]}]' \
  >/dev/null 2>"$TMP/td" || fail "register-task-definition: $(head -c 300 "$TMP/td")"
as "$AAK" "$ASK" ecs create-service --service-name "$SERVICE" --task-definition "$FAMILY" --desired-count 1 --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[${SUBNET}],assignPublicIp=ENABLED}" >/dev/null 2>"$TMP/cs" \
  || fail "create-service in the default subnet: $(head -c 400 "$TMP/cs")"
MADE_SERVICE=1
st=""
for _ in $(seq 1 60); do
  st="$(as "$AAK" "$ASK" ecs describe-services --services "$SERVICE" --query 'services[0].[runningCount,pendingCount]' 2>/dev/null | tr '\t' ' ')"
  [ "$st" = "1 0" ] && break
  sleep 5
done
[ "$st" = "1 0" ] || fail "the service in the default subnet never ran its task (running pending = ${st})"
task="$(as "$AAK" "$ASK" ecs list-tasks --service-name "$SERVICE" --query 'taskArns[0]' 2>/dev/null)"
read -r TSUB TIP <<<"$(as "$AAK" "$ASK" ecs describe-tasks --tasks "$task" \
  --query "tasks[0].attachments[0].details[?name=='subnetId' || name=='privateIPv4Address'].value" 2>/dev/null | tr '\t' ' ')"
[ "$TSUB" = "$SUBNET" ] || fail "the task's network interface is in '${TSUB}', want the default subnet ${SUBNET}"
python3 -c 'import ipaddress,sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2]) else 1)' "$TIP" "$SCIDR" 2>/dev/null \
  || fail "the task's address ${TIP} is not in the default subnet ${SCIDR}"
log "  ✓ the service's task runs in the default subnet: interface in ${SUBNET}, address ${TIP}"

# --- 3. from the task: DNS, the internet, the AWS endpoint (the operator's view, inside its pod) ---------
pod="$(kubectl get pods -A -l "app.kubernetes.io/name" -o jsonpath="{range .items[?(@.status.podIP==\"${TIP}\")]}{.metadata.namespace}/{.metadata.name}{end}" 2>/dev/null)"
[ -n "$pod" ] || inconclusive "the task's pod (${TIP}) is not readable (KUBECONFIG?)"
inpod() { kubectl -n "${pod%%/*}" exec "${pod##*/}" -c app -- "$@"; }
inpod nslookup aws.amazon.com >/dev/null 2>&1 || fail "the task cannot resolve DNS from the default subnet"
inpod wget -q -T 15 -O /dev/null http://example.com/ 2>/dev/null || fail "the task cannot reach the internet from the default subnet"
inpod wget -q -T 10 -O /dev/null "http://aws-shim.${SHIM_NS}.svc.cluster.local:4566/healthz" 2>/dev/null || fail "the task cannot reach the AWS endpoint from the default subnet"
log "  ✓ from the default subnet the task resolves DNS, reaches the internet and the AWS endpoint"

# --- 4. a principal with no policy is refused ----------------------------------------------------------
if as "$NAK" "$NSK" ec2 describe-vpcs >/dev/null 2>"$TMP/deny"; then fail "describe-vpcs was allowed for a principal with no policy"; fi
grep -qE 'UnauthorizedOperation|AccessDenied' "$TMP/deny" || fail "describe-vpcs failed without EC2's access-denied error: $(head -c 300 "$TMP/deny")"
log "  ✓ a principal with no policy is refused DescribeVpcs (UnauthorizedOperation)"

printf '\n✓ PASS: the account has its default VPC as AWS gives one: 172.31.0.0/16, its default subnet, gateway and route, named by DescribeAccountAttributes; a Fargate service naming the default subnet runs there and reaches DNS, the internet and the AWS endpoint; a principal with no policy is refused\n'
