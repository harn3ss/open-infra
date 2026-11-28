#!/usr/bin/env bash
# Live probe: a default VPC's private subnet reaches the internet only at the destinations its route table
# sends to the VPC's NAT gateway.
#
# For ACCOUNT_ID, a member account whose kind: Account has spec.defaultVpc.natGateway true, a public subnet
# and a private subnet with natGatewayRoutes, as the management account's administrator acting in it
# (OrganizationAccountAccessRole), through the AWS CLI:
#   - EC2 lists the NAT gateway available in the public subnet, with its Elastic IP (DescribeNatGateways,
#     DescribeAddresses), and the private subnet's route table: the local route and the NAT gateway routes,
#     no 0.0.0.0/0;
#   - a Fargate service in the private subnet runs its task there;
#   - from inside the task (the operator's view): the platform's AWS endpoint and DNS answer, ROUTED_URL (an
#     http URL at one of the routed destinations, e.g. http://192.0.2.10/ for a route 192.0.2.10/32) answers,
#     and BLOCKED_URLS (default example.com, 8.8.8.8, 9.9.9.9) do not get through;
#   - a principal with no policy is refused DescribeNatGateways with EC2's access-denied error.
#
# Exit 0 pass, 1 fail, 42 inconclusive. Needs the aws CLI, kubectl (KUBECONFIG) and curl; reaches the shim at
# SHIM_ENDPOINT (e.g. a port-forward of svc/aws-shim 4566).
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
IMAGE="${ECS_IMAGE:-nginx:1.27-alpine}" # a public image with wget and nslookup (busybox)
REGION="${AWS_REGION:-us-east-1}"
BLOCKED_URLS="${BLOCKED_URLS:-http://example.com/ http://8.8.8.8/ http://9.9.9.9/}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for c in aws kubectl curl; do command -v "$c" >/dev/null || inconclusive "$c is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

ADMIN="natgw-admin-$SFX"; NOPOL="natgw-nopol-$SFX"; SERVICE="natgw-$SFX"; FAMILY="natgw-$SFX"
ACCT="${ACCOUNT_ID:?ACCOUNT_ID: a member account whose default VPC has a NAT gateway and a private subnet}"
ROUTED="${ROUTED_URL:?ROUTED_URL: an http URL at a destination the private subnet routes to its NAT gateway, which answers}"
CREATED_KEYS=(); CREATED_USERS=(); MADE_SERVICE=""
as() { local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$@"; }
cleanup() {
  if [ -n "$MADE_SERVICE" ]; then
    mem ecs delete-service --service "$SERVICE" --force >/dev/null 2>&1
    mem ecs deregister-task-definition --task-definition "$FAMILY:1" >/dev/null 2>&1
  fi
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1; done
  for k in "${CREATED_KEYS[@]:-}"; do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1; done
  rm -rf "$TMP"
}
trap cleanup EXIT

# mint_key <owner> [group]: a kind: User (in group, or in none) and an access key the shim authenticates;
# sets MK_AK MK_SK (never printed).
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
MAK=""; MSK=""; MTOK=""
for _ in $(seq 1 12); do
  read -r MAK MSK MTOK <<<"$(as "$AAK" "$ASK" sts assume-role --role-arn "arn:aws:iam::${ACCT}:role/OrganizationAccountAccessRole" \
    --role-session-name nat-gateway-probe --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' 2>"$TMP/ar")"
  [ -n "${MTOK:-}" ] && break
  sleep 5
done
[ -n "${MTOK:-}" ] || inconclusive "could not act in ${ACCT}: $(head -c 300 "$TMP/ar")"
mem() { AWS_ACCESS_KEY_ID="$MAK" AWS_SECRET_ACCESS_KEY="$MSK" AWS_SESSION_TOKEN="$MTOK" AWS_REGION="$REGION" \
  aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$@"; }

# --- 1. the NAT gateway, its Elastic IP, and the private subnet's route table, as EC2 reports them ----------
VPC="$(mem ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' 2>/dev/null)"
case "$VPC" in vpc-*) ;; *) inconclusive "${ACCT} has no default VPC (got ${VPC})" ;; esac
read -r NAT NSTATE NSUB ALLOC <<<"$(mem ec2 describe-nat-gateways --filter "Name=vpc-id,Values=${VPC}" \
  --query 'NatGateways[0].[NatGatewayId,State,SubnetId,NatGatewayAddresses[0].AllocationId]' 2>"$TMP/ng")"
case "$NAT" in nat-*) ;; *) inconclusive "${ACCT}'s default VPC has no NAT gateway (set spec.defaultVpc.natGateway): $(head -c 300 "$TMP/ng")" ;; esac
[ "$NSTATE" = available ] || fail "the NAT gateway ${NAT} is ${NSTATE}, not available"
PUB="$(mem ec2 describe-subnets --subnet-ids "$NSUB" --query 'Subnets[0].MapPublicIpOnLaunch' 2>/dev/null)"
[ -n "$PUB" ] || fail "the NAT gateway's subnet ${NSUB} is not listed"
EIP="$(mem ec2 describe-addresses --allocation-ids "$ALLOC" --query 'Addresses[0].PublicIp' 2>/dev/null)"
[ -n "$EIP" ] && [ "$EIP" != None ] || fail "the NAT gateway's Elastic IP ${ALLOC} is not listed with an address"
RTB="$(mem ec2 describe-route-tables --filters "Name=route.nat-gateway-id,Values=${NAT}" --query 'RouteTables[0].RouteTableId' 2>/dev/null)"
PRIV="$(mem ec2 describe-route-tables --route-table-ids "$RTB" --query 'RouteTables[0].Associations[0].SubnetId' 2>/dev/null)"
case "$PRIV" in subnet-*) ;; *) inconclusive "no subnet routes to ${NAT} (set spec.defaultVpc.privateSubnet.natGatewayRoutes)" ;; esac
routes="$(mem ec2 describe-route-tables --route-table-ids "$RTB" --query 'RouteTables[0].Routes[].[DestinationCidrBlock,NatGatewayId,GatewayId,State]' 2>/dev/null | tr '\t\n' ' ;')"
case "$routes" in *0.0.0.0/0*) fail "the private subnet's route table routes 0.0.0.0/0: ${routes}" ;; esac
case "$routes" in *"$NAT"*active*) ;; *) fail "no active route to ${NAT}: ${routes}" ;; esac
log "  ✓ ${NAT} available in ${NSUB} with ${ALLOC} (${EIP}); ${PRIV}'s route table ${RTB}: ${routes}"

# --- 2. a task in the private subnet ----------------------------------------------------------------------
mem ecs register-task-definition --family "$FAMILY" --requires-compatibilities FARGATE --network-mode awsvpc \
  --cpu 256 --memory 512 --container-definitions '[{"name":"web","image":"'"$IMAGE"'","essential":true,"portMappings":[{"containerPort":80}]}]' \
  >/dev/null 2>"$TMP/td" || fail "register-task-definition: $(head -c 300 "$TMP/td")"
mem ecs create-service --service-name "$SERVICE" --task-definition "$FAMILY" --desired-count 1 --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[${PRIV}],assignPublicIp=DISABLED}" >/dev/null 2>"$TMP/cs" \
  || fail "create-service in the private subnet: $(head -c 400 "$TMP/cs")"
MADE_SERVICE=1
st=""
for _ in $(seq 1 60); do
  st="$(mem ecs describe-services --services "$SERVICE" --query 'services[0].[runningCount,pendingCount]' 2>/dev/null | tr '\t' ' ')"
  [ "$st" = "1 0" ] && break
  sleep 5
done
[ "$st" = "1 0" ] || fail "the task never ran (running pending = ${st})"
task="$(mem ecs list-tasks --service-name "$SERVICE" --query 'taskArns[0]' 2>/dev/null)"
TIP="$(mem ecs describe-tasks --tasks "$task" --query "tasks[0].attachments[0].details[?name=='privateIPv4Address'].value | [0]" 2>/dev/null)"
PCIDR="$(mem ec2 describe-subnets --subnet-ids "$PRIV" --query 'Subnets[0].CidrBlock' 2>/dev/null)"
log "  ✓ its task runs in ${PRIV} (${PCIDR}) at ${TIP}"

# --- 3. from the task: the platform, the routed destination, and nothing else outside ----------------------
pod="$(kubectl get pods -A -l "app.kubernetes.io/name" -o jsonpath="{range .items[?(@.status.podIP==\"${TIP}\")]}{.metadata.namespace}/{.metadata.name}{end}" 2>/dev/null)"
[ -n "$pod" ] || inconclusive "the task's pod (${TIP}) is not readable (KUBECONFIG?)"
inpod() { kubectl -n "${pod%%/*}" exec "${pod##*/}" -c app -- "$@"; }
inpod wget -q -T 10 -O /dev/null "http://aws-shim.${SHIM_NS}.svc.cluster.local:4566/healthz" 2>/dev/null \
  || fail "the task cannot reach the platform's AWS endpoint"
inpod nslookup "aws-shim.${SHIM_NS}.svc.cluster.local" >/dev/null 2>&1 || fail "the task cannot resolve the platform's names"
ok=""
for _ in 1 2 3; do
  # An answer of any kind (even an HTTP error, or a redirect wget cannot follow) is the destination reached;
  # a connection that never opens is not.
  if inpod wget -q -T 10 -O /dev/null "$ROUTED" 2>"$TMP/w" || ! grep -qiE "can't connect|timed out|unreachable|no route" "$TMP/w"; then ok=1; break; fi
  sleep 5
done
[ -n "$ok" ] || fail "the task did not reach ${ROUTED}, a destination its route table sends to the NAT gateway: $(head -c 200 "$TMP/w")"
for target in $BLOCKED_URLS; do
  if inpod wget -q -T 8 -O /dev/null "$target" 2>/dev/null; then
    fail "the task reached ${target}, which its route table does not send to the NAT gateway"
  fi
done
log "  ✓ from the task: the AWS endpoint and its DNS answer; ${ROUTED} answers through ${NAT}; ${BLOCKED_URLS} do not"

# --- 4. a principal with no policy is refused ------------------------------------------------------------
if as "$NAK" "$NSK" ec2 describe-nat-gateways >/dev/null 2>"$TMP/deny"; then fail "describe-nat-gateways was allowed for a principal with no policy"; fi
grep -qE 'UnauthorizedOperation|AccessDenied' "$TMP/deny" || fail "describe-nat-gateways failed without EC2's access-denied error: $(head -c 300 "$TMP/deny")"
log "  ✓ a principal with no policy is refused DescribeNatGateways (UnauthorizedOperation)"

printf '\n✓ PASS: a private subnet reaches the internet through its NAT gateway at its routed destinations only, and the platform as before\n'
