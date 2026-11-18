#!/usr/bin/env bash
# Live probe: an account's default VPC without its internet gateway keeps its tasks inside the platform.
#
# For ACCOUNT_ID, a member account whose kind: Account has spec.defaultVpc.internetGateway false, as the
# management account's administrator acting in it (OrganizationAccountAccessRole), through the AWS CLI:
#   - EC2 lists no internet gateway attached to its default VPC, and its main route table has no 0.0.0.0/0;
#   - a Fargate service in its default subnet runs its task there;
#   - from inside the task (the operator's view): the platform's AWS endpoint and DNS answer, and a
#     connection to the internet (example.com, 1.1.1.1, 8.8.8.8) does not get through — the subnet's network
#     ACL drops whatever leaves for anywhere but the platform's own networks;
#   - with a Route 53 Resolver DNS Firewall rule group associated with the VPC (list-firewall-rule-group-
#     associations), the task resolves the platform's names and not example.com, nor through another resolver;
#   - a principal with no policy is refused DescribeInternetGateways with EC2's access-denied error.
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

ADMIN="isovpc-admin-$SFX"; NOPOL="isovpc-nopol-$SFX"; SERVICE="isovpc-$SFX"; FAMILY="isovpc-$SFX"
ACCT="${ACCOUNT_ID:?ACCOUNT_ID: a member account whose default VPC has no internet gateway}"
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
# Act in the member account as the management account does: its OrganizationAccountAccessRole.
MAK=""; MSK=""; MTOK=""
for _ in $(seq 1 12); do
  read -r MAK MSK MTOK <<<"$(as "$AAK" "$ASK" sts assume-role --role-arn "arn:aws:iam::${ACCT}:role/OrganizationAccountAccessRole" \
    --role-session-name isolated-vpc-probe --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' 2>"$TMP/ar")"
  [ -n "${MTOK:-}" ] && break
  sleep 5
done
[ -n "${MTOK:-}" ] || inconclusive "could not act in ${ACCT}: $(head -c 300 "$TMP/ar")"
mem() { AWS_ACCESS_KEY_ID="$MAK" AWS_SECRET_ACCESS_KEY="$MSK" AWS_SESSION_TOKEN="$MTOK" AWS_REGION="$REGION" \
  aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$@"; }

# --- 1. the default VPC has no internet gateway, as EC2 reports it ----------------------------------------
VPC="$(mem ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' 2>/dev/null)"
SUBNET="$(mem ec2 describe-subnets --filters Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' 2>/dev/null)"
SCIDR="$(mem ec2 describe-subnets --filters Name=default-for-az,Values=true --query 'Subnets[0].CidrBlock' 2>/dev/null)"
case "$VPC/$SUBNET" in vpc-*/subnet-*) ;; *) inconclusive "${ACCT} has no default VPC (got ${VPC} ${SUBNET})" ;; esac
igws="$(mem ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=${VPC}" --query 'length(InternetGateways)' 2>/dev/null)"
[ "$igws" = 0 ] || inconclusive "${ACCT}'s default VPC has an internet gateway: set its account's spec.defaultVpc.internetGateway false first"
routes="$(mem ec2 describe-route-tables --filters "Name=vpc-id,Values=${VPC}" --query 'RouteTables[0].Routes[].DestinationCidrBlock' 2>/dev/null)"
case "$routes" in *0.0.0.0/0*) fail "the default VPC lists no internet gateway but routes 0.0.0.0/0 (${routes})" ;; esac
log "  ✓ ${VPC} (default): no internet gateway, route table ${routes} only; default subnet ${SUBNET} (${SCIDR})"

# --- 2. a task in its default subnet ----------------------------------------------------------------------
mem ecs register-task-definition --family "$FAMILY" --requires-compatibilities FARGATE --network-mode awsvpc \
  --cpu 256 --memory 512 --container-definitions '[{"name":"web","image":"'"$IMAGE"'","essential":true,"portMappings":[{"containerPort":80}]}]' \
  >/dev/null 2>"$TMP/td" || fail "register-task-definition: $(head -c 300 "$TMP/td")"
mem ecs create-service --service-name "$SERVICE" --task-definition "$FAMILY" --desired-count 1 --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[${SUBNET}],assignPublicIp=ENABLED}" >/dev/null 2>"$TMP/cs" \
  || fail "create-service in the default subnet: $(head -c 400 "$TMP/cs")"
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
log "  ✓ its task runs in ${SUBNET} at ${TIP} (assignPublicIp ENABLED)"

# --- 3. from the task: the platform, and nothing outside it --------------------------------------------------
pod="$(kubectl get pods -A -l "app.kubernetes.io/name" -o jsonpath="{range .items[?(@.status.podIP==\"${TIP}\")]}{.metadata.namespace}/{.metadata.name}{end}" 2>/dev/null)"
[ -n "$pod" ] || inconclusive "the task's pod (${TIP}) is not readable (KUBECONFIG?)"
inpod() { kubectl -n "${pod%%/*}" exec "${pod##*/}" -c app -- "$@"; }
inpod wget -q -T 10 -O /dev/null "http://aws-shim.${SHIM_NS}.svc.cluster.local:4566/healthz" 2>/dev/null \
  || fail "the task cannot reach the platform's AWS endpoint"
inpod nslookup "aws-shim.${SHIM_NS}.svc.cluster.local" >/dev/null 2>&1 || fail "the task cannot resolve the platform's names"
for target in http://example.com/ http://1.1.1.1/ http://8.8.8.8/; do
  if inpod wget -q -T 8 -O /dev/null "$target" 2>/dev/null; then
    fail "the task reached ${target} from a default VPC with no internet gateway"
  fi
done
log "  ✓ from the task: the AWS endpoint and its DNS answer; example.com, 1.1.1.1 and 8.8.8.8 are unreachable"

# --- 3b. its DNS Firewall, when one is associated with the VPC (Route 53 Resolver) --------------------------
assoc="$(mem route53resolver list-firewall-rule-group-associations --vpc-id "$VPC" --query 'length(FirewallRuleGroupAssociations)' 2>/dev/null)"
if [ -n "$assoc" ] && [ "$assoc" != 0 ]; then
  inpod nslookup "aws-shim.${SHIM_NS}.svc.cluster.local" >/dev/null 2>&1 || fail "with its DNS Firewall the task cannot resolve the platform's names"
  if inpod nslookup example.com >/dev/null 2>&1; then fail "the task resolved example.com though its VPC's DNS Firewall blocks it"; fi
  if inpod nslookup example.com 10.43.0.10 >/dev/null 2>&1; then fail "the task went around its VPC's resolver to the cluster's"; fi
  log "  ✓ DNS Firewall (${assoc} association(s) on ${VPC}): the platform's names resolve; example.com does not, nor through another resolver"
fi

# --- 4. a principal with no policy is refused ------------------------------------------------------------
if as "$NAK" "$NSK" ec2 describe-internet-gateways >/dev/null 2>"$TMP/deny"; then fail "describe-internet-gateways was allowed for a principal with no policy"; fi
grep -qE 'UnauthorizedOperation|AccessDenied' "$TMP/deny" || fail "describe-internet-gateways failed without EC2's access-denied error: $(head -c 300 "$TMP/deny")"
log "  ✓ a principal with no policy is refused DescribeInternetGateways (UnauthorizedOperation)"

printf '\n✓ PASS: a default VPC without its internet gateway has no gateway or route out, and a task in it reaches the platform'"'"'s AWS endpoint and DNS but nothing outside the platform\n'
