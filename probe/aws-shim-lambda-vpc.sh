#!/usr/bin/env bash
# Probe: a Lambda function in a VPC, egress-isolated the AWS way — Lambda's VpcConfig, a security group's
# outbound allow-list, a Route 53 Resolver DNS Firewall walled garden with query logging, and VPC Flow Logs of
# what is refused — through the aws-shim with the real AWS CLI, on a managed runtime and on an unsupported
# runtime image. See docs/lambda-vpc.md.
#
# Sets up (removed on exit): a VPC with two subnets and two security groups — "fn", whose only outbound rule
# allows the "backend" group on 8080, and "backend", on a small HTTP application (the allow-listed in-VPC
# destination). A VPC and its subnets and groups are what CloudFormation makes from AWS::EC2::VPC / Subnet /
# SecurityGroup; written here as the account's network objects directly, as a migration tool writes them,
# because an ECS service's SecurityGroups do not map yet.
#
# Asserts:
#   1. create-function --vpc-config (python3.12) answers the VpcConfig with its VpcId; get-function-
#      configuration answers it; a function on an unsupported runtime image (runtimeImage) is put in the same
#      VPC configuration;
#   2. the VPC's DNS Firewall (domain lists, a rule group ALLOW *.cluster.local then BLOCK * NXDOMAIN, its
#      association), its query logging (to a log group) and a REJECT flow log (to another) are created;
#   3. on BOTH functions: HTTP and HTTPS to an outside address fail; a lookup of an outside name fails
#      (NXDOMAIN); a DNS query sent straight to the cluster's own resolver gets no answer; the allow-listed
#      backend answers; a Service the security group does not list is unreachable; a cluster name resolves;
#   4. the query log holds the outside name, BLOCK, by the firewall rule group, from a function's address —
#      the resolver's own record that it answered without resolving; the flow log holds REJECT records of the
#      outside address on ports 80 and 443 and of the unlisted Service, on the network interfaces
#      describe-network-interfaces names for the two functions;
#   5. DENIAL: a user allowed only to read Lambda is refused route53resolver:ListFirewallRuleGroups
#      (AccessDeniedException) and ec2:CreateFlowLogs (UnauthorizedOperation); create-function with a VPC
#      configuration and an execution role that may not manage network interfaces is refused, as Lambda
#      refuses it.
# On a pass it writes an attestation (ATTEST_OUT, default ./lambda-vpc-attestation.json) in the shape
# open-transform's comparison reads: checked_at, covers (the probe's two functions), outbound_denied,
# dns_contained, denials_logged, evidence.
#
# ATTEST_FUNCTIONS="<function> ...": attest functions you already run instead of the probe's own. They must
# share one VPC configuration (get-function-configuration). Nothing of yours is changed or invoked: the probe
# reads that VPC's DNS Firewall (a rule group that BLOCKs "*"), its query logging and its REJECT flow log
# through the AWS APIs, puts a probe function in the identical VPC configuration, runs the posture test (3.)
# and reads the records (4.) from those log groups, then the denials (5.). covers is the attested functions.
# ALLOWED_URL (optional) is a destination the functions' security groups allow, asserted reachable. Run it
# with credentials of the functions' account — a user's key, or a role session (AWS_SESSION_TOKEN), allowed to
# create a role, a function and IAM's PassRole on it, as an account administrator is. (KEEP=1 leaves a run's
# own VPC and functions in place.)
#
# Needs: aws (v2), kubectl (a throwaway admin and the network objects, removed on exit), python3; a deployed
# shim with the Lambda, IAM, STS, Route 53 Resolver, EC2 and CloudWatch Logs front doors. Exit 0 = pass,
# 1 = a real failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-lambda-vpc.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
NET_NS="${NET_NS:-open-infra-cfn}" # the management account's network (the stack namespace)
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
OUTSIDE_IP="${OUTSIDE_IP:-1.1.1.1}"         # an address outside the platform
OUTSIDE_NAME="${OUTSIDE_NAME:-example.com}" # a name outside the platform
CLUSTER_RESOLVER="${CLUSTER_RESOLVER:-10.43.0.10}"
UNLISTED="${UNLISTED:-loki.monitoring.svc.cluster.local:3100}" # a Service the security group does not list
ATTEST_OUT="${ATTEST_OUT:-./lambda-vpc-attestation.json}"
export AWS_REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
VPC="lvpc-$SFX"; SUB_A="lvpc-a-$SFX"; SUB_B="lvpc-b-$SFX"; SG_FN="lvpc-fn-$SFX"; SG_BACK="lvpc-back-$SFX"
BACKEND="lvpc-backend-$SFX"; FN="lvpc-py-$SFX"; LEGACY="lvpc-legacy-$SFX"; NOENI="lvpc-noeni-$SFX"
EXEC="lvpc-exec-$SFX"; WEAK="lvpc-weak-$SFX"; FLOWROLE="lvpc-flow-$SFX"; READER="lvpc-reader-$SFX"
QLOG="/probe/lambda-vpc/dns-$SFX"; FLOG="/probe/lambda-vpc/flow-$SFX"

log()  { printf '▸ %s\n' "$*"; }
ok()   { printf '▸   ✓ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for t in aws kubectl python3; do command -v "$t" >/dev/null || inconclusive "$t is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
W="$(mktemp -d)"
A=(aws --endpoint-url "$ENDPOINT" --no-cli-pager)
R53=(aws --endpoint-url "$ENDPOINT" --no-cli-pager route53resolver)

CREATED_USERS=(); CREATED_KEYS=(); ROLES_MADE=(); FL_ID=""; FLID=""; ASSOC_ID=""; QASSOC_ID=""; RULES=(); GROUP_ID=""; LISTS=(); QCFG_ID=""
OWN_NET="" # set once the probe has made its own network; in attest mode it stays empty and nothing of yours is touched
cleanup() {
  set +e
  if [ -n "${KEEP:-}" ] && [ -n "$OWN_NET" ]; then # KEEP=1: leave the VPC and its functions (to attest them)
    printf '▸ KEEP: left VPC %s and functions %s %s in place\n' "$VPC" "$FN" "$LEGACY"
    OWN_NET=""; FN_KEEP=1
  fi
  [ -n "${ADMIN_AK:-}" ] && export AWS_ACCESS_KEY_ID="$ADMIN_AK" AWS_SECRET_ACCESS_KEY="$ADMIN_SK" AWS_SESSION_TOKEN="${ADMIN_ST:-}"
  if [ -n "$OWN_NET" ]; then
  [ -n "$FL_ID" ] && "${A[@]}" ec2 delete-flow-logs --flow-log-ids "$FL_ID" >/dev/null 2>&1
  [ -n "$QASSOC_ID" ] && "${R53[@]}" disassociate-resolver-query-log-config --resolver-query-log-config-id "$QCFG_ID" --resource-id "$VPC" >/dev/null 2>&1
  [ -n "$QCFG_ID" ] && "${R53[@]}" delete-resolver-query-log-config --resolver-query-log-config-id "$QCFG_ID" >/dev/null 2>&1
  [ -n "$ASSOC_ID" ] && "${R53[@]}" disassociate-firewall-rule-group --firewall-rule-group-association-id "$ASSOC_ID" >/dev/null 2>&1
  for rl in "${RULES[@]:-}"; do [ -n "$rl" ] && "${R53[@]}" delete-firewall-rule --firewall-rule-group-id "$GROUP_ID" --firewall-domain-list-id "$rl" >/dev/null 2>&1; done
  [ -n "$GROUP_ID" ] && "${R53[@]}" delete-firewall-rule-group --firewall-rule-group-id "$GROUP_ID" >/dev/null 2>&1
  for l in "${LISTS[@]:-}"; do [ -n "$l" ] && "${R53[@]}" delete-firewall-domain-list --firewall-domain-list-id "$l" >/dev/null 2>&1; done
  for g in "$QLOG" "$FLOG"; do "${A[@]}" logs delete-log-group --log-group-name "$g" >/dev/null 2>&1; done
  kubectl -n "$NET_NS" delete function.openinfra.dev "$LEGACY" --ignore-not-found --wait=false >/dev/null 2>&1
  kubectl -n "$NET_NS" delete configmap "$LEGACY-code" --ignore-not-found >/dev/null 2>&1
  kubectl -n "$NET_NS" delete application.openinfra.dev "$BACKEND" --ignore-not-found --wait=false >/dev/null 2>&1
  kubectl -n "$NET_NS" delete securitygroup.openinfra.dev "$SG_FN" "$SG_BACK" --ignore-not-found --wait=false >/dev/null 2>&1
  kubectl -n "$NET_NS" delete subnet.openinfra.dev "$SUB_A" "$SUB_B" --ignore-not-found --wait=false >/dev/null 2>&1
  kubectl -n "$NET_NS" delete vpc.openinfra.dev "$VPC" --ignore-not-found --wait=false >/dev/null 2>&1
  fi
  [ -z "${FN_KEEP:-}" ] && "${A[@]}" lambda delete-function --function-name "$FN" >/dev/null 2>&1 # the probe's own
  "${A[@]}" lambda delete-function --function-name "$NOENI" >/dev/null 2>&1
  if [ -n "${READER_USER:-}" ]; then
    [ -n "${READER_KEY:-}" ] && "${A[@]}" iam delete-access-key --user-name "$READER" --access-key-id "$READER_KEY" >/dev/null 2>&1
    "${A[@]}" iam delete-user-policy --user-name "$READER" --policy-name p >/dev/null 2>&1
    "${A[@]}" iam delete-user --user-name "$READER" >/dev/null 2>&1
  fi
  for r in "${ROLES_MADE[@]:-}"; do
    [ -z "$r" ] && continue
    [ -n "${FN_KEEP:-}" ] && [ "$r" != "$WEAK" ] && continue # kept: its functions and flow log use them
    "${A[@]}" iam delete-role-policy --role-name "$r" --policy-name p >/dev/null 2>&1
    "${A[@]}" iam delete-role --role-name "$r" >/dev/null 2>&1
  done
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
  mint_key "lvpc-admin-$SFX" admins
  export AWS_ACCESS_KEY_ID="$MK_AK" AWS_SECRET_ACCESS_KEY="$MK_SK"
  log "minted a throwaway openinfra:admins caller (lvpc-admin-$SFX)"
fi
ADMIN_AK="$AWS_ACCESS_KEY_ID"; ADMIN_SK="$AWS_SECRET_ACCESS_KEY"; ADMIN_ST="${AWS_SESSION_TOKEN:-}" # a role session's token, kept
for i in $(seq 1 24); do # a freshly minted caller's authority takes a minute or so to reach every check
  ACCOUNT="$("${A[@]}" sts get-caller-identity --query Account --output text 2>/dev/null)" && break
  [ "$i" = 24 ] && inconclusive "sts get-caller-identity never succeeded"
  sleep 5
done

# role <name> <trust-principal-json> [policy-json]: an IAM role, removed on exit.
role() {
  "${A[@]}" iam create-role --role-name "$1" \
    --assume-role-policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":$2,\"Action\":\"sts:AssumeRole\"}]}" \
    >/dev/null || inconclusive "iam create-role $1 failed"
  ROLES_MADE+=("$1")
  if [ -n "${3:-}" ]; then
    "${A[@]}" iam put-role-policy --role-name "$1" --policy-name p --policy-document "$3" >/dev/null || inconclusive "iam put-role-policy $1 failed"
  fi
}
ENI_POLICY='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:CreateNetworkInterface","ec2:DescribeNetworkInterfaces","ec2:DeleteNetworkInterface","logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"*"}]}'
role "$EXEC" '{"Service":"lambda.amazonaws.com"}' "$ENI_POLICY"
role "$WEAK" '{"Service":"lambda.amazonaws.com"}' '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:CreateLogStream","logs:PutLogEvents"],"Resource":"*"}]}'
role "$FLOWROLE" '{"Service":"vpc-flow-logs.amazonaws.com"}' \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents","logs:DescribeLogGroups","logs:DescribeLogStreams"],"Resource":"*"}]}'
EXEC_ARN="arn:aws:iam::$ACCOUNT:role/$EXEC"; WEAK_ARN="arn:aws:iam::$ACCOUNT:role/$WEAK"; FLOWROLE_ARN="arn:aws:iam::$ACCOUNT:role/$FLOWROLE"

ATTEST="${ATTEST_FUNCTIONS:-}"
if [ -n "$ATTEST" ]; then
  log "0. the attested functions' VPC configuration"
  for f in $ATTEST; do
    "${A[@]}" lambda get-function-configuration --function-name "$f" --query VpcConfig --output json >"$W/vc-$f.json" 2>"$W/vc.err" \
      || fail "get-function-configuration $f: $(tail -c 300 "$W/vc.err")"
  done
  VPCCFG="$(python3 - "$W" $ATTEST <<'PY'
import json, sys
w, fns = sys.argv[1], sys.argv[2:]
cfgs = {}
for f in fns:
    c = json.load(open("%s/vc-%s.json" % (w, f))) or {}
    if not c.get("SubnetIds"):
        sys.exit("%s is not in a VPC" % f)
    cfgs[f] = (c["VpcId"], tuple(sorted(c["SubnetIds"])), tuple(sorted(c["SecurityGroupIds"])))
if len(set(cfgs.values())) != 1:
    sys.exit("the functions do not share one VPC configuration: attest one configuration at a time")
vpc, subnets, groups = next(iter(cfgs.values()))
print("%s %s %s" % (vpc, ",".join(subnets), ",".join(groups)))
PY
)" || inconclusive "$VPCCFG"
  read -r VPC SUBNETS SGS <<<"$VPCCFG"
  VPCCFG="SubnetIds=$SUBNETS,SecurityGroupIds=$SGS"
  ok "$ATTEST share $VPC, subnets $SUBNETS, security groups $SGS"
else
log "0. the VPC: two subnets, a backend group on a small HTTP application, and the function's group (outbound: the backend on 8080 only)"
cat >"$W/net.yaml" <<EOF
apiVersion: openinfra.dev/v1
kind: Vpc
metadata: { name: $VPC, namespace: $NET_NS }
spec: {}
---
apiVersion: openinfra.dev/v1
kind: Subnet
metadata: { name: $SUB_A, namespace: $NET_NS }
spec: { vpc: $VPC, cidr: 10.231.1.0/24 }
---
apiVersion: openinfra.dev/v1
kind: Subnet
metadata: { name: $SUB_B, namespace: $NET_NS }
spec: { vpc: $VPC, cidr: 10.231.2.0/24 }
---
apiVersion: openinfra.dev/v1
kind: SecurityGroup
metadata: { name: $SG_BACK, namespace: $NET_NS }
spec: { vpc: $VPC }
---
apiVersion: openinfra.dev/v1
kind: SecurityGroup
metadata: { name: $SG_FN, namespace: $NET_NS }
spec:
  vpc: $VPC
  ingress: []
  egress:
    - { protocol: TCP, ports: [8080], to: [ { securityGroup: $SG_BACK } ], description: "the backend only" }
---
apiVersion: openinfra.dev/v1
kind: Application
metadata: { name: $BACKEND, namespace: $NET_NS }
spec: { image: ghcr.io/knative/helloworld-go:latest, port: 8080, securityGroups: [ $SG_BACK ] }
EOF
OWN_NET=1
kubectl apply -f "$W/net.yaml" >/dev/null || inconclusive "could not write the VPC's network objects"
for i in $(seq 1 36); do
  n="$("${A[@]}" ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC" --query 'length(Subnets)' --output text 2>/dev/null || echo 0)"
  [ "$n" = 2 ] && break
  [ "$i" = 36 ] && inconclusive "the VPC's subnets never showed in describe-subnets"
  sleep 5
done
ok "describe-subnets shows $SUB_A and $SUB_B in $VPC"
VPCCFG="SubnetIds=$SUB_A,$SUB_B,SecurityGroupIds=$SG_FN"
fi

# The handler: what the function can reach, from inside it. Python 3.6+ stdlib only.
cat >"$W/index.py" <<'PY'
import socket, struct, urllib.error, urllib.request
def tcp(host, port, t=4):
    try:
        socket.create_connection((host, int(port)), timeout=t).close()
        return "connected"
    except Exception as e:
        return "blocked: " + type(e).__name__
def http(url, t=5):
    try:
        with urllib.request.urlopen(url, timeout=t) as r:
            return "answered %d" % r.status
    except urllib.error.HTTPError as e:
        return "answered %d" % e.code
    except Exception as e:
        return "blocked: " + type(e).__name__
def resolve(name):
    try:
        return "resolved " + socket.gethostbyname(name)
    except Exception as e:
        return "failed: " + str(e)
def raw_dns(server, name, t=3):
    q = struct.pack(">HHHHHH", 0x5151, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(t)
    try:
        s.sendto(q, (server, 53))
        s.recvfrom(512)
        return "answered"
    except Exception as e:
        return "blocked: " + type(e).__name__
    finally:
        s.close()
def handler(event, context):
    h, p = event["unlisted"].rsplit(":", 1)
    return {
        "http_outside": http("http://%s/" % event["outside_ip"]),
        "https_outside": tcp(event["outside_ip"], 443),
        "dns_outside": resolve(event["outside_name"]),
        "dns_bypass": raw_dns(event["cluster_resolver"], event["outside_name"]),
        "allowed": http(event["allowed_url"]),
        "unlisted": tcp(h, p),
        "dns_cluster": resolve(event["cluster_name"]),
    }
PY
(cd "$W" && python3 -c "import zipfile;z=zipfile.ZipFile('fn.zip','w');z.write('index.py');z.close()")

log "1. create-function --vpc-config, and an unsupported runtime image in the same VPC configuration"
for i in $(seq 1 12); do # a new role's trust and policy reach the shim within a few seconds
  "${A[@]}" lambda create-function --function-name "$FN" --runtime python3.12 --handler index.handler --role "$EXEC_ARN" \
    --zip-file "fileb://$W/fn.zip" --timeout 60 --vpc-config "$VPCCFG" >"$W/create.json" 2>"$W/create.err" && break
  [ "$i" = 12 ] && fail "create-function --vpc-config failed: $(tail -c 500 "$W/create.err")"
  sleep 10
done
python3 - "$W/create.json" "$VPC" <<'PY' || fail "create-function did not answer the VPC configuration: $(cat "$W/create.json")"
import json, sys
c = json.load(open(sys.argv[1]))["VpcConfig"]
assert c["VpcId"] == sys.argv[2] and c["SubnetIds"] and c["SecurityGroupIds"], c
PY
[ "$("${A[@]}" lambda get-function-configuration --function-name "$FN" --query VpcConfig.VpcId --output text)" = "$VPC" ] \
  || fail "get-function-configuration does not answer the VpcId"
ok "$FN (python3.12) is in $VPC: create-function and get-function-configuration answer its VpcConfig"
FUNCS="$FN"
if [ -z "$ATTEST" ]; then
FUNCS="$FN $LEGACY"
kubectl -n "$NET_NS" create configmap "$LEGACY-code" --from-file=index.py="$W/index.py" >/dev/null
cat <<EOF | kubectl apply -f - >/dev/null || fail "could not write the unsupported-runtime function"
apiVersion: openinfra.dev/v1
kind: Function
metadata: { name: $LEGACY, namespace: $NET_NS }
spec:
  timeout: 60
  code:
    runtimeImage: ghcr.io/harn3ss/open-infra-lambda-python39:latest
    unsupportedRuntime: true
    handler: index.handler
    source: { configMap: $LEGACY-code }
  vpcConfig: { subnetIds: [ $SUB_A, $SUB_B ], securityGroupIds: [ $SG_FN ], vpcId: $VPC }
EOF
ok "$LEGACY (an unsupported runtime image) is in the same VPC configuration"
fi

if [ -n "$ATTEST" ]; then
  log "2. the VPC's DNS Firewall (a rule group that BLOCKs *), query logging and a REJECT flow log"
  "${R53[@]}" list-firewall-rule-group-associations --vpc-id "$VPC" --output json >"$W/assoc.json" || fail "list-firewall-rule-group-associations"
  for g in $(python3 -c "import json;[print(a['FirewallRuleGroupId']) for a in sorted(json.load(open('$W/assoc.json'))['FirewallRuleGroupAssociations'],key=lambda a:a['Priority'])]"); do
    "${R53[@]}" list-firewall-rules --firewall-rule-group-id "$g" --output json >"$W/rules-$g.json" || fail "list-firewall-rules $g"
    for l in $(python3 -c "import json;[print(r['FirewallDomainListId']) for r in json.load(open('$W/rules-$g.json'))['FirewallRules'] if r['Action']=='BLOCK']"); do
      "${R53[@]}" list-firewall-domains --firewall-domain-list-id "$l" --output json >"$W/dom-$l.json" || fail "list-firewall-domains $l"
      if python3 -c "import json,sys;sys.exit(0 if '*' in json.load(open('$W/dom-$l.json'))['Domains'] else 1)"; then GROUP_ID="$g"; ALL_LIST="$l"; break 2; fi
    done
  done
  [ -n "$GROUP_ID" ] || fail "no rule group associated with $VPC BLOCKs every name (*): its DNS is not contained"
  "${R53[@]}" list-resolver-query-log-config-associations --filters "Name=ResourceId,Values=$VPC" --query 'ResolverQueryLogConfigAssociations[0].ResolverQueryLogConfigId' --output text >"$W/qc" \
    || fail "list-resolver-query-log-config-associations"
  [ "$(cat "$W/qc")" != None ] && [ -s "$W/qc" ] || fail "$VPC has no query logging"
  DEST="$("${R53[@]}" get-resolver-query-log-config --resolver-query-log-config-id "$(cat "$W/qc")" --query ResolverQueryLogConfig.DestinationArn --output text)"
  QLOG="${DEST#*:log-group:}"; QLOG="${QLOG%:\*}"
  "${A[@]}" ec2 describe-flow-logs --filter "Name=resource-id,Values=$VPC" --output json >"$W/fl.json" || fail "describe-flow-logs"
  # Its last status may be FAILED with nothing delivered since (DeliverLogsStatus is the last attempt's): the
  # probe's own refusals reaching it (4.), then SUCCESS, are the proof that it delivers.
  read -r FLOG FLID <<<"$(python3 -c "import json;f=sorted([x for x in json.load(open('$W/fl.json'))['FlowLogs'] if x['TrafficType']=='REJECT' and x['LogDestinationType']=='cloud-watch-logs'],key=lambda x:x.get('DeliverLogsStatus')!='SUCCESS');print(f[0]['LogGroupName'],f[0]['FlowLogId'] if f else '')")"
  [ -n "$FLOG" ] || fail "$VPC has no REJECT flow log to CloudWatch Logs"
  ok "$VPC: rule group $GROUP_ID BLOCKs * ($ALL_LIST); query logging to $QLOG; REJECT flow log to $FLOG"
else
log "2. the VPC's DNS Firewall (walled garden), query logging and a REJECT flow log"
"${A[@]}" logs create-log-group --log-group-name "$QLOG" >/dev/null || fail "create-log-group $QLOG"
"${A[@]}" logs create-log-group --log-group-name "$FLOG" >/dev/null || fail "create-log-group $FLOG"
ALLOW_LIST="$("${R53[@]}" create-firewall-domain-list --creator-request-id "a-$SFX" --name "lvpc-cluster-$SFX" --query FirewallDomainList.Id --output text)" \
  || fail "create-firewall-domain-list (cluster names)"
LISTS+=("$ALLOW_LIST")
"${R53[@]}" update-firewall-domains --firewall-domain-list-id "$ALLOW_LIST" --operation ADD --domains '*.cluster.local' >/dev/null || fail "update-firewall-domains (cluster names)"
ALL_LIST="$("${R53[@]}" create-firewall-domain-list --creator-request-id "b-$SFX" --name "lvpc-all-$SFX" --query FirewallDomainList.Id --output text)" \
  || fail "create-firewall-domain-list (everything)"
LISTS+=("$ALL_LIST")
"${R53[@]}" update-firewall-domains --firewall-domain-list-id "$ALL_LIST" --operation ADD --domains '*' >/dev/null || fail "update-firewall-domains (*)"
GROUP_ID="$("${R53[@]}" create-firewall-rule-group --creator-request-id "g-$SFX" --name "lvpc-walled-$SFX" --query FirewallRuleGroup.Id --output text)" \
  || fail "create-firewall-rule-group"
"${R53[@]}" create-firewall-rule --creator-request-id "r1-$SFX" --firewall-rule-group-id "$GROUP_ID" --firewall-domain-list-id "$ALLOW_LIST" \
  --priority 100 --action ALLOW --name allow-cluster >/dev/null || fail "create-firewall-rule ALLOW"
RULES+=("$ALLOW_LIST")
"${R53[@]}" create-firewall-rule --creator-request-id "r2-$SFX" --firewall-rule-group-id "$GROUP_ID" --firewall-domain-list-id "$ALL_LIST" \
  --priority 200 --action BLOCK --block-response NXDOMAIN --name block-everything-else >/dev/null || fail "create-firewall-rule BLOCK"
RULES+=("$ALL_LIST")
ASSOC_ID="$("${R53[@]}" associate-firewall-rule-group --creator-request-id "s-$SFX" --firewall-rule-group-id "$GROUP_ID" --vpc-id "$VPC" \
  --priority 101 --name "lvpc-$SFX" --query FirewallRuleGroupAssociation.Id --output text)" || fail "associate-firewall-rule-group"
QCFG_ID="$("${R53[@]}" create-resolver-query-log-config --creator-request-id "q-$SFX" --name "lvpc-$SFX" \
  --destination-arn "arn:aws:logs:$AWS_REGION:$ACCOUNT:log-group:$QLOG" --query ResolverQueryLogConfig.Id --output text)" \
  || fail "create-resolver-query-log-config"
QASSOC_ID="$("${R53[@]}" associate-resolver-query-log-config --resolver-query-log-config-id "$QCFG_ID" --resource-id "$VPC" \
  --query ResolverQueryLogConfigAssociation.Id --output text)" || fail "associate-resolver-query-log-config"
FL_ID="$("${A[@]}" ec2 create-flow-logs --resource-type VPC --resource-ids "$VPC" --traffic-type REJECT --log-destination-type cloud-watch-logs \
  --log-group-name "$FLOG" --deliver-logs-permission-arn "$FLOWROLE_ARN" --max-aggregation-interval 60 --query 'FlowLogIds[0]' --output text)" \
  || fail "create-flow-logs"
[ -n "$FL_ID" ] && [ "$FL_ID" != None ] || fail "create-flow-logs answered no flow log id"
ok "rule group $GROUP_ID (ALLOW *.cluster.local, then BLOCK * NXDOMAIN) on $VPC; query logging to $QLOG; flow log $FL_ID (REJECT) to $FLOG"
fi

log "3. what each function can reach"
T0=$(( $(date +%s) * 1000 - 60000 )) # the records of what follows (a minute's allowance for clocks)
if [ -n "$ATTEST" ]; then ALLOWED="${ALLOWED_URL:-}"; CNAME="kubernetes.default.svc.cluster.local"; else ALLOWED="http://$BACKEND.$NET_NS.svc.cluster.local/"; CNAME="$BACKEND.$NET_NS.svc.cluster.local"; fi
EVENT="{\"outside_ip\":\"$OUTSIDE_IP\",\"outside_name\":\"$OUTSIDE_NAME\",\"cluster_resolver\":\"$CLUSTER_RESOLVER\",\"unlisted\":\"$UNLISTED\",\"allowed_url\":\"$ALLOWED\",\"cluster_name\":\"$CNAME\"}"
reach() { # reach <function>: invoke until it answers (cold start, rollout); the answer in $W/<function>.json
  for _ in $(seq 1 40); do
    if "${A[@]}" --cli-read-timeout 200 lambda invoke --function-name "$1" --cli-binary-format raw-in-base64-out --payload "$EVENT" \
      "$W/$1.json" >"$W/$1.meta" 2>"$W/$1.err" && python3 -c "import json,sys;r=json.load(open('$W/$1.json'));sys.exit(0 if 'allowed' in r and (r['allowed'].startswith('answered') or not '$ALLOWED') else 1)" 2>/dev/null; then
      return 0
    fi
    sleep 6
  done
  return 1
}
for f in $FUNCS; do
  reach "$f" || fail "$f never answered with the backend reachable: $(cat "$W/$f.json" 2>/dev/null) $(tail -c 300 "$W/$f.err")"
  python3 - "$W/$f.json" "$f" "$ALLOWED" <<'PY' || fail "$f's network is not the isolated posture: $(cat "$W/$f.json")"
import json, sys
r = json.load(open(sys.argv[1]))
if not sys.argv[3]:
    r["allowed"] = "answered 200 (not asserted: no ALLOWED_URL)"
assert r["http_outside"].startswith("blocked"), ("HTTP to an outside address", r)
assert r["https_outside"].startswith("blocked"), ("HTTPS to an outside address", r)
assert r["dns_outside"].startswith("failed"), ("a lookup of an outside name", r)
assert r["dns_bypass"].startswith("blocked"), ("DNS straight to the cluster's resolver", r)
assert r["allowed"].startswith("answered 200"), ("the allow-listed backend", r)
assert r["unlisted"].startswith("blocked"), ("a Service the group does not list", r)
assert r["dns_cluster"].startswith("resolved"), ("a cluster name", r)
print("    %s: %s" % (sys.argv[2], json.dumps(r, sort_keys=True)))
PY
  ok "$f: outside HTTP/HTTPS blocked, outside name NXDOMAIN, the cluster resolver unreachable, the allowed destination answers, the unlisted Service blocked"
done

log "4. the resolver's query log and the VPC's flow log record it"
ENIS="$("${A[@]}" ec2 describe-network-interfaces --filters "Name=vpc-id,Values=$VPC" --output json)" || fail "describe-network-interfaces"
echo "$ENIS" >"$W/enis.json"
python3 - "$W/enis.json" $FUNCS <<'PY' || fail "describe-network-interfaces does not name the functions' interfaces: $(head -c 600 "$W/enis.json")"
import json, sys
n = json.load(open(sys.argv[1]))["NetworkInterfaces"]
for fn in sys.argv[2:]:
    mine = [i for i in n if i.get("Description", "").startswith("AWS Lambda VPC ENI-" + fn) and i.get("InterfaceType") == "lambda"]
    assert mine, fn
PY
ok "describe-network-interfaces lists each function's Lambda interfaces in $VPC"
for i in $(seq 1 30); do
  "${A[@]}" logs filter-log-events --log-group-name "$QLOG" --start-time "$T0" --filter-pattern "$OUTSIDE_NAME" --output json >"$W/qlog.json" 2>/dev/null || true
  python3 - "$W/qlog.json" "$OUTSIDE_NAME" "$GROUP_ID" "$ALL_LIST" <<'PY' && break
import json, sys
ev = json.load(open(sys.argv[1])).get("events", [])
recs = [json.loads(e["message"]) for e in ev]
hit = [r for r in recs if r.get("query_name", "").rstrip(".") == sys.argv[2] and r.get("firewall_rule_action") == "BLOCK"
       and r.get("firewall_rule_group_id") == sys.argv[3] and r.get("firewall_domain_list_id") == sys.argv[4]]
sys.exit(0 if hit else 1)
PY
  [ "$i" = 30 ] && fail "the query log never recorded $OUTSIDE_NAME blocked: $(head -c 800 "$W/qlog.json")"
  sleep 6
done
ok "the query log records $OUTSIDE_NAME: BLOCK by $GROUP_ID (answered by the resolver, never resolved)"
UNLISTED_PORT="${UNLISTED##*:}"
for i in $(seq 1 40); do # the flow log publishes each closed 60 s window
  "${A[@]}" logs filter-log-events --log-group-name "$FLOG" --start-time "$T0" --filter-pattern REJECT --output json >"$W/flog.json" 2>/dev/null || true
  python3 - "$W/flog.json" "$W/enis.json" "$OUTSIDE_IP" "$UNLISTED_PORT" $FUNCS <<'PY' && break
import json, sys
ev = json.load(open(sys.argv[1])).get("events", [])
fns = sys.argv[5:]
enis = {i["NetworkInterfaceId"] for i in json.load(open(sys.argv[2]))["NetworkInterfaces"]
        if any(i.get("Description", "").startswith("AWS Lambda VPC ENI-" + f) for f in fns)}
recs = [e["message"].split() for e in ev]
rej = [r for r in recs if len(r) >= 14 and r[12] == "REJECT" and r[2] in enis]
ports_outside = {r[6] for r in rej if r[4] == sys.argv[3]}
unlisted = [r for r in rej if r[6] == sys.argv[4]]
sys.exit(0 if {"80", "443"} <= ports_outside and unlisted else 1)
PY
  [ "$i" = 40 ] && fail "the flow log never recorded the refused connections: $(head -c 1200 "$W/flog.json")"
  sleep 10
done
ok "the flow log records REJECT for $OUTSIDE_IP:80, $OUTSIDE_IP:443 and the unlisted Service's port $UNLISTED_PORT, on the probed functions' own interfaces, since the test began"
"${A[@]}" ec2 describe-flow-logs --flow-log-ids "${FL_ID:-$FLID}" --query 'FlowLogs[0].DeliverLogsStatus' --output text >"$W/fls" 2>/dev/null || true
[ "$(cat "$W/fls")" = SUCCESS ] || fail "describe-flow-logs: DeliverLogsStatus $(cat "$W/fls")"

log "5. DENIAL"
# A user of the account allowed only to read Lambda (a user, so the denial works whoever runs the probe: a key
# or a role session).
"${A[@]}" iam create-user --user-name "$READER" >/dev/null 2>"$W/ru.err" || inconclusive "create-user $READER: $(tail -c 300 "$W/ru.err")"
READER_USER=1
"${A[@]}" iam put-user-policy --user-name "$READER" --policy-name p --policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["lambda:GetFunction","lambda:ListFunctions"],"Resource":"*"}]}' >/dev/null \
  || inconclusive "put-user-policy $READER"
"${A[@]}" iam create-access-key --user-name "$READER" --output json >"$W/rk.json" || inconclusive "create-access-key $READER"
read -r RAK RSK < <(python3 -c 'import json,sys; k=json.load(open(sys.argv[1]))["AccessKey"]; print(k["AccessKeyId"], k["SecretAccessKey"])' "$W/rk.json")
READER_KEY="$RAK"
export AWS_ACCESS_KEY_ID="$RAK" AWS_SECRET_ACCESS_KEY="$RSK" AWS_SESSION_TOKEN=""
for i in $(seq 1 24); do "${A[@]}" lambda list-functions --max-items 1 >/dev/null 2>&1 && break; sleep 5; done
"${R53[@]}" list-firewall-rule-groups >/dev/null 2>"$W/deny1" && fail "a reader listed DNS Firewall rule groups"
grep -q AccessDeniedException "$W/deny1" || fail "route53resolver denial is not AccessDeniedException: $(tail -c 300 "$W/deny1")"
"${A[@]}" ec2 create-flow-logs --resource-type VPC --resource-ids "$VPC" --traffic-type REJECT --log-destination-type cloud-watch-logs \
  --log-group-name "$FLOG" --deliver-logs-permission-arn "$FLOWROLE_ARN" >/dev/null 2>"$W/deny2" && fail "a reader created a flow log"
grep -q UnauthorizedOperation "$W/deny2" || fail "ec2 denial is not UnauthorizedOperation: $(tail -c 300 "$W/deny2")"
export AWS_ACCESS_KEY_ID="$ADMIN_AK" AWS_SECRET_ACCESS_KEY="$ADMIN_SK" AWS_SESSION_TOKEN="$ADMIN_ST"
"${A[@]}" lambda create-function --function-name "$NOENI" --runtime python3.12 --handler index.handler --role "$WEAK_ARN" \
  --zip-file "fileb://$W/fn.zip" --vpc-config "$VPCCFG" >/dev/null 2>"$W/deny3" && fail "a role that may not manage network interfaces put a function in a VPC"
grep -q "does not have permissions to call CreateNetworkInterface on EC2" "$W/deny3" || fail "the role refusal is not Lambda's: $(tail -c 300 "$W/deny3")"
ok "AccessDeniedException (route53resolver), UnauthorizedOperation (ec2:CreateFlowLogs), and Lambda's refusal of a role without network-interface permissions"

python3 - "$ATTEST_OUT" "$FLOG" "$QLOG" "$VPC" "${ATTEST:-$FUNCS}" "$FUNCS" <<'PY'
import datetime, json, sys
out, flog, qlog, vpc, covers, probed = sys.argv[1:]
json.dump({"checked_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "covers": covers.split(), "outbound_denied": True, "dns_contained": True, "denials_logged": True,
           "evidence": "probe/aws-shim-lambda-vpc.sh: VPC %s, probed by %s; flow log group %s (REJECT), query log group %s"
                       % (vpc, ", ".join(probed.split()), flog, qlog)},
          open(out, "w"), indent=2)
PY
if [ -n "$ATTEST" ]; then WHAT="the VPC configuration of $ATTEST"; else WHAT="a function in a VPC (managed and unsupported runtime)"; fi
log "PASS — $WHAT: egress-isolated, DNS contained, refusals logged; attestation in $ATTEST_OUT"
