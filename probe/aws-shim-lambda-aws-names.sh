#!/usr/bin/env bash
# Probe: Lambda functions reach the platform by AWS's own hostnames (#335), through the aws-shim with the real
# AWS CLI, with handlers built on the JavaScript aws-sdk v2 (the nodejs16.x runtime's own SDK), which reads none
# of the endpoint variables.
#
# Asserts:
#   1. outside a VPC, a v2 DynamoDB client with no endpoint (ListTables) and a v2 S3 client addressing a bucket by
#      its virtual-hosted AWS name (GetObject) reach the platform with no code change: dynamodb.<region>.amazonaws.com
#      resolves to the platform, whose certificate the function trusts; a v2 client of a service the platform does
#      not serve (Comprehend) fails at once, naming its host, well under the function's timeout;
#   2. DENIAL: a function whose role does not allow dynamodb:ListTables is refused it, with AccessDeniedException,
#      by the platform: the call went through its IAM, not to AWS;
#   3. a pod that is not a function resolves dynamodb.<region>.amazonaws.com as the cluster DNS does (not to the
#      platform), cannot ask the function resolver, and has no AWS endpoints CA;
#   4. in a VPC whose DNS Firewall allows *.amazonaws.com (and blocks everything else) and whose security group
#      allows HTTPS to 0.0.0.0/0, the same v2 clients reach the platform through the VPC's resolver, and the
#      unserved service fails at once.
# Everything the probe made is removed on exit.
#
# Needs: aws (v2), kubectl (a throwaway admin, the VPC's network objects and the plain pod), python3; a deployed
# shim with the Lambda, IAM, STS, S3, DynamoDB, EC2 and Route 53 Resolver front doors, and functions reaching AWS's
# names (the openinfra-function-dns EnvironmentConfig, and VPC_RESOLVER_AWS_NAMES=on). Exit 0 = pass, 1 = a real
# failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-lambda-aws-names.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
NET_NS="${NET_NS:-open-infra-cfn}" # the management account's network (the stack namespace)
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
FUNCTION_RESOLVER="${FUNCTION_RESOLVER:-10.43.0.54}"
export AWS_REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
FN="lnames-$SFX"; FN_DENY="lnames-deny-$SFX"; FN_VPC="lnames-vpc-$SFX"; BUCKET="lnames-$SFX"; PLAIN="lnames-plain-$SFX"
EXEC="lnames-exec-$SFX"; NARROW="lnames-narrow-$SFX"
VPC="lnames-$SFX"; SUB="lnames-a-$SFX"; SG="lnames-fn-$SFX"

log()  { printf '▸ %s\n' "$*"; }
ok()   { printf '▸   ✓ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for t in aws kubectl python3 curl; do command -v "$t" >/dev/null || inconclusive "$t is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
kubectl get environmentconfigs.apiextensions.crossplane.io openinfra-function-dns >/dev/null 2>&1 \
  || inconclusive "functions do not reach AWS's names here (no openinfra-function-dns EnvironmentConfig)"
W="$(mktemp -d)"
A=(aws --endpoint-url "$ENDPOINT" --no-cli-pager)
R53=(aws --endpoint-url "$ENDPOINT" --no-cli-pager route53resolver)

CREATED_USERS=(); CREATED_KEYS=(); ROLES_MADE=(); BUCKET_MADE=""; OWN_NET=""; LISTS=(); RULES=(); GROUP_ID=""; ASSOC_ID=""
cleanup() {
  set +e
  [ -n "${ADMIN_AK:-}" ] && export AWS_ACCESS_KEY_ID="$ADMIN_AK" AWS_SECRET_ACCESS_KEY="$ADMIN_SK"
  for f in "$FN" "$FN_DENY" "$FN_VPC"; do "${A[@]}" lambda delete-function --function-name "$f" >/dev/null 2>&1; done
  kubectl -n "$NET_NS" delete pod "$PLAIN" --ignore-not-found --wait=false >/dev/null 2>&1
  [ -n "$ASSOC_ID" ] && "${R53[@]}" disassociate-firewall-rule-group --firewall-rule-group-association-id "$ASSOC_ID" >/dev/null 2>&1
  for l in "${RULES[@]:-}"; do [ -n "$l" ] && "${R53[@]}" delete-firewall-rule --firewall-rule-group-id "$GROUP_ID" --firewall-domain-list-id "$l" >/dev/null 2>&1; done
  [ -n "$GROUP_ID" ] && "${R53[@]}" delete-firewall-rule-group --firewall-rule-group-id "$GROUP_ID" >/dev/null 2>&1
  for l in "${LISTS[@]:-}"; do [ -n "$l" ] && "${R53[@]}" delete-firewall-domain-list --firewall-domain-list-id "$l" >/dev/null 2>&1; done
  if [ -n "$OWN_NET" ]; then
    kubectl -n "$NET_NS" delete securitygroup.openinfra.dev "$SG" --ignore-not-found --wait=false >/dev/null 2>&1
    kubectl -n "$NET_NS" delete subnet.openinfra.dev "$SUB" --ignore-not-found --wait=false >/dev/null 2>&1
    kubectl -n "$NET_NS" delete vpc.openinfra.dev "$VPC" --ignore-not-found --wait=false >/dev/null 2>&1
  fi
  if [ -n "$BUCKET_MADE" ]; then
    "${A[@]}" s3 rm "s3://$BUCKET" --recursive >/dev/null 2>&1
    "${A[@]}" s3api delete-bucket --bucket "$BUCKET" >/dev/null 2>&1
  fi
  for r in "${ROLES_MADE[@]:-}"; do
    [ -z "$r" ] && continue
    "${A[@]}" iam delete-role-policy --role-name "$r" --policy-name p >/dev/null 2>&1
    "${A[@]}" iam delete-role --role-name "$r" >/dev/null 2>&1
  done
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1; done
  for k in "${CREATED_KEYS[@]:-}"; do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1; done
  rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

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
mint_key "lnames-admin-$SFX" admins
ADMIN_AK="$MK_AK"; ADMIN_SK="$MK_SK"
export AWS_ACCESS_KEY_ID="$ADMIN_AK" AWS_SECRET_ACCESS_KEY="$ADMIN_SK"
for i in $(seq 1 24); do
  ACCOUNT="$("${A[@]}" sts get-caller-identity --query Account --output text 2>/dev/null)" && break
  [ "$i" = 24 ] && inconclusive "the administrator's key never authenticated"
  sleep 5
done
sleep "${IAM_SETTLE_SECONDS:-35}"

# role <name> <policy-json>: an execution role Lambda may assume, removed on exit.
role() {
  "${A[@]}" iam create-role --role-name "$1" --assume-role-policy-document \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
    >/dev/null 2>"$W/err" || inconclusive "iam create-role $1: $(tail -c 300 "$W/err")"
  ROLES_MADE+=("$1")
  "${A[@]}" iam put-role-policy --role-name "$1" --policy-name p --policy-document "$2" >/dev/null 2>"$W/err" \
    || inconclusive "iam put-role-policy $1: $(tail -c 300 "$W/err")"
}
ENI='"ec2:CreateNetworkInterface","ec2:DescribeNetworkInterfaces","ec2:DeleteNetworkInterface","logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"'
role "$EXEC" "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"dynamodb:ListTables\",$ENI],\"Resource\":\"*\"},{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::$BUCKET/*\"}]}"
role "$NARROW" "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[$ENI],\"Resource\":\"*\"}]}"
EXEC_ARN="arn:aws:iam::$ACCOUNT:role/$EXEC"; NARROW_ARN="arn:aws:iam::$ACCOUNT:role/$NARROW"

"${A[@]}" s3api create-bucket --bucket "$BUCKET" >/dev/null 2>"$W/err" || inconclusive "create-bucket: $(tail -c 300 "$W/err")"
BUCKET_MADE=1
printf 'hello from the platform' >"$W/hello.txt"
"${A[@]}" s3api put-object --bucket "$BUCKET" --key hello.txt --body "$W/hello.txt" >/dev/null 2>"$W/err" || inconclusive "put-object: $(tail -c 300 "$W/err")"

# The handler: aws-sdk v2 clients built as the estate builds them, with no endpoint, and where AWS's name resolves.
cat >"$W/index.js" <<'JS'
const AWS = require("aws-sdk");
const dns = require("dns").promises;
const err = (e) => [e.code, e.message].filter(Boolean).join(": ");
exports.handler = async (event) => {
  const out = { sdk: AWS.VERSION };
  out.dynamodbAddress = await dns.lookup("dynamodb." + process.env.AWS_REGION + ".amazonaws.com").then((a) => a.address, err);
  try { await new AWS.DynamoDB().listTables({ Limit: 1 }).promise(); out.dynamodb = "ok"; } catch (e) { out.dynamodb = err(e); }
  try {
    const r = await new AWS.S3().getObject({ Bucket: event.bucket, Key: "hello.txt" }).promise();
    out.s3 = r.Body.toString();
  } catch (e) { out.s3 = err(e); }
  const t0 = Date.now();
  try { await new AWS.Comprehend().detectDominantLanguage({ Text: "hello" }).promise(); out.unserved = "answered"; }
  catch (e) { out.unserved = err(e); }
  out.unservedMs = Date.now() - t0;
  return out;
};
JS
(cd "$W" && python3 -c "import zipfile;z=zipfile.ZipFile('fn.zip','w');z.write('index.js');z.close()")

create() { # create <name> <role-arn> [--vpc-config ...]
  local name="$1" arn="$2"; shift 2
  for i in $(seq 1 12); do
    "${A[@]}" lambda create-function --function-name "$name" --runtime nodejs16.x --handler index.handler --role "$arn" \
      --zip-file "fileb://$W/fn.zip" --timeout 60 "$@" >/dev/null 2>"$W/create.err" && return 0
    sleep 10
  done
  fail "create-function $name: $(tail -c 400 "$W/create.err")"
}
invoke() { # invoke <name> <out>: wait (up to 6 min) for an answer from the function's code
  local until=$((SECONDS + 360))
  while [ "$SECONDS" -lt "$until" ]; do
    if "${A[@]}" --cli-read-timeout 150 lambda invoke --function-name "$1" --cli-binary-format raw-in-base64-out \
      --payload "{\"bucket\":\"$BUCKET\"}" "$2" >/dev/null 2>"$W/inv.err" && python3 -c "import json,sys;sys.exit(0 if 'sdk' in json.load(open('$2')) else 1)" 2>/dev/null; then
      return 0
    fi
    sleep 5
  done
  return 1
}
SHIM_IP="$(kubectl -n "$SHIM_NS" get svc aws-shim -o jsonpath='{.spec.clusterIP}')"

# expect <out> <what>: the v2 clients reached the platform, and the unserved service failed fast.
expect() {
  python3 - "$1" "$SHIM_IP" "$AWS_REGION" <<'PY' || fail "$2: $(cat "$1")"
import json, sys
r, shim, region = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3]
assert r["sdk"].startswith("2."), "not aws-sdk v2: %s" % r["sdk"]
assert r["dynamodbAddress"] == shim, "dynamodb.%s.amazonaws.com resolved to %s, not the platform (%s)" % (region, r["dynamodbAddress"], shim)
assert r["dynamodb"] == "ok", "DynamoDB ListTables: %s" % r["dynamodb"]
assert r["s3"] == "hello from the platform", "S3 GetObject by the bucket's virtual-hosted name: %s" % r["s3"]
assert "comprehend.%s.amazonaws.com" % region in r["unserved"], "the unserved service's error does not name its host: %s" % r["unserved"]
assert r["unservedMs"] < 15000, "the unserved service took %d ms to fail" % r["unservedMs"]
PY
}

log "1. outside a VPC: aws-sdk v2 clients with no endpoint"
create "$FN" "$EXEC_ARN"
invoke "$FN" "$W/out1.json" || fail "the function never answered: $(cat "$W/out1.json" 2>/dev/null) $(tail -c 300 "$W/inv.err")"
expect "$W/out1.json" "outside a VPC"
ok "dynamodb.$AWS_REGION.amazonaws.com resolves to the platform; v2 DynamoDB ListTables and S3 GetObject by $BUCKET.s3.amazonaws.com answered; Comprehend failed at once, naming its host ($(python3 -c "import json;print(json.load(open('$W/out1.json'))['unservedMs'])") ms)"

log "2. DENIAL: a role that does not allow dynamodb:ListTables"
create "$FN_DENY" "$NARROW_ARN"
invoke "$FN_DENY" "$W/out2.json" || fail "the function never answered: $(tail -c 300 "$W/inv.err")"
python3 -c "import json,sys; r=json.load(open('$W/out2.json')); sys.exit(0 if r['dynamodb'].startswith('AccessDeniedException') else 1)" \
  || fail "the narrow role's ListTables was not refused by the platform: $(cat "$W/out2.json")"
ok "refused by the platform's IAM: AccessDeniedException"

log "3. a pod that is not a function"
kubectl -n "$NET_NS" run "$PLAIN" --image=busybox:1.36 --restart=Never --command -- sh -c \
  "nslookup dynamodb.$AWS_REGION.amazonaws.com; echo ===; timeout 6 nslookup dynamodb.$AWS_REGION.amazonaws.com $FUNCTION_RESOLVER; echo ===; ls /etc/openinfra/aws-endpoints-ca 2>&1" >/dev/null \
  || inconclusive "could not run the plain pod"
for i in $(seq 1 40); do
  ph="$(kubectl -n "$NET_NS" get pod "$PLAIN" -o jsonpath='{.status.phase}' 2>/dev/null)"
  [ "$ph" = Succeeded ] || [ "$ph" = Failed ] && break
  sleep 3
done
kubectl -n "$NET_NS" logs "$PLAIN" >"$W/plain.log" 2>&1
python3 - "$W/plain.log" "$SHIM_IP" <<'PY' || fail "a pod that is not a function: $(cat "$W/plain.log")"
import sys
parts = open(sys.argv[1]).read().split("===")
assert len(parts) == 3, parts
cluster, function_resolver, ca = parts
assert sys.argv[2] not in cluster, "it resolved AWS's name to the platform"
assert "Address" in cluster.split("Name:", 1)[-1], "it did not resolve AWS's name at all"
assert sys.argv[2] not in function_resolver, "it got an answer from the function resolver"
assert "No such file" in ca, "it has the AWS endpoints CA"
PY
ok "resolves AWS's name as the cluster does, cannot ask the function resolver, and has no AWS endpoints CA"

log "4. in a VPC: a walled garden that allows *.amazonaws.com, HTTPS egress to 0.0.0.0/0"
cat >"$W/net.yaml" <<EOF
apiVersion: openinfra.dev/v1
kind: Vpc
metadata: { name: $VPC, namespace: $NET_NS }
spec: {}
---
apiVersion: openinfra.dev/v1
kind: Subnet
metadata: { name: $SUB, namespace: $NET_NS }
spec: { vpc: $VPC, cidr: 10.232.1.0/24 }
---
apiVersion: openinfra.dev/v1
kind: SecurityGroup
metadata: { name: $SG, namespace: $NET_NS }
spec:
  vpc: $VPC
  ingress: []
  egress:
    - { protocol: TCP, ports: [443], to: [ { cidr: 0.0.0.0/0 } ], description: "HTTPS, as through a NAT gateway" }
EOF
OWN_NET=1
kubectl apply -f "$W/net.yaml" >/dev/null || inconclusive "could not write the VPC's network objects"
for i in $(seq 1 36); do
  n="$("${A[@]}" ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC" --query 'length(Subnets)' --output text 2>/dev/null || echo 0)"
  [ "$n" = 1 ] && break
  [ "$i" = 36 ] && inconclusive "the VPC's subnet never showed in describe-subnets"
  sleep 5
done
AWS_LIST="$("${R53[@]}" create-firewall-domain-list --creator-request-id "a-$SFX" --name "lnames-aws-$SFX" --query FirewallDomainList.Id --output text)" \
  || fail "create-firewall-domain-list (AWS names)"
LISTS+=("$AWS_LIST")
"${R53[@]}" update-firewall-domains --firewall-domain-list-id "$AWS_LIST" --operation ADD --domains '*.amazonaws.com' >/dev/null || fail "update-firewall-domains"
ALL_LIST="$("${R53[@]}" create-firewall-domain-list --creator-request-id "b-$SFX" --name "lnames-all-$SFX" --query FirewallDomainList.Id --output text)" \
  || fail "create-firewall-domain-list (everything)"
LISTS+=("$ALL_LIST")
"${R53[@]}" update-firewall-domains --firewall-domain-list-id "$ALL_LIST" --operation ADD --domains '*' >/dev/null || fail "update-firewall-domains"
GROUP_ID="$("${R53[@]}" create-firewall-rule-group --creator-request-id "g-$SFX" --name "lnames-walled-$SFX" --query FirewallRuleGroup.Id --output text)" \
  || fail "create-firewall-rule-group"
"${R53[@]}" create-firewall-rule --creator-request-id "r1-$SFX" --firewall-rule-group-id "$GROUP_ID" --firewall-domain-list-id "$AWS_LIST" \
  --priority 100 --action ALLOW --name allow-aws >/dev/null || fail "create-firewall-rule ALLOW"
RULES+=("$AWS_LIST")
"${R53[@]}" create-firewall-rule --creator-request-id "r2-$SFX" --firewall-rule-group-id "$GROUP_ID" --firewall-domain-list-id "$ALL_LIST" \
  --priority 200 --action BLOCK --block-response NXDOMAIN --name block-everything-else >/dev/null || fail "create-firewall-rule BLOCK"
RULES+=("$ALL_LIST")
ASSOC_ID="$("${R53[@]}" associate-firewall-rule-group --creator-request-id "s-$SFX" --firewall-rule-group-id "$GROUP_ID" --vpc-id "$VPC" \
  --priority 101 --name "lnames-$SFX" --query FirewallRuleGroupAssociation.Id --output text)" || fail "associate-firewall-rule-group"
create "$FN_VPC" "$EXEC_ARN" --vpc-config "SubnetIds=$SUB,SecurityGroupIds=$SG"
invoke "$FN_VPC" "$W/out4.json" || fail "the VPC function never answered: $(cat "$W/out4.json" 2>/dev/null) $(tail -c 300 "$W/inv.err")"
expect "$W/out4.json" "in a VPC"
ok "through the VPC's resolver: v2 DynamoDB and S3 answered by the platform, Comprehend failed at once"

log "PASS — aws-sdk v2 clients with no endpoint reach the platform by AWS's own hostnames, outside and inside a VPC; an unserved service fails fast, naming its host; the platform's IAM decides (a narrow role is refused); a pod that is not a function is unaffected"
