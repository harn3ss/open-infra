#!/usr/bin/env bash
# Probe: CloudFormation .zip Lambdas (#402), through the aws-shim front door with the real AWS CLI.
#
# It asserts, over real round-trips:
#   1. inline code: a stack with Code.ZipFile (Runtime nodejs22.x, Handler index.handler) and an in-stack
#      execution role reaches CREATE_COMPLETE, and `aws lambda invoke` returns the handler's result;
#   2. packaged code: a template run through `aws cloudformation package` against the shim's S3 (Code.S3Bucket
#      + S3Key, Runtime python3.12) deploys, and `aws lambda invoke` returns the handler's result;
#   3. an unsupported Runtime (nodejs18.x) is refused, naming the supported runtimes;
#   4. DENIAL: a deployer whose policy grants s3:GetObject on another prefix only (an assumed role) cannot
#      deploy a package it may not read — the stack fails with Lambda's AccessDenied message, as AWS refuses.
#
# Needs: aws (v2), kubectl (to mint a throwaway admin deployer, removed on exit), zip, python3; a deployed
# shim with the CloudFormation, Lambda, IAM, STS and S3 front doors. Exit 0 = pass, 1 = a real failure,
# 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-cfn-lambda-zip.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
BUCKET="lzip-probe-$SFX"
INLINE_STACK="lzip-inline-$SFX"; PKG_STACK="lzip-pkg-$SFX"; BAD_STACK="lzip-bad-$SFX"; DENY_STACK="lzip-deny-$SFX"
DEPLOYER_ROLE="lzip-deployer-$SFX"

log()  { printf '▸ %s\n' "$*"; }
ok()   { printf '▸   ✓ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for t in aws kubectl zip python3; do command -v "$t" >/dev/null || inconclusive "$t is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
W="$(mktemp -d)"
A=(aws --endpoint-url "$ENDPOINT" --region "$REGION" --no-cli-pager)

CREATED_USERS=(); CREATED_KEYS=(); ROLE_MADE=""
stack_gone() {
  local s="$1"
  for _ in $(seq 1 100); do
    st="$("${A[@]}" cloudformation describe-stacks --stack-name "$s" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
    case "$st" in *_IN_PROGRESS) sleep 5 ;; *) break ;; esac
  done
  "${A[@]}" cloudformation delete-stack --stack-name "$s" >/dev/null 2>&1 || return 0
  for _ in $(seq 1 60); do "${A[@]}" cloudformation describe-stacks --stack-name "$s" >/dev/null 2>&1 || return 0; sleep 3; done
  printf '  (cleanup) WARNING: stack %s is still present\n' "$s" >&2
}
cleanup() {
  set +e
  unset AWS_SESSION_TOKEN
  [ -n "${ADMIN_AK:-}" ] && export AWS_ACCESS_KEY_ID="$ADMIN_AK" AWS_SECRET_ACCESS_KEY="$ADMIN_SK"
  for s in "$DENY_STACK" "$BAD_STACK" "$PKG_STACK" "$INLINE_STACK"; do stack_gone "$s"; done
  "${A[@]}" s3 rb "s3://$BUCKET" --force >/dev/null 2>&1
  if [ -n "$ROLE_MADE" ]; then
    "${A[@]}" iam delete-role-policy --role-name "$DEPLOYER_ROLE" --policy-name deploy >/dev/null 2>&1
    "${A[@]}" iam delete-role --role-name "$DEPLOYER_ROLE" >/dev/null 2>&1
  fi
  # the deployer this run minted (never left behind: a minted key is an admin credential)
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1; done
  for k in "${CREATED_KEYS[@]:-}"; do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1; done
  rm -rf "$W"
}
trap cleanup EXIT

if [ -z "${AWS_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_SECRET_ACCESS_KEY:-}" ]; then
  owner="lzip-admin-$SFX"
  ak="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  sk="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  printf 'apiVersion: iam.openinfra.dev/v1\nkind: User\nmetadata: { name: "%s", namespace: "%s" }\nspec: { displayName: "%s", groups: ["admins"], source: local }\n' \
    "$owner" "$USERS_NS" "$owner" | kubectl apply -f - >/dev/null || inconclusive "could not mint a deployer User"
  CREATED_USERS+=("$owner")
  kname="iam-ak-$(printf '%s' "$ak" | sha256sum | cut -c1-40)"
  kubectl -n "$SHIM_NS" create secret generic "$kname" --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" \
    --from-literal=owner="$owner" >/dev/null || inconclusive "could not mint a deployer key"
  CREATED_KEYS+=("$kname")
  export AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk"
  log "minted a throwaway openinfra:admins deployer ($owner)"
  sleep 20 # the key reaches the shim's key cache
fi
ADMIN_AK="$AWS_ACCESS_KEY_ID"; ADMIN_SK="$AWS_SECRET_ACCESS_KEY"
# `aws cloudformation package` uploads to S3: send that to the shim too.
export AWS_ENDPOINT_URL="$ENDPOINT"

"${A[@]}" s3 mb "s3://$BUCKET" >/dev/null || inconclusive "could not create bucket $BUCKET"

ROLE_TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

# ── 1. inline code ─────────────────────────────────────────────────────────────────────────────────────
log "1. inline code (Code.ZipFile, nodejs22.x) with an in-stack execution role"
cat > "$W/inline.yaml" <<'YAML'
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Exec:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement: [{Effect: Allow, Principal: {Service: lambda.amazonaws.com}, Action: "sts:AssumeRole"}]
  Hello:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: nodejs22.x
      Handler: index.handler
      Role: !GetAtt Exec.Arn
      Code:
        ZipFile: |
          exports.handler = async (event) => ({ greeting: "hello " + event.name, file: __filename.split("/").pop() });
Outputs:
  FnName: { Value: !Ref Hello }
YAML
"${A[@]}" cloudformation deploy --template-file "$W/inline.yaml" --stack-name "$INLINE_STACK" --capabilities CAPABILITY_IAM >"$W/d1" 2>&1 \
  || fail "inline stack did not deploy: $(tail -c 600 "$W/d1")"
FN="$("${A[@]}" cloudformation describe-stacks --stack-name "$INLINE_STACK" --query "Stacks[0].Outputs[?OutputKey=='FnName'].OutputValue" --output text)"
ok "stack $INLINE_STACK CREATE_COMPLETE (function $FN)"
invoke() { # <function> <payload> <out>
  for _ in $(seq 1 6); do
    "${A[@]}" lambda invoke --function-name "$1" --cli-binary-format raw-in-base64-out --payload "$2" "$3" >"$W/inv" 2>&1 && return 0
    sleep 10
  done
  return 1
}
invoke "$FN" '{"name":"probe"}' "$W/out1.json" || fail "lambda invoke $FN failed: $(tail -c 400 "$W/inv")"
python3 - "$W/out1.json" <<'PY' || fail "the inline handler's result is wrong: $(cat "$W/out1.json")"
import json, sys
r = json.load(open(sys.argv[1]))
assert r.get("greeting") == "hello probe" and r.get("file") == "index.js", r
PY
ok "lambda invoke → {\"greeting\":\"hello probe\"} from index.js"

# ── 2. packaged code ───────────────────────────────────────────────────────────────────────────────────
log "2. packaged code (aws cloudformation package → Code.S3Bucket/S3Key, python3.12)"
mkdir -p "$W/src"
cat > "$W/src/app.py" <<'PY'
import os
def handler(event, context):
    return {"sum": event["a"] + event["b"], "runtime": os.environ.get("AWS_EXECUTION_ENV", "")}
PY
cat > "$W/pkg.yaml" <<YAML
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Exec:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument: ${ROLE_TRUST}
  Adder:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: app.handler
      Role: !GetAtt Exec.Arn
      Code: ./src
Outputs:
  FnName: { Value: !Ref Adder }
YAML
( cd "$W" && "${A[@]}" cloudformation package --template-file pkg.yaml --s3-bucket "$BUCKET" --output-template-file packaged.yaml >"$W/p" 2>&1 ) \
  || fail "aws cloudformation package failed: $(tail -c 600 "$W/p")"
grep -q "S3Bucket: $BUCKET" "$W/packaged.yaml" || fail "the packaged template has no S3Bucket: $(cat "$W/packaged.yaml")"
"${A[@]}" cloudformation deploy --template-file "$W/packaged.yaml" --stack-name "$PKG_STACK" --capabilities CAPABILITY_IAM >"$W/d2" 2>&1 \
  || fail "packaged stack did not deploy: $(tail -c 600 "$W/d2")"
FN2="$("${A[@]}" cloudformation describe-stacks --stack-name "$PKG_STACK" --query "Stacks[0].Outputs[?OutputKey=='FnName'].OutputValue" --output text)"
ok "stack $PKG_STACK CREATE_COMPLETE (function $FN2)"
invoke "$FN2" '{"a":2,"b":3}' "$W/out2.json" || fail "lambda invoke $FN2 failed: $(tail -c 400 "$W/inv")"
python3 - "$W/out2.json" <<'PY' || fail "the packaged handler's result is wrong: $(cat "$W/out2.json")"
import json, sys
r = json.load(open(sys.argv[1]))
assert r.get("sum") == 5, r
PY
ok "lambda invoke → {\"sum\":5} from the stored package"

# ── 3. an unsupported runtime ──────────────────────────────────────────────────────────────────────────
log "3. an unsupported Runtime (nodejs18.x) is refused, naming the supported runtimes"
sed 's/nodejs22.x/nodejs18.x/' "$W/inline.yaml" > "$W/bad.yaml"
if "${A[@]}" cloudformation create-stack --stack-name "$BAD_STACK" --template-body "file://$W/bad.yaml" --capabilities CAPABILITY_IAM >"$W/b" 2>&1; then
  for _ in $(seq 1 30); do
    st="$("${A[@]}" cloudformation describe-stacks --stack-name "$BAD_STACK" --query 'Stacks[0].[StackStatus,StackStatusReason]' --output text 2>&1 || true)"
    case "$st" in *_IN_PROGRESS*) sleep 3 ;; *) break ;; esac
  done
  echo "$st" > "$W/b"
  case "$st" in CREATE_COMPLETE*) fail "a nodejs18.x function was created" ;; esac
fi
grep -q "the supported runtimes are nodejs20.x, nodejs22.x, python3.12, python3.13 and dotnet8" "$W/b" \
  || fail "the refusal does not name the supported runtimes: $(tail -c 600 "$W/b")"
ok "refused: $(grep -o 'Runtime "nodejs18.x"[^;]*' "$W/b" | head -1 | cut -c1-80)…"

# ── 4. denial: a package the deployer may not read ─────────────────────────────────────────────────────
log "4. DENIAL: a deployer that may read only $BUCKET/allowed/* deploys a package under denied/"
(cd "$W/src" && zip -q "$W/denied.zip" app.py)
"${A[@]}" s3 cp "$W/denied.zip" "s3://$BUCKET/denied/app.zip" >/dev/null || inconclusive "could not upload the package"
ME="$("${A[@]}" sts get-caller-identity --query Arn --output text)" || inconclusive "sts get-caller-identity failed"
"${A[@]}" iam create-role --role-name "$DEPLOYER_ROLE" \
  --assume-role-policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"$ME\"},\"Action\":\"sts:AssumeRole\"}]}" >/dev/null \
  || inconclusive "iam create-role failed"
ROLE_MADE=1
"${A[@]}" iam put-role-policy --role-name "$DEPLOYER_ROLE" --policy-name deploy --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[
  {\"Effect\":\"Allow\",\"Action\":[\"cloudformation:*\",\"lambda:*\"],\"Resource\":\"*\"},
  {\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::$BUCKET/allowed/*\"}]}" >/dev/null \
  || inconclusive "iam put-role-policy failed"
sleep 10
CREDS="$("${A[@]}" sts assume-role --role-arn "$("${A[@]}" iam get-role --role-name "$DEPLOYER_ROLE" --query Role.Arn --output text)" \
  --role-session-name lzip-probe --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text)" \
  || inconclusive "sts assume-role failed"
cat > "$W/deny.yaml" <<YAML
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Denied:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: app.handler
      Code: { S3Bucket: $BUCKET, S3Key: denied/app.zip }
YAML
(
  read -r rak rsk rst <<<"$CREDS"
  export AWS_ACCESS_KEY_ID="$rak" AWS_SECRET_ACCESS_KEY="$rsk" AWS_SESSION_TOKEN="$rst"
  if "${A[@]}" cloudformation create-stack --stack-name "$DENY_STACK" --template-body "file://$W/deny.yaml" >"$W/dn" 2>&1; then
    for _ in $(seq 1 40); do
      st="$("${A[@]}" cloudformation describe-stacks --stack-name "$DENY_STACK" --query 'Stacks[0].[StackStatus,StackStatusReason]' --output text 2>&1 || true)"
      case "$st" in *_IN_PROGRESS*) sleep 3 ;; *) break ;; esac
    done
    echo "$st" > "$W/dn"
    "${A[@]}" cloudformation describe-stack-events --stack-name "$DENY_STACK" --query 'StackEvents[].ResourceStatusReason' --output text >>"$W/dn" 2>&1 || true
  fi
)
grep -q "CREATE_COMPLETE" "$W/dn" && ! grep -q "ROLLBACK" "$W/dn" && fail "a package the deployer may not read was deployed"
grep -q "Your access has been denied by S3" "$W/dn" && grep -q "AccessDenied" "$W/dn" \
  || fail "the refusal is not Lambda's AccessDenied: $(tail -c 600 "$W/dn")"
ok "refused as Lambda refuses it: AccessDenied reading $BUCKET/denied/app.zip"

printf '✓ PASS — CloudFormation .zip Lambdas: inline Code.ZipFile and an `aws cloudformation package` S3 package deploy and invoke; an unsupported runtime is refused naming the supported ones; a package the deployer may not read is refused with AccessDenied\n'
