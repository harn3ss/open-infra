#!/usr/bin/env bash
# Probe: the Lambda API creates and changes functions (#364), through the aws-shim with the real AWS CLI.
#
# Asserts:
#   1. create-function with a .zip (--zip-file) and an execution role that trusts Lambda makes a function
#      whose CodeSha256 is the package's, and which answers an invoke with its code and variables;
#   2. update-function-code with a new .zip changes what the function runs;
#   3. update-function-configuration changes its variables and timeout; a value with quotes, a backslash, a
#      line break and "{{", and one crafted to add a valueFrom (#405), reach the handler exactly as written,
#      and the function's Service reads no Secret for them;
#   4. update-function-code from S3 (--s3-bucket/--s3-key) runs the S3 object's code;
#   5. refusals, as Lambda refuses: a role that does not trust Lambda ("cannot be assumed by Lambda"),
#      layers, and more than 4 KB of variables (InvalidParameterValueException);
#   6. DENIAL: a principal whose policy allows only reads is refused create-function and delete-function
#      with AccessDeniedException, and one allowed lambda:CreateFunction but not iam:PassRole is refused
#      naming iam:PassRole;
#   7. delete-function removes it (get-function then answers ResourceNotFoundException).
#
# Needs: aws (v2), kubectl (to mint a throwaway admin, removed on exit), python3; a deployed shim with the
# Lambda, IAM, STS, S3 and CloudFormation front doors. Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-lambda-api.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
export AWS_REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
FN="lapi-$SFX"; EXEC="lapi-exec-$SFX"; NOTLAMBDA="lapi-states-$SFX"; READER="lapi-reader-$SFX"; CREATOR="lapi-creator-$SFX"
STACK="lapi-$SFX"

log()  { printf '▸ %s\n' "$*"; }
ok()   { printf '▸   ✓ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for t in aws kubectl python3; do command -v "$t" >/dev/null || inconclusive "$t is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
W="$(mktemp -d)"
A=(aws --endpoint-url "$ENDPOINT" --no-cli-pager)

CREATED_USERS=(); CREATED_KEYS=(); ROLES_MADE=(); BUCKET=""
cleanup() {
  set +e
  unset AWS_SESSION_TOKEN
  [ -n "${ADMIN_AK:-}" ] && export AWS_ACCESS_KEY_ID="$ADMIN_AK" AWS_SECRET_ACCESS_KEY="$ADMIN_SK"
  "${A[@]}" lambda delete-function --function-name "$FN" >/dev/null 2>&1
  "${A[@]}" lambda delete-function --function-name "$FN-denied" >/dev/null 2>&1
  [ -n "$BUCKET" ] && "${A[@]}" s3 rm "s3://$BUCKET" --recursive >/dev/null 2>&1
  if "${A[@]}" cloudformation describe-stacks --stack-name "$STACK" >/dev/null 2>&1; then
    "${A[@]}" cloudformation delete-stack --stack-name "$STACK" >/dev/null 2>&1
    for _ in $(seq 1 60); do "${A[@]}" cloudformation describe-stacks --stack-name "$STACK" >/dev/null 2>&1 || break; sleep 3; done
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
  mint_key "lapi-admin-$SFX" admins
  export AWS_ACCESS_KEY_ID="$MK_AK" AWS_SECRET_ACCESS_KEY="$MK_SK"
  log "minted a throwaway openinfra:admins caller (lapi-admin-$SFX)"
fi
ADMIN_AK="$AWS_ACCESS_KEY_ID"; ADMIN_SK="$AWS_SECRET_ACCESS_KEY"
for i in $(seq 1 24); do # a freshly minted caller's authority takes a minute or so to reach every check
  ME="$("${A[@]}" sts get-caller-identity --query Arn --output text 2>/dev/null)" && break
  [ "$i" = 24 ] && inconclusive "sts get-caller-identity never succeeded"
  sleep 5
done

# role <name> <trust-principal-json> [policy-json]: an IAM role, removed on exit; prints nothing.
role() {
  "${A[@]}" iam create-role --role-name "$1" \
    --assume-role-policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":$2,\"Action\":\"sts:AssumeRole\"}]}" \
    >/dev/null || inconclusive "iam create-role $1 failed"
  ROLES_MADE+=("$1")
  if [ -n "${3:-}" ]; then
    "${A[@]}" iam put-role-policy --role-name "$1" --policy-name p --policy-document "$3" >/dev/null || inconclusive "iam put-role-policy $1 failed"
  fi
}
role "$EXEC" '{"Service":"lambda.amazonaws.com"}'
role "$NOTLAMBDA" '{"Service":"states.amazonaws.com"}'
EXEC_ARN="$("${A[@]}" iam get-role --role-name "$EXEC" --query Role.Arn --output text)"
NOTLAMBDA_ARN="$("${A[@]}" iam get-role --role-name "$NOTLAMBDA" --query Role.Arn --output text)"

# zip <file> <version>: a Node.js package whose handler answers its version and STAGE.
mkzip() {
  python3 - "$1" "$2" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("index.js", "exports.handler = async () => ({ v: %s, stage: process.env.STAGE || null, odd: process.env.ODD || null, crafted: process.env.CRAFTED || null });\n" % sys.argv[2])
PY
}
b64sha() { python3 -c 'import base64,hashlib,sys;print(base64.b64encode(hashlib.sha256(open(sys.argv[1],"rb").read()).digest()).decode())' "$1"; }
mkzip "$W/v1.zip" 1; mkzip "$W/v2.zip" 2; mkzip "$W/v3.zip" 3

invoke() { "${A[@]}" --cli-read-timeout 200 lambda invoke --function-name "$FN" --cli-binary-format raw-in-base64-out --payload '{}' "$W/out.json" >/dev/null 2>"$W/inv.err"; }
# answers <python-expr over r>: wait (up to 3 min) until an invoke's answer satisfies it.
answers() {
  for _ in $(seq 1 36); do
    if invoke && python3 -c "import json,sys;r=json.load(open('$W/out.json'));sys.exit(0 if ($1) else 1)" 2>/dev/null; then return 0; fi
    sleep 5
  done
  return 1
}

log "1. create-function with a .zip and an execution role that trusts Lambda"
for i in $(seq 1 6); do # the role's trust reaches the shim within a few seconds of create-role
  "${A[@]}" lambda create-function --function-name "$FN" --runtime nodejs22.x --handler index.handler --role "$EXEC_ARN" \
    --zip-file "fileb://$W/v1.zip" --timeout 30 --environment 'Variables={STAGE=one}' >"$W/create.json" 2>"$W/create.err" && break
  [ "$i" = 6 ] && fail "create-function failed: $(tail -c 400 "$W/create.err")"
  sleep 10
done
python3 - "$W/create.json" "$(b64sha "$W/v1.zip")" "$FN" <<'PY' || fail "the CreateFunction answer is not the function's configuration: $(cat "$W/create.json")"
import json, sys
c = json.load(open(sys.argv[1]))
assert c["FunctionName"] == sys.argv[3] and c["Runtime"] == "nodejs22.x" and c["Handler"] == "index.handler", c
assert c["CodeSha256"] == sys.argv[2], (c.get("CodeSha256"), sys.argv[2])
assert c["Timeout"] == 30 and c["Environment"]["Variables"]["STAGE"] == "one", c
PY
ok "created; CodeSha256 is the package's"
answers 'r.get("v")==1 and r.get("stage")=="one"' || fail "the new function never answered with its code: $(cat "$W/out.json" 2>/dev/null) $(tail -c 300 "$W/inv.err")"
ok "invoke answered {\"v\":1,\"stage\":\"one\"}"

log "2. update-function-code with a new .zip"
"${A[@]}" lambda update-function-code --function-name "$FN" --zip-file "fileb://$W/v2.zip" --query CodeSha256 --output text >"$W/u2" 2>"$W/u2.err" \
  || fail "update-function-code failed: $(tail -c 400 "$W/u2.err")"
[ "$(cat "$W/u2")" = "$(b64sha "$W/v2.zip")" ] || fail "update-function-code's CodeSha256 is not the new package's"
answers 'r.get("v")==2' || fail "the function never ran the new code: $(cat "$W/out.json")"
ok "the function runs the new code"

log "3. update-function-configuration"
# Any value, as on Lambda (#405): one with quotes, a backslash, a line break and "{{", and one crafted to
# close its quotes and add a valueFrom reading another Secret. Both must reach the handler as written.
python3 - "$W/env.json" <<'ENV'
import json, sys
json.dump({"Variables": {"STAGE": "two",
    "ODD": 'say "hi" C:\\temp\\new\nline two {{ .observed }}',
    "CRAFTED": '", valueFrom: { secretKeyRef: { name: other-stack, key: password } }, x: "'}}, open(sys.argv[1], "w"))
ENV
"${A[@]}" lambda update-function-configuration --function-name "$FN" --timeout 45 --environment "file://$W/env.json" >/dev/null 2>"$W/u3.err" \
  || fail "update-function-configuration failed: $(tail -c 400 "$W/u3.err")"
[ "$("${A[@]}" lambda get-function-configuration --function-name "$FN" --query Timeout --output text)" = 45 ] || fail "the timeout did not change"
answers "r.get('v')==2 and r.get('stage')=='two' and {'ODD': r.get('odd'), 'CRAFTED': r.get('crafted')} == {k: v for k, v in json.load(open('$W/env.json'))['Variables'].items() if k != 'STAGE'}" \
  || fail "the function never saw its new variables as written: $(cat "$W/out.json")"
FNS="$(kubectl get functions.openinfra.dev -A -o jsonpath="{range .items[?(@.metadata.name==\"$FN\")]}{.metadata.namespace}{end}")"
kubectl -n "$FNS" get ksvc "$FN" -o json | python3 -c '
import json, sys
env = json.load(sys.stdin)["spec"]["template"]["spec"]["containers"][0]["env"]
bad = [e["name"] for e in env if e.get("name") in ("ODD", "CRAFTED") and "valueFrom" in e]
sys.exit(1 if bad or not any(e.get("name") == "CRAFTED" for e in env) else 0)' \
  || fail "the function's Service reads a Secret for a variable it was given as a value"
ok "Timeout 45; STAGE=two, and values with quotes, backslashes, a line break, {{ and a crafted valueFrom reach the handler as written"

log "4. update-function-code from S3"
cat > "$W/bucket.yaml" <<'YAML'
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Code:
    Type: AWS::S3::Bucket
Outputs:
  Name: { Value: !Ref Code }
YAML
"${A[@]}" cloudformation deploy --template-file "$W/bucket.yaml" --stack-name "$STACK" >"$W/b" 2>&1 || inconclusive "the bucket stack did not deploy: $(tail -c 300 "$W/b")"
BUCKET="$("${A[@]}" cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='Name'].OutputValue" --output text)"
"${A[@]}" s3 cp "$W/v3.zip" "s3://$BUCKET/fn/v3.zip" >/dev/null || inconclusive "s3 cp failed"
"${A[@]}" lambda update-function-code --function-name "$FN" --s3-bucket "$BUCKET" --s3-key fn/v3.zip --query CodeSha256 --output text >"$W/u4" 2>"$W/u4.err" \
  || fail "update-function-code from S3 failed: $(tail -c 400 "$W/u4.err")"
[ "$(cat "$W/u4")" = "$(b64sha "$W/v3.zip")" ] || fail "the S3 package's CodeSha256 is not the object's"
answers 'r.get("v")==3' || fail "the function never ran the S3 package: $(cat "$W/out.json")"
ok "the function runs the S3 object's code"

log "5. refusals, as Lambda refuses"
if "${A[@]}" lambda create-function --function-name "$FN-x" --runtime nodejs22.x --handler index.handler --role "$NOTLAMBDA_ARN" \
     --zip-file "fileb://$W/v1.zip" >/dev/null 2>"$W/r1.err"; then fail "a role that does not trust Lambda was accepted"; fi
grep -q "InvalidParameterValueException" "$W/r1.err" && grep -q "cannot be assumed by Lambda" "$W/r1.err" \
  || fail "the untrusted-role refusal is not Lambda's: $(tail -c 300 "$W/r1.err")"
ok "a role that does not trust Lambda: cannot be assumed by Lambda"
if "${A[@]}" lambda create-function --function-name "$FN-x" --runtime nodejs22.x --handler index.handler --role "$EXEC_ARN" \
     --zip-file "fileb://$W/v1.zip" --layers "arn:aws:lambda:$AWS_REGION:123456789012:layer:x:1" >/dev/null 2>"$W/r2.err"; then
  fail "layers were accepted"
fi
grep -q "InvalidParameterValueException" "$W/r2.err" || fail "the layers refusal: $(tail -c 300 "$W/r2.err")"
ok "layers: InvalidParameterValueException"
python3 -c 'import json,sys; json.dump({"Variables": {"BIG": "x" * 4100}}, open(sys.argv[1], "w"))' "$W/big.json"
if "${A[@]}" lambda update-function-configuration --function-name "$FN" --environment "file://$W/big.json" >/dev/null 2>"$W/r3.err"; then
  fail "more than 4 KB of variables was accepted"
fi
grep -q "InvalidParameterValueException" "$W/r3.err" && grep -q "exceeded the 4KB limit" "$W/r3.err" \
  || fail "the 4 KB refusal is not Lambda's: $(tail -c 300 "$W/r3.err")"
ok "more than 4 KB of variables: InvalidParameterValueException, exceeded the 4KB limit"

log "6. DENIAL: reads only, and CreateFunction without iam:PassRole"
role "$READER" "{\"AWS\":\"$ME\"}" '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["lambda:GetFunction","lambda:ListFunctions"],"Resource":"*"}]}'
role "$CREATOR" "{\"AWS\":\"$ME\"}" '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["lambda:CreateFunction","lambda:GetFunction"],"Resource":"*"}]}'
assume() { # <role> → exports the session
  local arn creds
  arn="$("${A[@]}" iam get-role --role-name "$1" --query Role.Arn --output text)"
  for i in $(seq 1 24); do
    dec="$("${A[@]}" iam simulate-principal-policy --policy-source-arn "$arn" --action-names lambda:GetFunction \
            --query 'EvaluationResults[0].EvalDecision' --output text 2>/dev/null || true)"
    [ "$dec" = allowed ] && break
    [ "$i" = 24 ] && inconclusive "$1's policy did not take effect within 2 minutes"
    sleep 5
  done
  creds="$("${A[@]}" sts assume-role --role-arn "$arn" --role-session-name lapi --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text)" \
    || inconclusive "sts assume-role $1 failed"
  read -r SAK SSK SST <<<"$creds"
}
as_session() { AWS_ACCESS_KEY_ID="$SAK" AWS_SECRET_ACCESS_KEY="$SSK" AWS_SESSION_TOKEN="$SST" "${A[@]}" "$@"; }
assume "$READER"
if as_session lambda create-function --function-name "$FN-denied" --runtime nodejs22.x --handler index.handler --role "$EXEC_ARN" \
     --zip-file "fileb://$W/v1.zip" >/dev/null 2>"$W/d1.err"; then fail "a read-only principal created a function"; fi
grep -q "AccessDeniedException" "$W/d1.err" || fail "the CreateFunction refusal is not AccessDeniedException: $(tail -c 300 "$W/d1.err")"
if as_session lambda delete-function --function-name "$FN" >/dev/null 2>"$W/d2.err"; then fail "a read-only principal deleted the function"; fi
grep -q "AccessDeniedException" "$W/d2.err" || fail "the DeleteFunction refusal is not AccessDeniedException: $(tail -c 300 "$W/d2.err")"
ok "read-only: create-function and delete-function refused with AccessDeniedException"
assume "$CREATOR"
if as_session lambda create-function --function-name "$FN-denied" --runtime nodejs22.x --handler index.handler --role "$EXEC_ARN" \
     --zip-file "fileb://$W/v1.zip" >/dev/null 2>"$W/d3.err"; then fail "a principal without iam:PassRole passed the role"; fi
grep -q "AccessDeniedException" "$W/d3.err" && grep -q "iam:PassRole" "$W/d3.err" \
  || fail "the PassRole refusal does not name iam:PassRole: $(tail -c 300 "$W/d3.err")"
ok "without iam:PassRole: AccessDeniedException naming iam:PassRole"

log "7. delete-function"
"${A[@]}" lambda delete-function --function-name "$FN" 2>"$W/del.err" || fail "delete-function failed: $(tail -c 300 "$W/del.err")"
if "${A[@]}" lambda get-function --function-name "$FN" >/dev/null 2>"$W/gone.err"; then fail "the function is still there"; fi
grep -q "ResourceNotFoundException" "$W/gone.err" || fail "a deleted function must be ResourceNotFoundException: $(tail -c 300 "$W/gone.err")"
ok "deleted; get-function answers ResourceNotFoundException"

printf '✓ PASS — the Lambda API creates (a .zip, a role that trusts Lambda), updates code (.zip and S3) and configuration, and deletes a function; takes any variable value as written (a crafted valueFrom stays a value); refuses an untrusted role, layers and more than 4 KB of variables as Lambda does; and denies create/delete without lambda permissions and CreateFunction without iam:PassRole\n'
