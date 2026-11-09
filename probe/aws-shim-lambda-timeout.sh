#!/usr/bin/env bash
# Probe: a Lambda invoke runs to the function's own Timeout (#372), through the aws-shim with the real AWS CLI.
#
# It deploys three functions with CloudFormation (inline Node.js code: two sleep for the event's "sleep"
# seconds, one echoes its event) and asserts:
#   0. a function with Lambda's default Timeout of 3 s, invoked from zero instances three times in a row,
#      returns its event each time: the cold start is not counted against its Timeout (#413);
#   1. a function with Timeout 150 that runs 120 s returns its result — the shim no longer cuts an invoke
#      at 60 s;
#   2. a function with Timeout 5 that runs 30 s ends with Lambda's timeout error: a function error
#      (Unhandled) whose payload is Sandbox.Timedout "Task timed out after 5.00 seconds" — not
#      ResourceNotFoundException — and it ends at about 5 s, by the function's own clock;
#   3. DENIAL: a principal whose policy does not allow lambda:InvokeFunction is refused with
#      AccessDeniedException.
#
# Needs: aws (v2), kubectl (to mint a throwaway admin deployer, removed on exit); a deployed shim with the
# CloudFormation, Lambda, IAM and STS front doors. Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-lambda-timeout.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
export AWS_REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
STACK="lto-$SFX"; ROLE="lto-invoker-$SFX"

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
  for _ in $(seq 1 60); do
    st="$("${A[@]}" cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
    case "$st" in *_IN_PROGRESS) sleep 5 ;; *) break ;; esac
  done
  if "${A[@]}" cloudformation delete-stack --stack-name "$STACK" >/dev/null 2>&1; then
    for _ in $(seq 1 60); do "${A[@]}" cloudformation describe-stacks --stack-name "$STACK" >/dev/null 2>&1 || break; sleep 3; done
  fi
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
  mint_key "lto-admin-$SFX" admins
  export AWS_ACCESS_KEY_ID="$MK_AK" AWS_SECRET_ACCESS_KEY="$MK_SK"
  log "minted a throwaway openinfra:admins deployer (lto-admin-$SFX)"
  sleep 20
fi
ADMIN_AK="$AWS_ACCESS_KEY_ID"; ADMIN_SK="$AWS_SECRET_ACCESS_KEY"

cat > "$W/t.yaml" <<'YAML'
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Exec:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement: [{Effect: Allow, Principal: {Service: lambda.amazonaws.com}, Action: "sts:AssumeRole"}]
  Slow:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: nodejs22.x
      Handler: index.handler
      Timeout: 150
      Role: !GetAtt Exec.Arn
      Code:
        ZipFile: |
          exports.handler = async (e) => { await new Promise((r) => setTimeout(r, (e.sleep || 0) * 1000)); return { slept: e.sleep || 0 }; };
  Short:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: nodejs22.x
      Handler: index.handler
      Timeout: 5
      Role: !GetAtt Exec.Arn
      Code:
        ZipFile: |
          exports.handler = async (e) => { await new Promise((r) => setTimeout(r, (e.sleep || 0) * 1000)); return { slept: e.sleep || 0 }; };
  Cold:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: nodejs22.x
      Handler: index.handler
      Timeout: 3
      Role: !GetAtt Exec.Arn
      Code:
        ZipFile: |
          exports.handler = async (e) => e;
Outputs:
  SlowName: { Value: !Ref Slow }
  ShortName: { Value: !Ref Short }
  ColdName: { Value: !Ref Cold }
YAML
log "deploying $STACK (Slow: Timeout 150; Short: Timeout 5; Cold: Timeout 3)"
for i in $(seq 1 5); do # a freshly minted deployer's authority reaches every check within a minute or so
  "${A[@]}" cloudformation deploy --template-file "$W/t.yaml" --stack-name "$STACK" --capabilities CAPABILITY_IAM >"$W/d" 2>&1 && break
  [ "$i" = 5 ] && fail "the stack did not deploy: $(tail -c 500 "$W/d")"
  "${A[@]}" cloudformation delete-stack --stack-name "$STACK" >/dev/null 2>&1; sleep 25
done
out() { "${A[@]}" cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }
SLOW="$(out SlowName)"; SHORT="$(out ShortName)"; COLD="$(out ColdName)"
ok "deployed ($SLOW, $SHORT, $COLD)"

invoke() { # <function> <payload> <out> → prints the FunctionError ("" for none)
  "${A[@]}" --cli-read-timeout 400 lambda invoke --function-name "$1" --cli-binary-format raw-in-base64-out --payload "$2" "$3" \
    --query FunctionError --output text 2>"$W/inv.err"
}
warm() { for _ in $(seq 1 6); do invoke "$1" '{"sleep":0}' "$W/warm.json" >/dev/null && grep -q '"slept":0' "$W/warm.json" && return 0; sleep 10; done; return 1; }
log "0. three invokes from zero of a function with Timeout 3"
COLD_NS="$(kubectl get ksvc -A --field-selector "metadata.name=$COLD" -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null)"
[ -n "$COLD_NS" ] || inconclusive "no Knative Service for $COLD"
for i in $(seq 1 60); do # the first instance (Knative starts one to verify the revision) scales away when idle
  [ "$(kubectl -n "$COLD_NS" get pods -l "serving.knative.dev/service=$COLD" --no-headers 2>/dev/null | grep -c .)" = 0 ] && break
  [ "$i" = 60 ] && inconclusive "$COLD never scaled to zero instances"
  sleep 10
done
for n in 1 2 3; do
  start=$(date +%s)
  fe="$(invoke "$COLD" "{\"cold\":$n}" "$W/cold.json")" || fail "cold invoke $n failed at the API: $(tail -c 400 "$W/inv.err")"
  took=$(( $(date +%s) - start ))
  [ "$fe" = "None" ] || [ -z "$fe" ] || fail "cold invoke $n of a function with Timeout 3 ended with a function error ($fe) after ${took}s: $(cat "$W/cold.json")"
  grep -q "\"cold\":$n" "$W/cold.json" || fail "cold invoke $n returned: $(cat "$W/cold.json")"
  ok "invoke $n from zero returned its event after ${took}s"
done

warm "$SLOW" || fail "the Slow function never answered a warm-up: $(tail -c 300 "$W/inv.err")"

log "1. a 120 s invoke of a function with Timeout 150"
start=$(date +%s)
fe="$(invoke "$SLOW" '{"sleep":120}' "$W/slow.json")" || fail "the 120 s invoke failed: $(tail -c 400 "$W/inv.err")"
took=$(( $(date +%s) - start ))
[ "$fe" = "None" ] || [ -z "$fe" ] || fail "the 120 s invoke ended with a function error ($fe): $(cat "$W/slow.json")"
grep -q '"slept":120' "$W/slow.json" || fail "the 120 s invoke returned: $(cat "$W/slow.json")"
[ "$took" -ge 115 ] || fail "the invoke returned after ${took}s, before the function's 120 s"
ok "returned {\"slept\":120} after ${took}s"

log "2. a 30 s invoke of a function with Timeout 5"
# warmed just before, so the elapsed time is the function's own clock alone (a cold start is not counted)
warm "$SHORT" || fail "the Short function never answered a warm-up: $(tail -c 300 "$W/inv.err")"
start=$(date +%s)
fe="$(invoke "$SHORT" '{"sleep":30}' "$W/short.json")" || fail "the timed-out invoke failed at the API: $(tail -c 400 "$W/inv.err")"
took=$(( $(date +%s) - start ))
[ "$fe" = "Unhandled" ] || fail "a timed-out invoke must be a function error (Unhandled), got '$fe': $(cat "$W/short.json")"
[ "$took" -ge 4 ] && [ "$took" -le 12 ] || fail "the timed-out invoke ended after ${took}s, not at the function's own 5 s"
python3 - "$W/short.json" <<'PY' || fail "the timed-out payload is not Lambda's: $(cat "$W/short.json")"
import json, sys
r = json.load(open(sys.argv[1]))
assert r.get("errorType") == "Sandbox.Timedout" and "Task timed out after 5.00 seconds" in r.get("errorMessage", ""), r
PY
ok "Unhandled after ${took}s: $(python3 -c "import json;print(json.load(open('$W/short.json'))['errorMessage'])" | cut -c1-90)"

log "3. DENIAL: a principal whose policy does not allow lambda:InvokeFunction"
ME="$("${A[@]}" sts get-caller-identity --query Arn --output text)" || inconclusive "sts get-caller-identity failed"
"${A[@]}" iam create-role --role-name "$ROLE" \
  --assume-role-policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"$ME\"},\"Action\":\"sts:AssumeRole\"}]}" >/dev/null \
  || inconclusive "iam create-role failed"
ROLE_MADE=1
"${A[@]}" iam put-role-policy --role-name "$ROLE" --policy-name read \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["lambda:GetFunction","lambda:ListFunctions"],"Resource":"*"}]}' >/dev/null \
  || inconclusive "iam put-role-policy failed"
ROLE_ARN="$("${A[@]}" iam get-role --role-name "$ROLE" --query Role.Arn --output text)"
for i in $(seq 1 24); do
  dec="$("${A[@]}" iam simulate-principal-policy --policy-source-arn "$ROLE_ARN" --action-names lambda:GetFunction \
          --query 'EvaluationResults[0].EvalDecision' --output text 2>/dev/null || true)"
  [ "$dec" = allowed ] && break
  [ "$i" = 24 ] && inconclusive "the role's policy did not take effect within 2 minutes"
  sleep 5
done
CREDS="$("${A[@]}" sts assume-role --role-arn "$ROLE_ARN" --role-session-name lto --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text)" \
  || inconclusive "sts assume-role failed"
read -r rak rsk rst <<<"$CREDS"
if AWS_ACCESS_KEY_ID="$rak" AWS_SECRET_ACCESS_KEY="$rsk" AWS_SESSION_TOKEN="$rst" \
   "${A[@]}" lambda invoke --function-name "$SHORT" --cli-binary-format raw-in-base64-out --payload '{}' "$W/deny.json" >/dev/null 2>"$W/deny.err"; then
  fail "a principal without lambda:InvokeFunction invoked the function"
fi
grep -q "AccessDeniedException" "$W/deny.err" || fail "the refusal is not AccessDeniedException: $(tail -c 300 "$W/deny.err")"
ok "refused: AccessDeniedException"

printf '✓ PASS — a Lambda invoke runs to the function'"'"'s own Timeout: a cold start is not counted (Timeout 3 from zero returns), 120 s with Timeout 150 returns its result, 30 s with Timeout 5 is Sandbox.Timedout "Task timed out after 5.00 seconds" at 5 s, and lambda:InvokeFunction is enforced\n'
