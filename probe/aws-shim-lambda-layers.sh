#!/usr/bin/env bash
# Probe: a Lambda function with a role and a stored package runs as on Lambda (#418), through the aws-shim
# with the real AWS CLI.
#
# Asserts:
#   1. create-function makes a function that is not published on the gateway (spec.expose false: on Lambda a
#      function is reachable over HTTP only through a function URL), and whose handler sees the execution
#      role's credentials in AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN when its module
#      loads, as Lambda hands them over;
#   2. layers (spec.code.layers, an object in a bucket of the function's own account) are extracted into
#      /opt with the function's own identity, no keys: the handler loads a module the layer provides;
#   3. a layer the function's account may not read (a platform bucket) is not served: the update fails,
#      and get-function-configuration answers LastUpdateStatus Failed (FunctionError) while the function
#      stays Active on its previous configuration, which still answers;
#   4. DENIAL: a principal no policy allows is refused create-function with AccessDeniedException.
# Everything the probe made is removed on exit.
#
# The layers are written on the function's claim (kubectl), as a tenant's tooling writes them: the Lambda
# API does not take Layers yet.
#
# Needs: aws (v2), kubectl (a cluster operator), python3; a deployed shim with the Lambda, IAM, STS and S3
# front doors, and the managed Node.js runtime. Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-lambda-layers.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
export AWS_REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
FN="llay-$SFX"; EXEC="llay-exec-$SFX"; BUCKET="llay-$SFX"

log()  { printf '▸ %s\n' "$*"; }
ok()   { printf '▸   ✓ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for t in aws kubectl python3 curl; do command -v "$t" >/dev/null || inconclusive "$t is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
W="$(mktemp -d)"
A=(aws --endpoint-url "$ENDPOINT" --no-cli-pager)

CREATED_USERS=(); CREATED_KEYS=(); ROLE_MADE=""; BUCKET_MADE=""
cleanup() {
  set +e
  unset AWS_SESSION_TOKEN
  [ -n "${ADMIN_AK:-}" ] && export AWS_ACCESS_KEY_ID="$ADMIN_AK" AWS_SECRET_ACCESS_KEY="$ADMIN_SK"
  "${A[@]}" lambda delete-function --function-name "$FN" >/dev/null 2>&1
  "${A[@]}" lambda delete-function --function-name "$FN-denied" >/dev/null 2>&1
  if [ -n "$BUCKET_MADE" ]; then
    "${A[@]}" s3 rm "s3://$BUCKET" --recursive >/dev/null 2>&1
    "${A[@]}" s3api delete-bucket --bucket "$BUCKET" >/dev/null 2>&1
  fi
  [ -n "$ROLE_MADE" ] && "${A[@]}" iam delete-role --role-name "$EXEC" >/dev/null 2>&1
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
  printf 'apiVersion: iam.openinfra.dev/v1\nkind: User\nmetadata: { name: "%s", namespace: "%s" }\nspec: { displayName: "%s", groups: [%s], source: local }\n' \
    "$owner" "$USERS_NS" "$owner" "$group" | kubectl apply -f - >/dev/null || inconclusive "could not mint User $owner"
  CREATED_USERS+=("$owner")
  kname="iam-ak-$(printf '%s' "$MK_AK" | sha256sum | cut -c1-40)"
  kubectl -n "$SHIM_NS" create secret generic "$kname" --from-literal=accessKeyId="$MK_AK" --from-literal=secretKey="$MK_SK" \
    --from-literal=owner="$owner" >/dev/null || inconclusive "could not mint a key for $owner"
  CREATED_KEYS+=("$kname")
}
mint_key "llay-admin-$SFX" '"admins"'
ADMIN_AK="$MK_AK"; ADMIN_SK="$MK_SK"
mint_key "llay-nobody-$SFX" ''
NOBODY_AK="$MK_AK"; NOBODY_SK="$MK_SK"
export AWS_ACCESS_KEY_ID="$ADMIN_AK" AWS_SECRET_ACCESS_KEY="$ADMIN_SK"
for i in $(seq 1 24); do
  "${A[@]}" sts get-caller-identity >/dev/null 2>&1 && break
  [ "$i" = 24 ] && inconclusive "the administrator's key never authenticated"
  sleep 5
done
sleep "${IAM_SETTLE_SECONDS:-35}"

"${A[@]}" iam create-role --role-name "$EXEC" --assume-role-policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
  >/dev/null 2>"$W/err" || inconclusive "iam create-role: $(tail -c 300 "$W/err")"
ROLE_MADE=1
EXEC_ARN="$("${A[@]}" iam get-role --role-name "$EXEC" --query Role.Arn --output text)"

# The function's package: its handler reports the credentials it saw at load and the layer's module.
python3 - "$W/fn.zip" "$W/layer.zip" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("index.js", """
const atLoad = { key: !!process.env.AWS_ACCESS_KEY_ID, secret: !!process.env.AWS_SECRET_ACCESS_KEY,
                 token: !!process.env.AWS_SESSION_TOKEN };
exports.handler = async () => {
  let layer = null;
  try { layer = require("oilayer").answer; } catch (e) { layer = null; }
  return { atLoad, layer };
};
""")
with zipfile.ZipFile(sys.argv[2], "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("nodejs/node_modules/oilayer/index.js", "exports.answer = 'from-the-layer';\n")
PY
"${A[@]}" s3api create-bucket --bucket "$BUCKET" >/dev/null 2>"$W/err" || inconclusive "create-bucket: $(tail -c 300 "$W/err")"
BUCKET_MADE=1
"${A[@]}" s3api put-object --bucket "$BUCKET" --key layer.zip --body "$W/layer.zip" >/dev/null 2>"$W/err" || inconclusive "put-object: $(tail -c 300 "$W/err")"

invoke() { "${A[@]}" --cli-read-timeout 200 lambda invoke --function-name "$FN" --cli-binary-format raw-in-base64-out --payload '{}' "$W/out.json" >/dev/null 2>"$W/inv.err"; }
# answers <python-expr over r>: wait (up to 4 min) until an invoke's answer satisfies it.
answers() {
  for _ in $(seq 1 48); do
    if invoke && python3 -c "import json,sys;r=json.load(open('$W/out.json'));sys.exit(0 if ($1) else 1)" 2>/dev/null; then return 0; fi
    sleep 5
  done
  return 1
}

log "1. create-function: not published, and the role's credentials are in the environment at load"
for i in $(seq 1 6); do
  "${A[@]}" lambda create-function --function-name "$FN" --runtime nodejs22.x --handler index.handler --role "$EXEC_ARN" \
    --zip-file "fileb://$W/fn.zip" --timeout 30 >/dev/null 2>"$W/err" && break
  [ "$i" = 6 ] && fail "create-function: $(tail -c 400 "$W/err")"
  sleep 10
done
NS="$(kubectl get functions.openinfra.dev -A -o jsonpath="{range .items[?(@.metadata.name==\"$FN\")]}{.metadata.namespace}{end}")"
[ -n "$NS" ] || fail "the function's claim is not found"
[ "$(kubectl -n "$NS" get functions.openinfra.dev "$FN" -o jsonpath='{.spec.expose}')" = "false" ] \
  || fail "a function the Lambda API creates must not be published on the gateway (spec.expose)"
answers 'r.get("atLoad") == {"key": True, "secret": True, "token": True}' \
  || fail "the handler did not see the role's credentials in its environment at load: $(cat "$W/out.json" 2>/dev/null) $(tail -c 300 "$W/inv.err")"
ok "not published (expose false); AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN set before the handler loaded"

log "2. a layer in the function's own account's bucket, fetched with the function's identity"
kubectl -n "$NS" patch functions.openinfra.dev "$FN" --type merge \
  -p "{\"spec\":{\"code\":{\"layers\":[{\"bucket\":\"$BUCKET\",\"key\":\"layer.zip\"}]}}}" >/dev/null || fail "could not add the layer to the claim"
answers 'r.get("layer") == "from-the-layer"' \
  || fail "the handler did not load the layer's module: $(cat "$W/out.json" 2>/dev/null) $(tail -c 300 "$W/inv.err")"
ok "the handler requires the layer's module from /opt"

log "3. a layer its account may not read: the update fails, reported as Lambda reports it"
kubectl -n "$NS" patch functions.openinfra.dev "$FN" --type merge \
  -p '{"spec":{"code":{"layers":[{"bucket":"lambda-code","key":"not-a-layer.zip"}]}}}' >/dev/null || fail "could not change the layer"
status=""
for _ in $(seq 1 72); do
  "${A[@]}" lambda get-function-configuration --function-name "$FN" --output json >"$W/cfg.json" 2>/dev/null
  status="$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); print(c.get("LastUpdateStatus",""), c.get("LastUpdateStatusReasonCode",""), c.get("State",""))' "$W/cfg.json" 2>/dev/null)"
  [ "$status" = "Failed FunctionError Active" ] && break
  sleep 10
done
[ "$status" = "Failed FunctionError Active" ] || fail "get-function-configuration answered '$status', want LastUpdateStatus Failed (FunctionError) on an Active function: $(head -c 400 "$W/cfg.json")"
answers 'r.get("layer") == "from-the-layer"' || fail "the function's previous configuration must still answer"
ok "LastUpdateStatus Failed (FunctionError), the function Active on its previous configuration, which answers"

log "4. DENIAL"
AWS_ACCESS_KEY_ID="$NOBODY_AK" AWS_SECRET_ACCESS_KEY="$NOBODY_SK" "${A[@]}" lambda create-function --function-name "$FN-denied" \
  --runtime nodejs22.x --handler index.handler --role "$EXEC_ARN" --zip-file "fileb://$W/fn.zip" >/dev/null 2>"$W/deny.err" \
  && fail "a principal no policy allows created a function"
grep -q AccessDeniedException "$W/deny.err" || fail "the refusal is not AccessDeniedException: $(tail -c 300 "$W/deny.err")"
ok "a principal no policy allows: create-function AccessDeniedException"

log "PASS — a function with a role and a stored package gets the role's credentials as Lambda hands them over, its own account's layers with its own identity, and a failed update is reported as Lambda reports it"
