#!/usr/bin/env bash
# Probe: Lambda versions and aliases, through the aws-shim with the real AWS CLI.
#
# Asserts:
#   1. create-function --publish answers version 1, and <function>:1 runs that code once it has rolled out;
#   2. after update-function-code, publish-version answers version 2 (retrying ResourceConflictException
#      while the update rolls out, as on Lambda); publishing again with nothing changed answers version 2;
#   3. each version runs its own code and reports it (ExecutedVersion): <function> and :$LATEST the latest,
#      :1 version 1, :2 version 2; a configuration change reaches $LATEST only (version 1 keeps its timeout);
#      the handler's context reports the ARN it was invoked by (with the qualifier) and the version that
#      runs (#406); --log-type Tail answers the invocation's log (START with its request ID and version, what
#      the handler printed, END, REPORT) in LogResult (#407);
#   4. a weighted alias (version 1, half to version 2) runs both versions, each reporting the alias's ARN;
#      get-alias and list-aliases answer it; an asynchronous (Event) invoke of the alias is accepted;
#   5. refusals, as Lambda refuses: deleting a version an alias names (ResourceConflictException), an alias of
#      a version the function lacks (ResourceNotFoundException), a weighted alias of $LATEST
#      (InvalidParameterValueException);
#   6. DENIAL: a principal allowed only to read and invoke is refused publish-version and create-alias with
#      AccessDeniedException;
#   7. delete-alias, then delete-function --qualifier 2 removes version 2 (list-versions-by-function).
#
# Needs: aws (v2), kubectl (to mint a throwaway admin, removed on exit), python3; a deployed shim with the
# Lambda, IAM and STS front doors. Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-lambda-versions.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
export AWS_REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
FN="lver-$SFX"; EXEC="lver-exec-$SFX"; READER="lver-reader-$SFX"

log()  { printf '▸ %s\n' "$*"; }
ok()   { printf '▸   ✓ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for t in aws kubectl python3; do command -v "$t" >/dev/null || inconclusive "$t is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
W="$(mktemp -d)"
A=(aws --endpoint-url "$ENDPOINT" --no-cli-pager)

CREATED_USERS=(); CREATED_KEYS=(); ROLES_MADE=()
cleanup() {
  set +e
  unset AWS_SESSION_TOKEN
  [ -n "${ADMIN_AK:-}" ] && export AWS_ACCESS_KEY_ID="$ADMIN_AK" AWS_SECRET_ACCESS_KEY="$ADMIN_SK"
  "${A[@]}" lambda delete-alias --function-name "$FN" --name live >/dev/null 2>&1
  "${A[@]}" lambda delete-function --function-name "$FN" >/dev/null 2>&1
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
  mint_key "lver-admin-$SFX" admins
  export AWS_ACCESS_KEY_ID="$MK_AK" AWS_SECRET_ACCESS_KEY="$MK_SK"
  log "minted a throwaway openinfra:admins caller (lver-admin-$SFX)"
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
EXEC_ARN="$("${A[@]}" iam get-role --role-name "$EXEC" --query Role.Arn --output text)"

# mkzip <file> <version>: a Node.js package whose handler prints a marker and answers its code's version and
# what its context says.
mkzip() {
  python3 - "$1" "$2" <<'PY'
import sys, zipfile
src = ("exports.handler = async (event, context) => { console.log('marker-v%s ' + context.awsRequestId); "
       "return { v: %s, arn: context.invokedFunctionArn, fv: context.functionVersion }; };\n") % (sys.argv[2], sys.argv[2])
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("index.js", src)
PY
}
mkzip "$W/v1.zip" 1; mkzip "$W/v2.zip" 2

# invoke <qualified-name>: one synchronous invoke; the answer in $W/out.json, the CLI's in $W/meta.json.
invoke() {
  "${A[@]}" --cli-read-timeout 200 lambda invoke --function-name "$1" --cli-binary-format raw-in-base64-out --payload '{}' \
    "$W/out.json" >"$W/meta.json" 2>"$W/inv.err"
}
# runs <qualified-name> <v> <executed>: wait (up to 3 min) until an invoke answers {"v": v}, ExecutedVersion executed.
runs() {
  for _ in $(seq 1 36); do
    if invoke "$1" && python3 -c "import json,sys;r=json.load(open('$W/out.json'));m=json.load(open('$W/meta.json'));sys.exit(0 if r.get('v')==$2 and m.get('ExecutedVersion')=='$3' else 1)" 2>/dev/null; then
      return 0
    fi
    sleep 5
  done
  return 1
}
# expect_error <code> <file> <what>
expect_error() { grep -q "$1" "$2" || fail "$3: $(tail -c 300 "$2")"; }

log "1. create-function --publish"
for i in $(seq 1 6); do # the role's trust reaches the shim within a few seconds of create-role
  "${A[@]}" lambda create-function --function-name "$FN" --runtime nodejs22.x --handler index.handler --role "$EXEC_ARN" \
    --zip-file "fileb://$W/v1.zip" --timeout 30 --publish >"$W/create.json" 2>"$W/create.err" && break
  [ "$i" = 6 ] && fail "create-function failed: $(tail -c 400 "$W/create.err")"
  sleep 10
done
python3 - "$W/create.json" <<'PY' || fail "create-function --publish did not answer version 1: $(cat "$W/create.json")"
import json, sys
c = json.load(open(sys.argv[1]))
assert c["Version"] == "1" and c["FunctionArn"].endswith(":1"), c
PY
runs "$FN:1" 1 1 || fail "version 1 never ran its code: $(cat "$W/out.json" 2>/dev/null) $(tail -c 300 "$W/inv.err")"
ok "version 1 published and running"

log "2. update-function-code, then publish-version"
"${A[@]}" lambda update-function-code --function-name "$FN" --zip-file "fileb://$W/v2.zip" >/dev/null 2>"$W/u2.err" \
  || fail "update-function-code failed: $(tail -c 400 "$W/u2.err")"
conflicts=0
for i in $(seq 1 36); do
  if "${A[@]}" lambda publish-version --function-name "$FN" --description second >"$W/pub.json" 2>"$W/pub.err"; then break; fi
  expect_error ResourceConflictException "$W/pub.err" "publish-version during an update must be ResourceConflictException"
  conflicts=$((conflicts + 1))
  [ "$i" = 36 ] && fail "publish-version never succeeded after the update rolled out"
  sleep 5
done
python3 -c "import json,sys;c=json.load(open('$W/pub.json'));sys.exit(0 if c['Version']=='2' and c['Description']=='second' else 1)" \
  || fail "publish-version did not answer version 2: $(cat "$W/pub.json")"
ok "version 2 published (ResourceConflictException $conflicts time(s) while the update rolled out)"
"${A[@]}" lambda publish-version --function-name "$FN" --query Version --output text >"$W/again" 2>"$W/again.err" \
  || fail "publishing an unchanged function failed: $(tail -c 300 "$W/again.err")"
[ "$(cat "$W/again")" = 2 ] || fail "publishing an unchanged function must answer version 2, got $(cat "$W/again")"
ok "publishing again with nothing changed answers version 2"

log "3. each version runs its own code"
runs "$FN" 2 '$LATEST' || fail "the function does not run version 2's code as \$LATEST: $(cat "$W/out.json") $(cat "$W/meta.json")"
runs "$FN:\$LATEST" 2 '$LATEST' || fail ":\$LATEST: $(cat "$W/out.json") $(cat "$W/meta.json")"
runs "$FN:1" 1 1 || fail ":1 does not run version 1: $(cat "$W/out.json") $(cat "$W/meta.json")"
runs "$FN:2" 2 2 || fail ":2 does not run version 2: $(cat "$W/out.json") $(cat "$W/meta.json")"
python3 - "$W/out.json" "$FN" <<'PY' || fail "the context of :2 does not report its ARN and version: $(cat "$W/out.json")"
import json, sys
r = json.load(open(sys.argv[1]))
assert r["arn"].startswith("arn:aws:lambda:") and r["arn"].endswith(":function:%s:2" % sys.argv[2]) and r["fv"] == "2", r
PY
ok "unqualified and \$LATEST run the latest, :1 version 1, :2 version 2, each reported as ExecutedVersion; :2's context names <arn>:2 and version 2"
"${A[@]}" lambda invoke --function-name "$FN:2" --log-type Tail --cli-binary-format raw-in-base64-out --payload '{}' \
  "$W/out.json" >"$W/meta.json" 2>"$W/inv.err" || fail "invoke --log-type Tail failed: $(tail -c 300 "$W/inv.err")"
python3 - "$W/meta.json" <<'PY' || fail "LogResult is not the invocation's log: $(cat "$W/meta.json")"
import base64, json, sys
m = json.load(open(sys.argv[1]))
log = base64.b64decode(m["LogResult"]).decode()
lines = log.splitlines()
rid = lines[0].split("START RequestId: ", 1)[1].split(" ", 1)[0]
assert lines[0] == "START RequestId: %s Version: 2" % rid, log
assert any(l.endswith("marker-v2 " + rid) for l in lines), log  # what the handler printed, with its awsRequestId
assert "END RequestId: " + rid in lines and lines[-1].startswith("REPORT RequestId: %s\tDuration: " % rid), log
PY
ok "--log-type Tail: LogResult holds START (request ID, version 2), the handler's marker, END and REPORT"
"${A[@]}" lambda update-function-configuration --function-name "$FN" --timeout 45 >/dev/null 2>"$W/u3.err" \
  || fail "update-function-configuration failed: $(tail -c 300 "$W/u3.err")"
[ "$("${A[@]}" lambda get-function-configuration --function-name "$FN" --query Timeout --output text)" = 45 ] || fail "\$LATEST's timeout did not change"
[ "$("${A[@]}" lambda get-function-configuration --function-name "$FN" --qualifier 1 --query Timeout --output text)" = 30 ] \
  || fail "version 1's timeout changed with \$LATEST's"
ok "a configuration change reaches \$LATEST only (version 1 keeps Timeout 30)"

log "4. a weighted alias"
"${A[@]}" lambda create-alias --function-name "$FN" --name live --function-version 1 \
  --routing-config 'AdditionalVersionWeights={"2"=0.5}' >"$W/alias.json" 2>"$W/alias.err" || fail "create-alias failed: $(tail -c 300 "$W/alias.err")"
python3 -c "import json,sys;a=json.load(open('$W/alias.json'));sys.exit(0 if a['FunctionVersion']=='1' and a['AliasArn'].endswith(':live') and a['RoutingConfig']['AdditionalVersionWeights']=={'2':0.5} else 1)" \
  || fail "the CreateAlias answer: $(cat "$W/alias.json")"
seen1=0; seen2=0
for _ in $(seq 1 20); do
  invoke "$FN:live" || fail "invoking the alias failed: $(tail -c 300 "$W/inv.err")"
  python3 -c "import json,sys;r=json.load(open('$W/out.json'));m=json.load(open('$W/meta.json'));sys.exit(0 if r['arn'].endswith(':live') and r['fv']==m['ExecutedVersion'] else 1)" \
    || fail "the alias's context must report the alias's ARN and the version that ran: $(cat "$W/out.json") $(cat "$W/meta.json")"
  case "$(python3 -c "import json;print(json.load(open('$W/meta.json')).get('ExecutedVersion'))")" in
    1) seen1=$((seen1 + 1)) ;; 2) seen2=$((seen2 + 1)) ;; *) fail "the alias ran something else: $(cat "$W/meta.json")" ;;
  esac
done
[ "$seen1" -gt 0 ] && [ "$seen2" -gt 0 ] || fail "a half-and-half alias ran version 1 $seen1 and version 2 $seen2 times of 20"
ok "the alias ran version 1 $seen1 and version 2 $seen2 times of 20"
[ "$("${A[@]}" lambda get-alias --function-name "$FN" --name live --query FunctionVersion --output text)" = 1 ] || fail "get-alias"
[ "$("${A[@]}" lambda list-aliases --function-name "$FN" --query 'length(Aliases)' --output text)" = 1 ] || fail "list-aliases"
"${A[@]}" lambda invoke --function-name "$FN:live" --invocation-type Event --cli-binary-format raw-in-base64-out --payload '{}' "$W/ev.json" \
  --query StatusCode --output text >"$W/ev" 2>"$W/ev.err" || fail "an Event invoke of the alias failed: $(tail -c 300 "$W/ev.err")"
[ "$(cat "$W/ev")" = 202 ] || fail "an Event invoke of the alias must be accepted (202), got $(cat "$W/ev")"
ok "get-alias and list-aliases answer it; an Event invoke of the alias is accepted"

log "5. refusals, as Lambda refuses"
if "${A[@]}" lambda delete-function --function-name "$FN" --qualifier 1 >/dev/null 2>"$W/r1.err"; then fail "a version an alias names was deleted"; fi
expect_error ResourceConflictException "$W/r1.err" "deleting a version an alias names"
if "${A[@]}" lambda create-alias --function-name "$FN" --name beta --function-version 9 >/dev/null 2>"$W/r2.err"; then fail "an alias of a missing version was made"; fi
expect_error ResourceNotFoundException "$W/r2.err" "an alias of a version the function lacks"
if "${A[@]}" lambda create-alias --function-name "$FN" --name beta --function-version '$LATEST' \
     --routing-config 'AdditionalVersionWeights={"1"=0.1}' >/dev/null 2>"$W/r3.err"; then fail "a weighted alias of \$LATEST was made"; fi
expect_error InvalidParameterValueException "$W/r3.err" "a weighted alias of \$LATEST"
ok "ResourceConflictException, ResourceNotFoundException, InvalidParameterValueException"

log "6. DENIAL: read and invoke only"
role "$READER" "{\"AWS\":\"$ME\"}" '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["lambda:GetFunction","lambda:InvokeFunction","lambda:ListVersionsByFunction"],"Resource":"*"}]}'
READER_ARN="$("${A[@]}" iam get-role --role-name "$READER" --query Role.Arn --output text)"
for i in $(seq 1 24); do
  dec="$("${A[@]}" iam simulate-principal-policy --policy-source-arn "$READER_ARN" --action-names lambda:GetFunction \
          --query 'EvaluationResults[0].EvalDecision' --output text 2>/dev/null || true)"
  [ "$dec" = allowed ] && break
  [ "$i" = 24 ] && inconclusive "the reader's policy did not take effect within 2 minutes"
  sleep 5
done
creds="$("${A[@]}" sts assume-role --role-arn "$READER_ARN" --role-session-name lver --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text)" \
  || inconclusive "sts assume-role failed"
read -r SAK SSK SST <<<"$creds"
as_session() { AWS_ACCESS_KEY_ID="$SAK" AWS_SECRET_ACCESS_KEY="$SSK" AWS_SESSION_TOKEN="$SST" "${A[@]}" "$@"; }
as_session lambda list-versions-by-function --function-name "$FN" >/dev/null 2>"$W/d0.err" \
  || fail "the reader may list versions: $(tail -c 300 "$W/d0.err")"
if as_session lambda publish-version --function-name "$FN" >/dev/null 2>"$W/d1.err"; then fail "a read-only principal published a version"; fi
expect_error AccessDeniedException "$W/d1.err" "the PublishVersion refusal is not AccessDeniedException"
if as_session lambda create-alias --function-name "$FN" --name denied --function-version 1 >/dev/null 2>"$W/d2.err"; then fail "a read-only principal made an alias"; fi
expect_error AccessDeniedException "$W/d2.err" "the CreateAlias refusal is not AccessDeniedException"
ok "publish-version and create-alias refused with AccessDeniedException; list-versions-by-function allowed"

log "7. delete-alias and a version"
"${A[@]}" lambda delete-alias --function-name "$FN" --name live 2>"$W/da.err" || fail "delete-alias failed: $(tail -c 300 "$W/da.err")"
"${A[@]}" lambda delete-function --function-name "$FN" --qualifier 2 2>"$W/dv.err" || fail "deleting version 2 failed: $(tail -c 300 "$W/dv.err")"
[ "$("${A[@]}" lambda list-versions-by-function --function-name "$FN" --query 'join(`,`, Versions[].Version)' --output text)" = '$LATEST,1' ] \
  || fail "after deleting version 2 the versions are not \$LATEST,1"
if "${A[@]}" lambda get-function --function-name "$FN" --qualifier 2 >/dev/null 2>"$W/g2.err"; then fail "version 2 is still there"; fi
expect_error ResourceNotFoundException "$W/g2.err" "a deleted version must be ResourceNotFoundException"
ok "the alias and version 2 deleted; the versions are \$LATEST and 1"

printf '✓ PASS — Lambda versions and aliases: publish (on create and after an update, ResourceConflictException while it rolls out), each version runs its own code and reports it (ExecutedVersion, and the handler'"'"'s context: the invoked ARN and version), --log-type Tail answers the invocation'"'"'s log, a configuration change reaches $LATEST only, a weighted alias runs both versions, the refusals are Lambda'"'"'s, and publish-version and create-alias are denied without their permissions\n'
