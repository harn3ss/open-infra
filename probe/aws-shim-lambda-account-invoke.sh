#!/usr/bin/env bash
# Probe: Lambda Invoke reaches a member account's functions in its own namespaces, as AWS reaches a function
# in its account, authorized by the caller's lambda:InvokeFunction on the named functions alone (#412).
#
# Through the real AWS CLI:
#   1. the management account's administrator creates a throwaway member account (Organizations
#      CreateAccount) and assumes its OrganizationAccountAccessRole;
#   2. in the member account: an execution role, a function made with CreateFunction (fn-api), a function
#      written straight into the account's home as a kind: Function (fn-claim, the way a migration tool
#      writes one), a third function (fn-other), and a user whose only policy allows lambda:InvokeFunction on
#      fn-api and fn-claim by ARN;
#   3. as that user: a signed Invoke of fn-api and of fn-claim returns each handler's raw result;
#   4. DENIAL: the user's Invoke of fn-other is AccessDeniedException; so is GetFunction on fn-api (not
#      granted); an unsigned Invoke and one signed with a wrong secret are refused, never run.
# Everything the probe made is removed on exit: the functions, the user, the role, the member account and
# its home namespace (only when this run created it), and the administrator's key.
#
# Needs: aws (v2), kubectl (a cluster operator), curl, python3; a deployed shim with the Organizations,
# STS, IAM and Lambda front doors. Exit 0 = pass, 1 = fail, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-lambda-account-invoke.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SETTLE="${IAM_SETTLE_SECONDS:-35}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
NAME="linv-$SFX"
TMP="$(mktemp -d)"
START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

log()  { printf '▸ %s\n' "$*"; }
ok()   { printf '▸   ✓ %s\n' "$*"; }
die()  { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for t in aws kubectl curl python3; do command -v "$t" >/dev/null || inconclusive "$t is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
kubectl get crd accounts.organizations.openinfra.dev >/dev/null 2>&1 || inconclusive "the Account kind is not installed"

OWNER="linv-admin-$SFX"; AK=""; SK=""; KS=""; NEW_ACCOUNT=""; NEW_HOME=""
CLEAN=() # commands run on exit, in reverse
cleanup() {
  local i
  for ((i=${#CLEAN[@]}-1; i>=0; i--)); do eval "${CLEAN[$i]}" >/dev/null 2>&1 || true; done
  [ -n "$NEW_ACCOUNT" ] && kubectl delete accounts.organizations.openinfra.dev "$NEW_ACCOUNT" --ignore-not-found --wait=false >/dev/null 2>&1
  if [ -n "$NEW_HOME" ]; then
    created="$(kubectl get ns "$NEW_HOME" -o jsonpath='{.metadata.creationTimestamp}' 2>/dev/null)"
    if [ -n "$created" ] && [[ "$created" > "$START" || "$created" == "$START" ]]; then
      kubectl delete ns "$NEW_HOME" --ignore-not-found --wait=false >/dev/null 2>&1
    fi
  fi
  [ -n "$KS" ] && kubectl -n "$SHIM_NS" delete secret "$KS" --ignore-not-found >/dev/null 2>&1
  kubectl -n "$USERS_NS" delete users.iam.openinfra.dev "$OWNER" --ignore-not-found >/dev/null 2>&1
  rm -rf "$TMP"
  return 0
}
trap cleanup EXIT

# --- 1. the management account's administrator, and a member account ---------------------------------
AK="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
SK="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
KS="iam-ak-$(printf '%s' "$AK" | sha256sum | cut -c1-40)"
printf 'apiVersion: iam.openinfra.dev/v1\nkind: User\nmetadata: { name: "%s", namespace: "%s" }\nspec: { displayName: "%s", groups: ["admins"], source: local }\n' \
  "$OWNER" "$USERS_NS" "$OWNER" | kubectl apply -f - >/dev/null || inconclusive "could not create the administrator"
kubectl -n "$SHIM_NS" create secret generic "$KS" --from-literal=accessKeyId="$AK" --from-literal=secretKey="$SK" \
  --from-literal=owner="$OWNER" >/dev/null || inconclusive "could not create the administrator's key"
M() { AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" "$@"; }
for _ in $(seq 1 20); do M sts get-caller-identity >/dev/null 2>&1 && break; sleep 3; done
sleep "$SETTLE"
M sts get-caller-identity >/dev/null 2>&1 || inconclusive "the administrator's key does not authenticate"

log "1. a member account, and its OrganizationAccountAccessRole"
car="$(M organizations create-account --email "$NAME@example.com" --account-name "$NAME" --query 'CreateAccountStatus.Id' --output text 2>"$TMP/err")" \
  || inconclusive "create-account: $(tr '\n' ' ' < "$TMP/err")"
for _ in $(seq 1 60); do
  read -r state acct < <(M organizations describe-create-account-status --create-account-request-id "$car" \
    --query 'CreateAccountStatus.[State,AccountId]' --output text 2>/dev/null)
  [ "$state" = SUCCEEDED ] && NEW_ACCOUNT="$acct" && break
  [ "$state" = FAILED ] && inconclusive "create-account FAILED"
  sleep 5
done
[ -n "$NEW_ACCOUNT" ] || inconclusive "the member account was not created"
NEW_HOME="$(kubectl get accounts.organizations.openinfra.dev "$NEW_ACCOUNT" -o jsonpath='{.spec.namespaces[0]}' 2>/dev/null)"
for _ in $(seq 1 60); do
  [ "$(kubectl -n "$NEW_HOME" get roles.iam.openinfra.dev organizationaccountaccessrole \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = True ] && break
  sleep 5
done
sleep "$SETTLE"
M sts assume-role --role-arn "arn:aws:iam::$NEW_ACCOUNT:role/OrganizationAccountAccessRole" \
  --role-session-name linv --output json > "$TMP/session.json" 2>"$TMP/err" \
  || die "assume-role into the member account: $(tr '\n' ' ' < "$TMP/err")"
read -r MAK MSK MST < <(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["Credentials"]; print(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"])' "$TMP/session.json")
B() { AWS_ACCESS_KEY_ID="$MAK" AWS_SECRET_ACCESS_KEY="$MSK" AWS_SESSION_TOKEN="$MST" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" "$@"; }
[ "$(B sts get-caller-identity --query Account --output text 2>/dev/null)" = "$NEW_ACCOUNT" ] || die "the assumed session is not the member account's"
ok "acting in member account $NEW_ACCOUNT (home $NEW_HOME)"

log "2. three functions and a user allowed to invoke two of them"
cat >"$TMP/index.py" <<'PY'
import os
def handler(event, context):
    return {"function": os.environ.get("AWS_LAMBDA_FUNCTION_NAME"), "echo": event}
PY
(cd "$TMP" && python3 -c "import zipfile;z=zipfile.ZipFile('fn.zip','w');z.write('index.py');z.close()")
B iam create-role --role-name "$NAME-exec" --assume-role-policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
  >/dev/null 2>"$TMP/err" || die "create-role: $(cat "$TMP/err")"
CLEAN+=("B iam delete-role --role-name $NAME-exec")
sleep 10
for fn in "$NAME-api" "$NAME-other"; do
  for i in $(seq 1 6); do
    B lambda create-function --function-name "$fn" --runtime python3.12 --handler index.handler \
      --role "arn:aws:iam::$NEW_ACCOUNT:role/$NAME-exec" --zip-file "fileb://$TMP/fn.zip" --timeout 30 >/dev/null 2>"$TMP/err" && break
    [ "$i" = 6 ] && die "create-function $fn: $(cat "$TMP/err")"
    sleep 10
  done
  CLEAN+=("B lambda delete-function --function-name $fn")
done
kubectl -n "$NEW_HOME" get function.openinfra.dev "$NAME-api" >/dev/null 2>&1 || die "CreateFunction did not put $NAME-api in the account's home"
kubectl -n "$NEW_HOME" create configmap "$NAME-claim-code" --from-file=index.py="$TMP/index.py" >/dev/null || die "configmap"
printf 'apiVersion: openinfra.dev/v1\nkind: Function\nmetadata: { name: "%s", namespace: "%s" }\nspec:\n  timeout: 30\n  code: { runtime: python3.12, handler: index.handler, source: { configMap: "%s" } }\n' \
  "$NAME-claim" "$NEW_HOME" "$NAME-claim-code" | kubectl apply -f - >/dev/null || die "could not write $NAME-claim"
CLEAN+=("kubectl -n $NEW_HOME delete function.openinfra.dev $NAME-claim --wait=false; kubectl -n $NEW_HOME delete configmap $NAME-claim-code")
B iam create-user --user-name "$NAME-tester" >/dev/null 2>"$TMP/err" || die "create-user: $(cat "$TMP/err")"
CLEAN+=("B iam delete-user --user-name $NAME-tester")
B iam put-user-policy --user-name "$NAME-tester" --policy-name invoke-two --policy-document \
  "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"lambda:InvokeFunction\",\"Resource\":[\"arn:aws:lambda:$REGION:$NEW_ACCOUNT:function:$NAME-api\",\"arn:aws:lambda:$REGION:$NEW_ACCOUNT:function:$NAME-claim\"]}]}" \
  >/dev/null 2>"$TMP/err" || die "put-user-policy: $(cat "$TMP/err")"
CLEAN+=("B iam delete-user-policy --user-name $NAME-tester --policy-name invoke-two")
B iam create-access-key --user-name "$NAME-tester" --output json >"$TMP/key.json" 2>"$TMP/err" || die "create-access-key: $(cat "$TMP/err")"
read -r TAK TSK < <(python3 -c 'import json,sys; k=json.load(open(sys.argv[1]))["AccessKey"]; print(k["AccessKeyId"], k["SecretAccessKey"])' "$TMP/key.json")
CLEAN+=("B iam delete-access-key --user-name $NAME-tester --access-key-id $TAK")
T() { AWS_ACCESS_KEY_ID="$TAK" AWS_SECRET_ACCESS_KEY="$TSK" AWS_SESSION_TOKEN="" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" "$@"; }
ok "$NAME-api (CreateFunction), $NAME-claim (a kind: Function in the home), $NAME-other; $NAME-tester may invoke the first two only"
sleep "$SETTLE"

log "3. the user invokes the two functions it may invoke"
invoke_as_tester() { # invoke_as_tester <function>: until the function answers (cold start) or 4 min
  for _ in $(seq 1 24); do
    T --cli-read-timeout 120 lambda invoke --function-name "$1" --cli-binary-format raw-in-base64-out \
      --payload "{\"probe\":\"$SFX\"}" "$TMP/$1.out" >"$TMP/$1.meta" 2>"$TMP/$1.err" && return 0
    grep -q AccessDeniedException "$TMP/$1.err" && return 1
    sleep 10
  done
  return 1
}
for fn in "$NAME-api" "$NAME-claim"; do
  invoke_as_tester "$fn" || die "the user's Invoke of $fn: $(tail -c 400 "$TMP/$fn.err")"
  python3 - "$TMP/$fn.out" "$fn" "$SFX" <<'PY' || die "$fn did not return its handler's raw result: $(cat "$TMP/$fn.out")"
import json, sys
r = json.load(open(sys.argv[1]))
assert r == {"function": sys.argv[2], "echo": {"probe": sys.argv[3]}}, r
PY
  ok "$fn: a signed Invoke returns the handler's raw result"
done

log "4. DENIAL"
T lambda invoke --function-name "$NAME-other" --payload '{}' --cli-binary-format raw-in-base64-out "$TMP/o.out" >/dev/null 2>"$TMP/o.err" \
  && die "the user invoked $NAME-other, which its policy does not name"
grep -q AccessDeniedException "$TMP/o.err" || die "the refusal of $NAME-other is not AccessDeniedException: $(tail -c 300 "$TMP/o.err")"
T lambda get-function --function-name "$NAME-api" >/dev/null 2>"$TMP/g.err" && die "the user read $NAME-api, which its policy does not allow"
grep -q AccessDeniedException "$TMP/g.err" || die "the GetFunction refusal is not AccessDeniedException: $(tail -c 300 "$TMP/g.err")"
code="$(curl -s -o "$TMP/unsigned" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' \
  "$ENDPOINT/2015-03-31/functions/$NAME-api/invocations")"
case "$code" in 2*) die "an unsigned Invoke was answered $code: $(head -c 300 "$TMP/unsigned")";; esac
grep -q '"function"' "$TMP/unsigned" && die "an unsigned Invoke ran the function"
AWS_ACCESS_KEY_ID="$TAK" AWS_SECRET_ACCESS_KEY="not-the-secret-$SFX" AWS_SESSION_TOKEN="" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" \
  lambda invoke --function-name "$NAME-api" --payload '{}' --cli-binary-format raw-in-base64-out "$TMP/w.out" >/dev/null 2>"$TMP/w.err" \
  && die "an Invoke signed with a wrong secret ran"
grep -qE 'InvalidSignatureException|SignatureDoesNotMatch|UnrecognizedClient|AccessDenied' "$TMP/w.err" || die "the wrong-secret refusal is not AWS's: $(tail -c 300 "$TMP/w.err")"
ok "$NAME-other: AccessDeniedException; GetFunction: AccessDeniedException; unsigned: HTTP $code, not run; wrong secret: $(grep -oE 'InvalidSignatureException|SignatureDoesNotMatch|UnrecognizedClient[A-Za-z]*|AccessDenied[A-Za-z]*' "$TMP/w.err" | head -1)"

log "PASS — a member account's principal invokes the account's named functions, in its own namespace, and nothing else"
