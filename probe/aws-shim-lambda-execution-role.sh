#!/usr/bin/env bash
# Compatibility probe: a Lambda function's execution role, as on AWS. Through the real AWS CLI and a
# real AWS SDK (boto3, in the function):
#   - the IAM API creates a role trusting lambda.amazonaws.com whose only permission is sqs:SendMessage
#     on one queue (put-role-policy), and a second Lambda-trusted role;
#   - a kind: Function names the role (spec.role); its handler, with no keys configured, reports who it is
#     (sts get-caller-identity = assumed-role/<role>/<function>, in the account), sends to the granted queue
#     (and the message arrives), and is AccessDenied sending to another queue and receiving from the
#     granted one (the role's policy grants neither);
#   - the function's configuration reports its Role (lambda get-function-configuration);
#   - another function, whose own role also trusts Lambda, is AccessDenied assuming this function's role;
#     a function with no role cannot assume it either (its token is not an identity STS takes); and the
#     function's identity token taken outside its pod (kubectl create token) is AccessDenied.
# Everything the probe made is removed on exit: the functions and their code, both roles, both queues and
# the administrator's key.
#
# On-demand (a deployed shim with STS enabled — its sealing key — the SQS and Lambda front doors, Knative
# Serving, the python3.12 runtime image, and kubectl as a cluster operator). Exit 0 = pass, 1 = fail,
# 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-lambda-execution-role.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
FN_NS="${FUNCTIONS_NAMESPACE:-default}"    # the Lambda API's namespace: Invoke finds the function there
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
# The address the functions reach the shim at (in-cluster), for the handler's own STS calls.
INCLUSTER_ENDPOINT="http://aws-shim.${SHIM_NS}.svc.cluster.local:4566"
REGION="${AWS_REGION:-us-east-1}"
SETTLE="${IAM_SETTLE_SECONDS:-35}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"

FN="exec-role-$SFX"; FN_OTHER="exec-other-$SFX"; FN_NONE="exec-none-$SFX"
ROLE="exec-role-$SFX"; ROLE_OTHER="exec-other-$SFX"
Q_OK="exec-granted-$SFX"; Q_NO="exec-denied-$SFX"
CODE="exec-role-code-$SFX"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; FAILED=1; }
die()  { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }
FAILED=0

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v python3 >/dev/null || inconclusive "python3 is required"
kubectl get ksvc -n "$FN_NS" >/dev/null 2>&1 || inconclusive "Knative Serving is not installed (kind: Function needs it)"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

OWNER="exec-admin-$SFX"; AK=""; SK=""; KS=""
M() { AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="" AWS_PAGER="" \
  aws --endpoint-url "$ENDPOINT" --region "$REGION" --cli-read-timeout 180 "$@"; }
cleanup() {
  kubectl -n "$FN_NS" delete function.openinfra.dev "$FN" "$FN_OTHER" "$FN_NONE" --ignore-not-found --wait=false >/dev/null 2>&1
  kubectl -n "$FN_NS" delete configmap "$CODE" --ignore-not-found >/dev/null 2>&1
  if [ -n "$AK" ]; then
    for r in "$ROLE" "$ROLE_OTHER"; do
      M iam delete-role-policy --role-name "$r" --policy-name send >/dev/null 2>&1
      M iam delete-role --role-name "$r" >/dev/null 2>&1
    done
    for q in "$Q_OK" "$Q_NO"; do
      url="$(M sqs get-queue-url --queue-name "$q" --query QueueUrl --output text 2>/dev/null)"
      [ -n "$url" ] && M sqs delete-queue --queue-url "$url" >/dev/null 2>&1
    done
  fi
  [ -n "$KS" ] && kubectl -n "$SHIM_NS" delete secret "$KS" --ignore-not-found >/dev/null 2>&1
  kubectl -n "$USERS_NS" delete users.iam.openinfra.dev "$OWNER" --ignore-not-found >/dev/null 2>&1
  rm -rf "$TMP"
  return 0
}
trap cleanup EXIT

# --- 1. the management account's administrator -------------------------------------------------------
AK="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
SK="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
KS="iam-ak-$(printf '%s' "$AK" | sha256sum | cut -c1-40)"
printf 'apiVersion: iam.openinfra.dev/v1\nkind: User\nmetadata: { name: "%s", namespace: "%s" }\nspec: { displayName: "%s", groups: ["admins"], source: local }\n' \
  "$OWNER" "$USERS_NS" "$OWNER" | kubectl apply -f - >/dev/null || inconclusive "could not create the administrator"
kubectl -n "$SHIM_NS" create secret generic "$KS" --from-literal=accessKeyId="$AK" --from-literal=secretKey="$SK" \
  --from-literal=owner="$OWNER" >/dev/null || inconclusive "could not create the administrator's key"
for _ in $(seq 1 20); do M sts get-caller-identity >/dev/null 2>&1 && break; sleep 3; done
sleep "$SETTLE"
ACCOUNT="$(M sts get-caller-identity --query Account --output text 2>/dev/null)"
[ -n "$ACCOUNT" ] || inconclusive "the administrator's key does not authenticate"

# --- 2. two queues, the execution role (sqs:SendMessage on one of them), a second Lambda-trusted role --
log "creating queues ${Q_OK} (granted) and ${Q_NO}"
M sqs create-queue --queue-name "$Q_OK" --query QueueUrl --output text > "$TMP/qok" 2>"$TMP/err" || inconclusive "create-queue: $(cat "$TMP/err")"
M sqs create-queue --queue-name "$Q_NO" --query QueueUrl --output text > "$TMP/qno" 2>"$TMP/err" || inconclusive "create-queue: $(cat "$TMP/err")"
URL_OK="$(cat "$TMP/qok")"; URL_NO="$(cat "$TMP/qno")"

TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
SEND='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:'"$REGION"':'"$ACCOUNT"':'"$Q_OK"'"}]}'
log "creating role ${ROLE} (trusts lambda.amazonaws.com; sqs:SendMessage on ${Q_OK} only) and role ${ROLE_OTHER}"
for r in "$ROLE" "$ROLE_OTHER"; do
  M iam create-role --role-name "$r" --assume-role-policy-document "$TRUST" >/dev/null 2>"$TMP/err" \
    || die "create-role ${r} (a role trusting the Lambda service): $(cat "$TMP/err")"
  M iam put-role-policy --role-name "$r" --policy-name send --policy-document "$SEND" >/dev/null 2>"$TMP/err" \
    || die "put-role-policy ${r}: $(cat "$TMP/err")"
done
M iam get-role --role-name "$ROLE" --query 'Role.AssumeRolePolicyDocument' --output json > "$TMP/trust" 2>/dev/null
grep -q 'lambda.amazonaws.com' "$TMP/trust" || fail "get-role does not show the Lambda service trust: $(cat "$TMP/trust")"

# --- 3. the functions: one names the role, one names the other role, one names none --------------------
cat > "$TMP/app.py" <<'PY'
import os

import boto3
from botocore.exceptions import ClientError


def _err(e):
    if isinstance(e, ClientError):
        return {"error": e.response.get("Error", {}).get("Code", "ClientError"), "message": str(e)}
    return {"error": type(e).__name__, "message": str(e)}


def handler(event, context):
    """The SDK finds the execution role's credentials on its own (no keys configured)."""
    op = event.get("op")
    try:
        if op == "whoami":
            return {"arn": boto3.client("sts").get_caller_identity()["Arn"]}
        if op == "send":
            r = boto3.client("sqs").send_message(QueueUrl=event["queue"], MessageBody=event["body"])
            return {"messageId": r["MessageId"]}
        if op == "receive":
            r = boto3.client("sqs").receive_message(QueueUrl=event["queue"], WaitTimeSeconds=1)
            return {"messages": len(r.get("Messages", []))}
        if op == "assume":
            # Present this pod's own token to STS for a role, as the SDK's web-identity provider does.
            path = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE") or "/var/run/secrets/kubernetes.io/serviceaccount/token"
            token = open(path).read().strip() if os.path.exists(path) else "no-token-in-this-pod"
            sts = boto3.client("sts", endpoint_url=event["endpoint"], region_name=os.environ.get("AWS_REGION", "us-east-1"))
            r = sts.assume_role_with_web_identity(RoleArn=event["role"], RoleSessionName="probe", WebIdentityToken=token)
            return {"arn": r["AssumedRoleUser"]["Arn"]}
    except Exception as e:  # report the SDK's error code to the probe
        return _err(e)
    return {"error": "unknown op " + str(op)}
PY
kubectl -n "$FN_NS" create configmap "$CODE" --from-file=app.py="$TMP/app.py" >/dev/null || inconclusive "could not create the handler ConfigMap"

fn_yaml() { # <name> <role or "">
  printf 'apiVersion: openinfra.dev/v1\nkind: Function\nmetadata: { name: "%s", namespace: "%s" }\nspec:\n  expose: false\n' "$1" "$FN_NS"
  [ -n "$2" ] && printf '  role: "%s"\n' "$2"
  printf '  code: { runtime: python3.12, handler: app.handler, source: { configMap: "%s" } }\n' "$CODE"
}
log "creating Function ${FN} (role: arn:aws:iam::${ACCOUNT}:role/${ROLE}), ${FN_OTHER} (role ${ROLE_OTHER}), ${FN_NONE} (no role)"
fn_yaml "$FN" "arn:aws:iam::${ACCOUNT}:role/${ROLE}" | kubectl apply -f - >/dev/null 2>"$TMP/err" \
  || die "creating a Function with an execution role (an operator passes any role): $(cat "$TMP/err")"
fn_yaml "$FN_OTHER" "$ROLE_OTHER" | kubectl apply -f - >/dev/null 2>"$TMP/err" || die "creating ${FN_OTHER}: $(cat "$TMP/err")"
fn_yaml "$FN_NONE" "" | kubectl apply -f - >/dev/null 2>"$TMP/err" || die "creating ${FN_NONE}: $(cat "$TMP/err")"

for f in "$FN" "$FN_OTHER" "$FN_NONE"; do
  for _ in $(seq 1 60); do kubectl -n "$FN_NS" get ksvc "$f" >/dev/null 2>&1 && break; sleep 2; done
  kubectl -n "$FN_NS" get ksvc "$f" >/dev/null 2>&1 || inconclusive "Function ${f}: its Knative Service was not created (composition did not reconcile)"
  kubectl -n "$FN_NS" wait --for=condition=Ready "ksvc/$f" --timeout=300s >/dev/null 2>&1 \
    || inconclusive "Function ${f} did not become Ready (Knative, or the python3.12 runtime image)"
done
[ "$(kubectl -n "$FN_NS" get ksvc "$FN" -o jsonpath='{.spec.template.spec.serviceAccountName}')" = "fn-$FN" ] \
  || fail "the Function with a role does not run as its own identity fn-${FN}"
sleep "$SETTLE"   # the role's policy reaches the shim's policy cache

# invoke <function> <payload> -> the handler's JSON answer in $TMP/out.json
invoke() {
  M lambda invoke --function-name "$1" --payload "$2" --cli-binary-format raw-in-base64-out "$TMP/out.json" >"$TMP/inv" 2>&1 \
    || { fail "lambda invoke $1: $(cat "$TMP/inv")"; echo '{}' > "$TMP/out.json"; }
}
field() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d=d.get("body",d) if isinstance(d,dict) else d; print((d or {}).get(sys.argv[2],""))' "$TMP/out.json" "$1" 2>/dev/null; }

# --- 4. the function acts as its role ------------------------------------------------------------------
log "the function's SDK, with no keys configured, is its execution role's session"
invoke "$FN" '{"op":"whoami"}'
WHO="$(field arn)"
[ "$WHO" = "arn:aws:sts::${ACCOUNT}:assumed-role/${ROLE}/${FN}" ] \
  || fail "get-caller-identity in the function = '${WHO}' (error: $(field error) $(field message)), want arn:aws:sts::${ACCOUNT}:assumed-role/${ROLE}/${FN} — if AccessDenied, the shim may lack get on pods, replicasets and deployments (aws-shim RBAC and the control-plane corpus)"
[ -n "$WHO" ] && log "  ✓ ${WHO}"

MARKER="exec-role-$RANDOM$RANDOM"
log "ALLOW: the role sends to ${Q_OK}"
invoke "$FN" "{\"op\":\"send\",\"queue\":\"${URL_OK}\",\"body\":\"${MARKER}\"}"
[ -n "$(field messageId)" ] || fail "the role could not send to the granted queue: $(field error) $(field message)"
M sqs receive-message --queue-url "$URL_OK" --wait-time-seconds 5 --query 'Messages[].Body' --output text > "$TMP/recv" 2>/dev/null
grep -q "$MARKER" "$TMP/recv" || fail "the function's message did not arrive in ${Q_OK}: $(cat "$TMP/recv")"
log "DENY: the role sends to ${Q_NO}, and receives from ${Q_OK} (its policy grants neither)"
invoke "$FN" "{\"op\":\"send\",\"queue\":\"${URL_NO}\",\"body\":\"no\"}"
case "$(field error)" in AccessDenied*) ;; *) fail "sending to an ungranted queue must be AccessDenied, got: $(cat "$TMP/out.json")" ;; esac
invoke "$FN" "{\"op\":\"receive\",\"queue\":\"${URL_OK}\"}"
case "$(field error)" in AccessDenied*) ;; *) fail "an ungranted action must be AccessDenied, got: $(cat "$TMP/out.json")" ;; esac

log "the function's configuration names its Role"
M lambda get-function-configuration --function-name "$FN" --query Role --output text > "$TMP/role" 2>&1
[ "$(cat "$TMP/role")" = "arn:aws:iam::${ACCOUNT}:role/${ROLE}" ] || fail "get-function-configuration Role = $(cat "$TMP/role")"

# --- 5. nobody else assumes it ---------------------------------------------------------------------------
ROLE_ARN="arn:aws:iam::${ACCOUNT}:role/${ROLE}"
log "DENY: another function, whose own role trusts Lambda too, assumes ${ROLE}"
invoke "$FN_OTHER" "{\"op\":\"assume\",\"role\":\"${ROLE_ARN}\",\"endpoint\":\"${INCLUSTER_ENDPOINT}\"}"
case "$(field error)" in AccessDenied*) ;; *) fail "another function assumed this function's role: $(cat "$TMP/out.json")" ;; esac
log "DENY: a function with no role assumes ${ROLE}"
invoke "$FN_NONE" "{\"op\":\"assume\",\"role\":\"${ROLE_ARN}\",\"endpoint\":\"${INCLUSTER_ENDPOINT}\"}"
case "$(field error)" in AccessDenied*|InvalidIdentityToken*) ;; *) fail "a role-less function assumed the role: $(cat "$TMP/out.json")" ;; esac
log "DENY: the function's identity token, taken outside its pod (kubectl create token)"
TOK="$(kubectl -n "$FN_NS" create token "fn-$FN" --audience sts.openinfra --duration 10m 2>"$TMP/err")"
if [ -z "$TOK" ]; then
  log "  (skipped: kubectl create token: $(cat "$TMP/err"))"
else
  if env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AWS_PROFILE AWS_PAGER="" \
      aws --endpoint-url "$ENDPOINT" --region "$REGION" sts assume-role-with-web-identity --role-arn "$ROLE_ARN" \
      --role-session-name borrowed --web-identity-token "$TOK" > "$TMP/borrow" 2>&1; then
    fail "a token of the function's identity, minted outside its pod, assumed the role: $(cat "$TMP/borrow")"
  fi
  grep -q 'AccessDenied' "$TMP/borrow" || fail "the borrowed token's refusal is not AccessDenied: $(cat "$TMP/borrow")"
fi

[ "$FAILED" = 0 ] || exit 1
echo
echo "✓ PASS — a function runs as its execution role (exactly the role's policy, no keys), and no other workload can assume it."
