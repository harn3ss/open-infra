#!/usr/bin/env bash
# Compatibility probe: an application's task role, as on ECS. Through the real AWS CLI (botocore's
# web-identity credential chain, in the application's own container):
#   - the IAM API creates a role trusting ecs-tasks.amazonaws.com whose only permission is sqs:SendMessage
#     on one queue (put-role-policy), and a second ECS-trusted role;
#   - a kind: Application names the role (spec.assumeRole); its code, with no keys configured, reports who
#     it is (sts get-caller-identity = assumed-role/<role>/<pod>, in the account), sends to the granted queue
#     (and the message arrives), and is AccessDenied sending to another queue and receiving from the
#     granted one (the role's policy grants neither);
#   - the app's environment names the role by its ARN in the account and the aws-shim's real address;
#   - another application, whose own role also trusts ECS, is AccessDenied assuming this app's role; a bare
#     pod running as the app's own ServiceAccount (not a pod of its Deployment) is AccessDenied; and the
#     app's identity token taken outside any pod (kubectl create token) is AccessDenied.
# Everything the probe made is removed on exit: the applications and the bare pod, both roles, both queues
# and the administrator's key.
#
# On-demand (a deployed shim with STS enabled — its sealing key — the SQS front door, Crossplane with the
# application composition, an image registry the cluster pulls the aws-cli image from, and kubectl as a
# cluster operator, who may pass any role). Exit 0 = pass, 1 = fail, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-app-assume-role.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
APP_NS="${APP_NAMESPACE:-default}"     # a namespace of the management account
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
# The address the applications reach the shim at (in-cluster): what the composition renders.
INCLUSTER_ENDPOINT="http://aws-shim.${SHIM_NS}.svc.cluster.local:4566"
REGION="${AWS_REGION:-us-east-1}"
SETTLE="${IAM_SETTLE_SECONDS:-35}"
APP_IMAGE="${APP_IMAGE:-docker.io/amazon/aws-cli:2.27.50}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"

APP="task-role-$SFX"; APP_OTHER="task-other-$SFX"; BORROW="task-borrow-$SFX"
ROLE="task-role-$SFX"; ROLE_OTHER="task-other-$SFX"
Q_OK="task-granted-$SFX"; Q_NO="task-denied-$SFX"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; FAILED=1; }
die()  { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }
FAILED=0

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
kubectl get applications.openinfra.dev -n "$APP_NS" >/dev/null 2>&1 || inconclusive "kind: Application is not installed"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

OWNER="task-admin-$SFX"; AK=""; SK=""; KS=""
M() { AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="" AWS_PAGER="" \
  aws --endpoint-url "$ENDPOINT" --region "$REGION" --cli-read-timeout 180 "$@"; }
cleanup() {
  kubectl -n "$APP_NS" delete pod "$BORROW" --ignore-not-found --wait=false >/dev/null 2>&1
  kubectl -n "$APP_NS" delete application.openinfra.dev "$APP" "$APP_OTHER" --ignore-not-found --wait=false >/dev/null 2>&1
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

# --- 2. two queues, the task role (sqs:SendMessage on one of them), a second ECS-trusted role -----------
log "creating queues ${Q_OK} (granted) and ${Q_NO}"
M sqs create-queue --queue-name "$Q_OK" --query QueueUrl --output text > "$TMP/qok" 2>"$TMP/err" || inconclusive "create-queue: $(cat "$TMP/err")"
M sqs create-queue --queue-name "$Q_NO" --query QueueUrl --output text > "$TMP/qno" 2>"$TMP/err" || inconclusive "create-queue: $(cat "$TMP/err")"
URL_OK="$(cat "$TMP/qok")"; URL_NO="$(cat "$TMP/qno")"

TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
SEND='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:'"$REGION"':'"$ACCOUNT"':'"$Q_OK"'"}]}'
log "creating role ${ROLE} (trusts ecs-tasks.amazonaws.com; sqs:SendMessage on ${Q_OK} only) and role ${ROLE_OTHER}"
for r in "$ROLE" "$ROLE_OTHER"; do
  M iam create-role --role-name "$r" --assume-role-policy-document "$TRUST" >/dev/null 2>"$TMP/err" \
    || die "create-role ${r} (a role trusting the ECS tasks service): $(cat "$TMP/err")"
  M iam put-role-policy --role-name "$r" --policy-name send --policy-document "$SEND" >/dev/null 2>"$TMP/err" \
    || die "put-role-policy ${r}: $(cat "$TMP/err")"
done
M iam get-role --role-name "$ROLE" --query 'Role.AssumeRolePolicyDocument' --output json > "$TMP/trust" 2>/dev/null
grep -q 'ecs-tasks.amazonaws.com' "$TMP/trust" || fail "get-role does not show the ECS tasks service trust: $(cat "$TMP/trust")"

# --- 3. the applications: one names the role (by ARN), one names the other role (by name) ---------------
app_yaml() { # <name> <role>
  printf 'apiVersion: openinfra.dev/v1\nkind: Application\nmetadata: { name: "%s", namespace: "%s" }\nspec:\n' "$1" "$APP_NS"
  printf '  image: "%s"\n  command: ["sleep", "infinity"]\n  scaling: { min: 1, max: 1 }\n  assumeRole: "%s"\n' "$APP_IMAGE" "$2"
}
log "creating Application ${APP} (assumeRole: arn:aws:iam::${ACCOUNT}:role/${ROLE}) and ${APP_OTHER} (assumeRole: ${ROLE_OTHER})"
app_yaml "$APP" "arn:aws:iam::${ACCOUNT}:role/${ROLE}" | kubectl apply -f - >/dev/null 2>"$TMP/err" \
  || die "creating an Application with a task role (an operator passes any role): $(cat "$TMP/err")"
app_yaml "$APP_OTHER" "$ROLE_OTHER" | kubectl apply -f - >/dev/null 2>"$TMP/err" || die "creating ${APP_OTHER}: $(cat "$TMP/err")"

for a in "$APP" "$APP_OTHER"; do
  for _ in $(seq 1 60); do kubectl -n "$APP_NS" get deploy "$a" >/dev/null 2>&1 && break; sleep 2; done
  kubectl -n "$APP_NS" get deploy "$a" >/dev/null 2>&1 || inconclusive "Application ${a}: its Deployment was not created (composition did not reconcile)"
  kubectl -n "$APP_NS" rollout status "deploy/$a" --timeout=300s >/dev/null 2>&1 \
    || inconclusive "Application ${a} did not roll out (the image ${APP_IMAGE} could not be pulled?)"
done
[ "$(kubectl -n "$APP_NS" get deploy "$APP" -o jsonpath='{.spec.template.spec.serviceAccountName}')" = "$APP" ] \
  || fail "the Application with a task role does not run as its own identity ${APP}"
kubectl -n "$APP_NS" get deploy "$APP" -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}' > "$TMP/env"
grep -qx "AWS_ROLE_ARN=arn:aws:iam::${ACCOUNT}:role/${ROLE}" "$TMP/env" || fail "AWS_ROLE_ARN is not the role's ARN in the account: $(grep AWS_ROLE_ARN "$TMP/env")"
grep -qx "AWS_ENDPOINT_URL_STS=${INCLUSTER_ENDPOINT}" "$TMP/env" || fail "AWS_ENDPOINT_URL_STS is not the aws-shim's address: $(grep AWS_ENDPOINT_URL_STS "$TMP/env")"
[ "$(kubectl -n "$APP_NS" get application "$APP" -o jsonpath='{.status.conditions[?(@.type=="RoleTrustsWorkload")].status}')" != "False" ] \
  || fail "the Application reports that its ECS-trusted role does not trust it"
sleep "$SETTLE"   # the role's policy reaches the shim's policy cache

# inapp <app> <shell script> -> its stdout+stderr in $TMP/out (the container's own env: no keys configured)
inapp() { kubectl -n "$APP_NS" exec "deploy/$1" -c app -- sh -c "$2" > "$TMP/out" 2>&1; }

# --- 4. the application acts as its role -----------------------------------------------------------------
log "the application's SDK, with no keys configured, is its task role's session (named after its pod)"
inapp "$APP" 'echo "$HOSTNAME"; aws sts get-caller-identity --query Arn --output text'
POD="$(sed -n 1p "$TMP/out")"; WHO="$(sed -n 2p "$TMP/out")"
[ -n "$POD" ] && [ "$WHO" = "arn:aws:sts::${ACCOUNT}:assumed-role/${ROLE}/${POD}" ] \
  || fail "get-caller-identity in the app = '$(cat "$TMP/out")', want arn:aws:sts::${ACCOUNT}:assumed-role/${ROLE}/<pod> — if AccessDenied, the shim may lack get on pods, replicasets, deployments or applications (aws-shim RBAC and the control-plane corpus)"
[ -n "$WHO" ] && log "  ✓ ${WHO}"

MARKER="task-role-$RANDOM$RANDOM"
log "ALLOW: the role sends to ${Q_OK}"
inapp "$APP" "aws sqs send-message --queue-url '${URL_OK}' --message-body '${MARKER}' --query MessageId --output text" \
  || fail "the role could not send to the granted queue: $(cat "$TMP/out")"
M sqs receive-message --queue-url "$URL_OK" --wait-time-seconds 5 --query 'Messages[].Body' --output text > "$TMP/recv" 2>/dev/null
grep -q "$MARKER" "$TMP/recv" || fail "the app's message did not arrive in ${Q_OK}: $(cat "$TMP/recv")"
log "DENY: the role sends to ${Q_NO}, and receives from ${Q_OK} (its policy grants neither)"
if inapp "$APP" "aws sqs send-message --queue-url '${URL_NO}' --message-body no"; then
  fail "sending to an ungranted queue must be AccessDenied, got: $(cat "$TMP/out")"
fi
grep -q 'AccessDenied' "$TMP/out" || fail "the refusal is not AccessDenied: $(cat "$TMP/out")"
if inapp "$APP" "aws sqs receive-message --queue-url '${URL_OK}' --wait-time-seconds 1"; then
  fail "an ungranted action must be AccessDenied, got: $(cat "$TMP/out")"
fi
grep -q 'AccessDenied' "$TMP/out" || fail "the refusal is not AccessDenied: $(cat "$TMP/out")"

# --- 5. nobody else assumes it ---------------------------------------------------------------------------
ROLE_ARN="arn:aws:iam::${ACCOUNT}:role/${ROLE}"
ASSUME='aws sts assume-role-with-web-identity --no-sign-request --endpoint-url "$AWS_ENDPOINT_URL_STS" --role-arn "'"$ROLE_ARN"'" --role-session-name probe --web-identity-token "$(cat "$AWS_WEB_IDENTITY_TOKEN_FILE")"'
log "DENY: another application, whose own role trusts ECS too, assumes ${ROLE}"
if inapp "$APP_OTHER" "$ASSUME"; then fail "another application assumed this app's role: $(cat "$TMP/out")"; fi
grep -q 'AccessDenied' "$TMP/out" || fail "another application's refusal is not AccessDenied: $(cat "$TMP/out")"

log "DENY: a bare pod running as the app's own ServiceAccount ${APP} (not a pod of its Deployment)"
cat <<YAML | kubectl apply -f - >/dev/null 2>"$TMP/err" || inconclusive "could not create the bare pod: $(cat "$TMP/err")"
apiVersion: v1
kind: Pod
metadata: { name: "${BORROW}", namespace: "${APP_NS}", labels: { app.kubernetes.io/name: "${APP}" } }
spec:
  serviceAccountName: "${APP}"
  restartPolicy: Never
  containers:
    - name: app
      image: "${APP_IMAGE}"
      command: ["sleep", "infinity"]
      env:
        - { name: AWS_WEB_IDENTITY_TOKEN_FILE, value: /var/run/secrets/openinfra/token }
        - { name: AWS_ENDPOINT_URL_STS, value: "${INCLUSTER_ENDPOINT}" }
        - { name: AWS_REGION, value: "${REGION}" }
      volumeMounts: [ { name: tok, mountPath: /var/run/secrets/openinfra, readOnly: true } ]
  volumes:
    - name: tok
      projected: { sources: [ { serviceAccountToken: { audience: sts.openinfra, expirationSeconds: 3600, path: token } } ] }
YAML
kubectl -n "$APP_NS" wait --for=condition=Ready "pod/$BORROW" --timeout=180s >/dev/null 2>&1 || inconclusive "the bare pod did not start"
if kubectl -n "$APP_NS" exec "$BORROW" -c app -- sh -c "$ASSUME" > "$TMP/out" 2>&1; then
  fail "a pod that only runs as the app's ServiceAccount assumed its ECS-trusted role: $(cat "$TMP/out")"
fi
grep -q 'AccessDenied' "$TMP/out" || fail "the bare pod's refusal is not AccessDenied: $(cat "$TMP/out")"

log "DENY: the app's identity token, taken outside any pod (kubectl create token)"
TOK="$(kubectl -n "$APP_NS" create token "$APP" --audience sts.openinfra --duration 10m 2>"$TMP/err")"
if [ -z "$TOK" ]; then
  log "  (skipped: kubectl create token: $(cat "$TMP/err"))"
else
  if env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u AWS_PROFILE AWS_PAGER="" \
      aws --endpoint-url "$ENDPOINT" --region "$REGION" sts assume-role-with-web-identity --role-arn "$ROLE_ARN" \
      --role-session-name borrowed --web-identity-token "$TOK" > "$TMP/borrow" 2>&1; then
    fail "a token of the app's identity, minted outside its pod, assumed the role: $(cat "$TMP/borrow")"
  fi
  grep -q 'AccessDenied' "$TMP/borrow" || fail "the borrowed token's refusal is not AccessDenied: $(cat "$TMP/borrow")"
fi

[ "$FAILED" = 0 ] || exit 1
echo
echo "✓ PASS — an application runs as its task role (exactly the role's policy, no keys), and no other workload can assume it."
