#!/usr/bin/env bash
# Compatibility probe for the aws-shim Step Functions surface (polyhedron#172).
#
# It asserts, over real round-trips against a deployed shim + the singleton statemachine controller:
#   - CreateStateMachine validates + STORES an AWS-authored ASL definition, and StartExecution runs it
#   - a Task, a Choice branch, a Wait, Retry (with backoff) and Catch all execute correctly (Succeeded)
#   - EXECUTION-ROLE AUTHORITY (the confused-deputy fix, with #168): a Task runs under the state machine's
#     role — the injected STS session is a REAL role session (get-caller-identity = the assumed role) that
#     can do EXACTLY what the role's policy grants (GetObject the granted bucket) and is DENIED what it does
#     not (a different bucket). A controller that ran Tasks under its own ambient authority would fail this.
#   - StopExecution aborts a running execution (status → ABORTED)
#   - GetExecutionHistory / DescribeExecution reflect the REAL transitions (a retry + a catch happened)
# and the NEGATIVES:
#   - StartExecution under a role whose trust does NOT name the caller → AccessDenied (the PassRole gate)
#   - CreateStateMachine with an unsupported ASL feature (Parallel) → InvalidDefinition (refused, not faked)
#
# On-demand (needs a deployed shim + STS AssumeRole enabled + MinIO/S3 + the IAM CRDs + the statemachine
# controller + an openinfra:admins caller). Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 MINIO_ENDPOINT=http://localhost:9000 ./probe/aws-shim-stepfunctions.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
ACCOUNT="${ACCOUNT_ID:-open-infra}"
ECHO_IMG="${SFN_ECHO_IMAGE:-mendhak/http-https-echo:37}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v python3 >/dev/null || inconclusive "python3 is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

ECHO_NAME="sfn-echo-$SFX"
SM_NAME="sfn-probe-$SFX"
SM_NOTRUST="sfn-notrust-$SFX"
ROLE="sfn-role-$SFX"; NOTRUST_ROLE="sfn-notrust-role-$SFX"
POL="sfn-pol-$SFX"
BUCKET_X="sfn-granted-$SFX"; BUCKET_Y="sfn-denied-$SFX"
CREATED_KEYS=(); CREATED_USERS=(); CREATED_EXECS=(); CREATED_BUCKETS=()
AAK=""; ASK=""

sfn()  { AWS_ACCESS_KEY_ID="$AAK" AWS_SECRET_ACCESS_KEY="$ASK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager stepfunctions "$@"; }
iam()  { AWS_ACCESS_KEY_ID="$AAK" AWS_SECRET_ACCESS_KEY="$ASK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text iam "$@"; }
s3op() { local ak="$1" sk="$2" tok="${3:-}"; shift 3; AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_SESSION_TOKEN="$tok" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager s3api "$@"; }

cleanup() {
  sfn delete-state-machine --state-machine-arn "arn:aws:states:${REGION}:${ACCOUNT}:stateMachine:${SM_NAME}" >/dev/null 2>&1 || true
  sfn delete-state-machine --state-machine-arn "arn:aws:states:${REGION}:${ACCOUNT}:stateMachine:${SM_NOTRUST}" >/dev/null 2>&1 || true
  for e in "${CREATED_EXECS[@]:-}"; do [ -n "$e" ] && kubectl -n "$SHIM_NS" delete execution.openinfra.dev "$e" --ignore-not-found >/dev/null 2>&1 || true; done
  kubectl -n "$SHIM_NS" delete secret -l openinfra.dev/statemachine-creds=true >/dev/null 2>&1 || true
  kubectl -n "$SHIM_NS" delete deployment,service "$ECHO_NAME" --ignore-not-found >/dev/null 2>&1 || true
  iam delete-role --role-name "$ROLE" >/dev/null 2>&1 || true
  iam delete-role --role-name "$NOTRUST_ROLE" >/dev/null 2>&1 || true
  iam delete-policy --policy-arn "arn:aws:iam::${ACCOUNT}:policy/${POL}" >/dev/null 2>&1 || true
  kubectl -n "$USERS_NS" delete role.iam.openinfra.dev "$ROLE" "$NOTRUST_ROLE" --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev "$POL" "role-${ROLE}-"* "role-${NOTRUST_ROLE}-"* --ignore-not-found >/dev/null 2>&1 || true
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for k in "${CREATED_KEYS[@]:-}";  do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
  if [ -n "${MINIO_USER:-}" ]; then
    for b in "${CREATED_BUCKETS[@]:-}"; do [ -n "$b" ] && { minio_s3 delete-object --bucket "$b" --key obj >/dev/null 2>&1; minio_s3 delete-bucket --bucket "$b" >/dev/null 2>&1; } || true; done
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }
mint_key() { # <owner> <group> -> "AK SK"
  local owner="$1" group="$2"
  local ak="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  local sk; sk="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "${owner}", namespace: "${USERS_NS}" }
spec: { displayName: "${owner}", groups: ["${group}"], source: local }
YAML
  CREATED_USERS+=("$owner")
  local name; name="$(secret_name "$ak")"
  kubectl -n "$SHIM_NS" create secret generic "$name" --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  CREATED_KEYS+=("$name")
  printf '%s %s' "$ak" "$sk"
}

# --- 1. admin caller -------------------------------------------------------------------------------
log "seeding an openinfra:admins caller + key"
ADMIN="sfn-admin-$SFX"
read -r AAK ASK <<<"$(mint_key "$ADMIN" "admins")"
[ -n "$AAK" ] && [ -n "$ASK" ] || inconclusive "failed to mint an admin key"
sleep 2

# --- 2. deploy a plain echo Service (the Task target). function:<name> resolves to <name>.<ns>.svc ---
log "deploying echo Task target ${ECHO_NAME} (${ECHO_IMG})"
cat <<YAML | kubectl apply -f - >/dev/null || inconclusive "could not deploy the echo service"
apiVersion: apps/v1
kind: Deployment
metadata: { name: "${ECHO_NAME}", namespace: "${SHIM_NS}", labels: { app: "${ECHO_NAME}" } }
spec:
  replicas: 1
  selector: { matchLabels: { app: "${ECHO_NAME}" } }
  template:
    metadata: { labels: { app: "${ECHO_NAME}" } }
    spec:
      containers:
        - name: echo
          image: "${ECHO_IMG}"
          env: [ { name: HTTP_PORT, value: "8080" }, { name: LOG_WITHOUT_NEWLINE, value: "true" } ]
          ports: [ { containerPort: 8080 } ]
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            seccompProfile: { type: RuntimeDefault }
            capabilities: { drop: [ALL] }
---
apiVersion: v1
kind: Service
metadata: { name: "${ECHO_NAME}", namespace: "${SHIM_NS}" }
spec:
  selector: { app: "${ECHO_NAME}" }
  ports: [ { port: 80, targetPort: 8080 } ]
YAML
kubectl -n "$SHIM_NS" rollout status deployment/"$ECHO_NAME" --timeout=120s >/dev/null 2>&1 || inconclusive "echo service did not become ready"

# --- 3. policy (s3:GetObject on granted bucket) + role (trust: account, so the admin caller may pass) ---
log "create-policy ${POL} (Allow s3:GetObject on ${BUCKET_X}) + role ${ROLE} (trusts the account)"
POLDOC='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::'"$BUCKET_X"'/*"}]}'
POL_ARN="$(iam create-policy --policy-name "$POL" --policy-document "$POLDOC" --query 'Policy.Arn' 2>"$TMP/cp" || true)"
[ -n "$POL_ARN" ] && [ "$POL_ARN" != "None" ] || inconclusive "create-policy failed (admin caller + shim IAM RBAC?): $(cat "$TMP/cp" 2>/dev/null)"
# trust the account root → any caller in the account may run executions under this role (the happy path).
TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::'"$ACCOUNT"':root"},"Action":"sts:AssumeRole"}]}'
iam create-role --role-name "$ROLE" --assume-role-policy-document "$TRUST" >/dev/null 2>&1 || fail "create-role failed"
iam attach-role-policy --role-name "$ROLE" --policy-arn "$POL_ARN" >/dev/null 2>&1 || fail "attach-role-policy failed"
# a role whose trust names a DIFFERENT user only (for the PassRole/trust negative).
NTRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::'"$ACCOUNT"':user/somebody-else-'"$SFX"'"},"Action":"sts:AssumeRole"}]}'
iam create-role --role-name "$NOTRUST_ROLE" --assume-role-policy-document "$NTRUST" >/dev/null 2>&1 || fail "create notrust-role failed"

# --- 4. seed buckets in MinIO (the shim S3 API has no CreateBucket; the role reads them THROUGH the shim) ---
MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://minio.minio.svc.cluster.local:9000}"
MINIO_USER="$(kubectl -n minio get secret minio -o jsonpath='{.data.rootUser}' 2>/dev/null | base64 -d)"
MINIO_PW="$(kubectl -n minio get secret minio -o jsonpath='{.data.rootPassword}' 2>/dev/null | base64 -d)"
[ -n "$MINIO_USER" ] && [ -n "$MINIO_PW" ] || inconclusive "could not read MinIO root creds (secret minio/minio)"
minio_s3() { AWS_ACCESS_KEY_ID="$MINIO_USER" AWS_SECRET_ACCESS_KEY="$MINIO_PW" AWS_REGION="$REGION" aws --endpoint-url "$MINIO_ENDPOINT" --no-cli-pager s3api "$@"; }
curl -fsS -m 5 "${MINIO_ENDPOINT}/minio/health/live" >/dev/null 2>&1 || inconclusive "MinIO not reachable at ${MINIO_ENDPOINT}"
log "seeding buckets ${BUCKET_X}, ${BUCKET_Y} + objects in MinIO"
for b in "$BUCKET_X" "$BUCKET_Y"; do
  minio_s3 create-bucket --bucket "$b" >/dev/null 2>&1 || inconclusive "could not create bucket $b"
  CREATED_BUCKETS+=("$b")
  printf 'hello-from-%s' "$b" > "$TMP/obj"
  minio_s3 put-object --bucket "$b" --key obj --body "$TMP/obj" >/dev/null 2>&1 || inconclusive "could not put object in $b"
done

log "waiting ~35s for the data-plane policy loader to see the attached policy..."
sleep 35

# --- 5. CreateStateMachine (with roleArn) -----------------------------------------------------------
cat > "$TMP/def.json" <<JSON
{ "Comment": "open-infra Step Functions probe", "StartAt": "Classify",
  "States": {
    "Classify": { "Type": "Choice",
      "Choices": [ {"Variable":"\$.mode","StringEquals":"faily","Next":"Faily"},
                   {"Variable":"\$.mode","StringEquals":"wait","Next":"LongWait"} ],
      "Default": "Echo" },
    "Echo":  { "Type":"Task","Resource":"function:${ECHO_NAME}","ResultPath":"\$.echo","Next":"Done" },
    "Faily": { "Type":"Task","Resource":"function:sfn-nonexistent-${SFX}",
      "Retry":[{"ErrorEquals":["States.TaskFailed"],"MaxAttempts":2,"IntervalSeconds":1,"BackoffRate":2.0}],
      "Catch":[{"ErrorEquals":["States.ALL"],"Next":"Recovered"}], "End":true },
    "Recovered": { "Type":"Pass","Result":{"recovered":true},"Next":"Done" },
    "LongWait":  { "Type":"Wait","Seconds":120,"Next":"Done" },
    "Done": { "Type":"Succeed" }
  } }
JSON
log "create-state-machine ${SM_NAME} (roleArn=${ROLE})"
SM_ARN="$(sfn create-state-machine --name "$SM_NAME" --definition "file://$TMP/def.json" \
  --role-arn "arn:aws:iam::${ACCOUNT}:role/${ROLE}" --query stateMachineArn --output text 2>"$TMP/csm" || true)"
[ -n "$SM_ARN" ] && [ "$SM_ARN" != "None" ] || fail "create-state-machine failed: $(cat "$TMP/csm" 2>/dev/null)"

start_exec() { # <mode> -> exec-arn (prints)
  local mode="$1"
  local arn; arn="$(sfn start-execution --state-machine-arn "$SM_ARN" --input "{\"mode\":\"$mode\"}" \
    --query executionArn --output text 2>"$TMP/se" || true)"
  if [ -z "$arn" ] || [ "$arn" = "None" ]; then
    if grep -qiE 'STS disabled|not enabled|signing key' "$TMP/se"; then
      inconclusive "execution-role authority needs STS enabled (Vault sts/signing-key). start-execution: $(cat "$TMP/se")"
    fi
    fail "start-execution ($mode) failed: $(cat "$TMP/se" 2>/dev/null)"
  fi
  CREATED_EXECS+=("$(python3 -c 'import sys;a=sys.argv[1];print(a.rsplit(":",1)[1])' "$arn")")
  printf '%s' "$arn"
}
poll_status() { # <exec-arn> <want> <timeout-s> -> 0 if reached; prints last status
  local arn="$1" want="$2" t="${3:-90}" i=0 st=""
  while [ "$i" -lt "$t" ]; do
    st="$(sfn describe-execution --execution-arn "$arn" --query status --output text 2>/dev/null || true)"
    [ "$st" = "$want" ] && { printf '%s' "$st"; return 0; }
    case "$st" in SUCCEEDED|FAILED|TIMED_OUT|ABORTED) printf '%s' "$st"; return 1;; esac
    sleep 3; i=$((i+3))
  done
  printf '%s' "$st"; return 1
}

# --- 6. ECHO run: Task under role authority (the confused-deputy detector) --------------------------
log "start-execution (mode=echo) → the Echo Task must run under role ${ROLE}"
EXARN="$(start_exec echo)"
ST="$(poll_status "$EXARN" SUCCEEDED 90)" || fail "echo execution did not SUCCEED (status=$ST)"
log "    ✓ execution SUCCEEDED"

sfn describe-execution --execution-arn "$EXARN" --query output --output text > "$TMP/out.json" 2>/dev/null || true
cat > "$TMP/extract.py" <<'PY'
import sys, json
data = json.loads(open(sys.argv[1]).read())
def find(d, key):
    for k, v in (d or {}).items():
        if k.lower() == key.lower(): return v
    return ""
headers = (data.get("echo") or {}).get("headers") or {}
m = {"access":"x-openinfra-task-access-key-id","secret":"x-openinfra-task-secret-access-key","token":"x-openinfra-task-session-token"}
print(find(headers, m[sys.argv[2]]))
PY
SAK="$(python3 "$TMP/extract.py" "$TMP/out.json" access)"
SSK="$(python3 "$TMP/extract.py" "$TMP/out.json" secret)"
STOK="$(python3 "$TMP/extract.py" "$TMP/out.json" token)"
[ -n "$SAK" ] && [ -n "$SSK" ] && [ -n "$STOK" ] || fail "the Echo Task did NOT receive the role's STS session (no injected X-Openinfra-Task-* creds in the output) — the controller ran the Task under its own authority, not the role's"
log "    ✓ the Task received the role's STS session (injected as request identity)"

log "  the injected session is a REAL role session: get-caller-identity = the assumed role"
CID="$(AWS_ACCESS_KEY_ID="$SAK" AWS_SECRET_ACCESS_KEY="$SSK" AWS_SESSION_TOKEN="$STOK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager sts get-caller-identity --query Arn --output text 2>"$TMP/ci" || true)"
grep -q "assumed-role/${ROLE}" <<<"$CID" || fail "the injected session did not resolve to assumed-role/${ROLE} (got '$CID'): $(cat "$TMP/ci" 2>/dev/null)"
log "    ✓ ${CID}"

log "  ALLOW: the session can GetObject ${BUCKET_X}/obj (what the role's policy grants)"
s3op "$SAK" "$SSK" "$STOK" get-object --bucket "$BUCKET_X" --key obj "$TMP/got" >/dev/null 2>"$TMP/g" \
  || fail "the role session could NOT GetObject the granted bucket (allow direction broken): $(cat "$TMP/g" 2>/dev/null)"
[ "$(cat "$TMP/got" 2>/dev/null)" = "hello-from-$BUCKET_X" ] || fail "granted GetObject returned wrong content"
log "    ✓ allowed"

log "  DENY: the session is denied GetObject ${BUCKET_Y}/obj (a bucket its policy does NOT grant)"
if s3op "$SAK" "$SSK" "$STOK" get-object --bucket "$BUCKET_Y" --key obj "$TMP/y" >/dev/null 2>"$TMP/yerr"; then
  fail "the role session read a bucket its policy does NOT grant (confused deputy — Task ran on backend creds?)"
fi
grep -qiE 'AccessDenied|denied|forbidden' "$TMP/yerr" || fail "cross-bucket denial had the wrong error: $(cat "$TMP/yerr")"
log "    ✓ denied (the Task runs under the ROLE's authority, doing exactly what it grants and no more)"

# --- 7. RETRY + CATCH + CHOICE: the faily branch recovers and history reflects it -------------------
log "start-execution (mode=faily) → Retry (backoff) then Catch → Recovered → Succeeded"
FEXARN="$(start_exec faily)"
ST="$(poll_status "$FEXARN" SUCCEEDED 90)" || fail "faily execution did not SUCCEED via Catch (status=$ST)"
FNAME="$(python3 -c 'import sys;print(sys.argv[1].rsplit(":",1)[1])' "$FEXARN")"
HIST="$(kubectl -n "$SHIM_NS" get execution.openinfra.dev "$FNAME" -o jsonpath='{.status.history}' 2>/dev/null || true)"
grep -q 'TaskRetry' <<<"$HIST" || fail "execution history shows no TaskRetry (Retry did not fire)"
grep -q 'TaskCaught' <<<"$HIST" || fail "execution history shows no TaskCaught (Catch did not fire)"
# the front-door GetExecutionHistory must also return events.
EVN="$(sfn get-execution-history --execution-arn "$FEXARN" --query 'length(events)' --output text 2>/dev/null || echo 0)"
[ "${EVN:-0}" -gt 0 ] 2>/dev/null || fail "GetExecutionHistory returned no events"
log "    ✓ retry + catch happened and are reflected in the history (${EVN} events)"

# --- 8. STOP: a long-running (Wait) execution can be aborted ----------------------------------------
log "start-execution (mode=wait) → StopExecution → status ABORTED"
WEXARN="$(start_exec wait)"
poll_status "$WEXARN" RUNNING 30 >/dev/null || fail "wait execution never reached RUNNING"
sleep 3
sfn stop-execution --execution-arn "$WEXARN" --cause "probe-stop" >/dev/null 2>"$TMP/stop" || fail "stop-execution failed: $(cat "$TMP/stop")"
ST="$(poll_status "$WEXARN" ABORTED 40)" || fail "stopped execution did not reach ABORTED (status=$ST)"
log "    ✓ ABORTED"

# --- 9. NEGATIVE: run under a role whose trust does not name the caller → AccessDenied --------------
log "negative: start-execution under a role the caller is NOT trusted to pass → AccessDenied"
sfn create-state-machine --name "$SM_NOTRUST" --definition "file://$TMP/def.json" \
  --role-arn "arn:aws:iam::${ACCOUNT}:role/${NOTRUST_ROLE}" >/dev/null 2>&1 || fail "create-state-machine (notrust) failed"
if sfn start-execution --state-machine-arn "arn:aws:states:${REGION}:${ACCOUNT}:stateMachine:${SM_NOTRUST}" --input '{"mode":"echo"}' >/dev/null 2>"$TMP/nt"; then
  fail "start-execution under an untrusted role was allowed (the PassRole/trust gate is broken)"
fi
grep -qiE 'AccessDenied|not authorized|trust' "$TMP/nt" || fail "untrusted-role denial had the wrong error: $(cat "$TMP/nt")"
log "    ✓ denied (caller not named by the role's trust policy)"

# --- 10. NEGATIVE: an unsupported ASL feature is REFUSED at CreateStateMachine ----------------------
log "negative: CreateStateMachine with a Parallel state → InvalidDefinition (refused, not faked)"
echo '{"StartAt":"P","States":{"P":{"Type":"Parallel","End":true}}}' > "$TMP/bad.json"
if sfn create-state-machine --name "sfn-bad-$SFX" --definition "file://$TMP/bad.json" \
   --role-arn "arn:aws:iam::${ACCOUNT}:role/${ROLE}" >/dev/null 2>"$TMP/bad"; then
  sfn delete-state-machine --state-machine-arn "arn:aws:states:${REGION}:${ACCOUNT}:stateMachine:sfn-bad-$SFX" >/dev/null 2>&1 || true
  fail "an unsupported Parallel definition was accepted (should be refused)"
fi
grep -qiE 'InvalidDefinition|not supported|Parallel' "$TMP/bad" || fail "unsupported-ASL refusal had the wrong error: $(cat "$TMP/bad")"
log "    ✓ refused"

printf '\n✓ PASS — aws-shim Step Functions is faithful: an AWS-authored ASL workflow runs (Task/Choice/Wait/Retry/Catch), a Task executes under the state machine ROLE (injected STS session = the assumed role, doing exactly what the role grants and denied what it does not — the confused-deputy fix), StopExecution aborts, the history reflects real transitions, and the negatives (untrusted-role pass, unsupported ASL) are refused.\n'
