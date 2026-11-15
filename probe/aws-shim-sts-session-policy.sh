#!/usr/bin/env bash
# Live probe: STS session policies narrow an assumed-role session, as on AWS (sts:AssumeRole Policy and
# PolicyArns). One role is allowed all of SQS:
#   - a session with no session policy creates a queue (the role's own permissions);
#   - a session whose inline session policy allows only sqs:ListQueues lists queues, and is REFUSED
#     sqs:CreateQueue with AccessDenied;
#   - a session whose session policy is AWS's ReadOnlyAccess (PolicyArns) is refused sqs:CreateQueue too.
# Before the fix, the shim ignored Policy and PolicyArns and both narrowed sessions created the queue.
#
# Exit 0 pass, 1 fail, 42 inconclusive. Needs the aws CLI and kubectl (KUBECONFIG); reaches the shim at
# SHIM_ENDPOINT (port-forward svc/aws-shim 4566).
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
ACCOUNT="${ACCOUNT_ID:-000000000000}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

ADMIN="sp-probe-admin-$SFX"; ROLE="sp-probe-role-$SFX"
CREATED_KEYS=(); CREATED_USERS=(); MADE_ROLE=""; QUEUES=()
as() { local ak="$1" sk="$2" tok="$3"; shift 3
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_SESSION_TOKEN="$tok" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$@"; }
cleanup() {
  for q in "${QUEUES[@]:-}"; do [ -n "$q" ] && as "$AAK" "$ASK" "" sqs delete-queue --queue-url "$q" >/dev/null 2>&1; done
  if [ -n "$MADE_ROLE" ]; then
    as "$AAK" "$ASK" "" iam delete-role-policy --role-name "$ROLE" --policy-name sqs-all >/dev/null 2>&1
    as "$AAK" "$ASK" "" iam delete-role --role-name "$ROLE" >/dev/null 2>&1
  fi
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1; done
  for k in "${CREATED_KEYS[@]:-}"; do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1; done
  rm -rf "$TMP"
}
trap cleanup EXIT

# mint_key <owner> <group>: a kind: User and an access key the shim authenticates; sets MK_AK MK_SK.
mint_key() {
  local owner="$1" group="$2" ak sk name
  ak="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  sk="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  cat <<YAML | kubectl apply -f - >/dev/null || inconclusive "could not create User $owner"
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "${owner}", namespace: "${USERS_NS}" }
spec: { displayName: "${owner}", groups: ["${group}"], source: local }
YAML
  CREATED_USERS+=("$owner")
  name="iam-ak-$(printf '%s' "$ak" | sha256sum | cut -c1-40)"
  kubectl -n "$SHIM_NS" create secret generic "$name" --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" \
    --from-literal=owner="$owner" >/dev/null || inconclusive "could not create the access key"
  CREATED_KEYS+=("$name")
  MK_AK="$ak"; MK_SK="$sk"
}

# --- 1. a role allowed all of SQS ----------------------------------------------------------------------
log "seeding an administrator and role $ROLE (sqs:* on *)"
mint_key "$ADMIN" "admins"; AAK="$MK_AK"; ASK="$MK_SK"
TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::'"$ACCOUNT"':user/'"$ADMIN"'"},"Action":"sts:AssumeRole"}]}'
for _ in $(seq 1 10); do
  as "$AAK" "$ASK" "" iam create-role --role-name "$ROLE" --assume-role-policy-document "$TRUST" >/dev/null 2>"$TMP/cr" && break
  sleep 3   # the new key reaches the shim's key cache
done
grep -q . "$TMP/cr" && ! as "$AAK" "$ASK" "" iam get-role --role-name "$ROLE" >/dev/null 2>&1 && inconclusive "create-role failed: $(head -c 300 "$TMP/cr")"
MADE_ROLE=1
as "$AAK" "$ASK" "" iam put-role-policy --role-name "$ROLE" --policy-name sqs-all \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*"}]}' >/dev/null \
  || fail "put-role-policy failed"
log "waiting 35s for the IAM policy world to load the role's policy"
sleep 35

# assume <args…>: the session's "AK SK TOKEN".
assume() {
  as "$AAK" "$ASK" "" sts assume-role --role-arn "arn:aws:iam::${ACCOUNT}:role/${ROLE}" --role-session-name "sp-$SFX" \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' "$@" 2>"$TMP/ar"
}

# --- 2. no session policy: the role's own permissions ---------------------------------------------------
log "a session with no session policy creates a queue"
read -r S0_AK S0_SK S0_TOK <<<"$(assume)"
[ -n "${S0_TOK:-}" ] || inconclusive "assume-role returned no credentials: $(head -c 300 "$TMP/ar")"
Q0="$(as "$S0_AK" "$S0_SK" "$S0_TOK" sqs create-queue --queue-name "sp-probe-plain-$SFX" --query QueueUrl 2>"$TMP/q0")" \
  || fail "the role's plain session could not create a queue: $(head -c 300 "$TMP/q0")"
QUEUES+=("$Q0")
log "  ✓ created"

# --- 3. an inline session policy narrows it -------------------------------------------------------------
log "a session whose inline session policy allows only sqs:ListQueues"
read -r S1_AK S1_SK S1_TOK <<<"$(assume --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:ListQueues","Resource":"*"}]}')"
[ -n "${S1_TOK:-}" ] || fail "assume-role with a session policy returned no credentials: $(head -c 300 "$TMP/ar")"
as "$S1_AK" "$S1_SK" "$S1_TOK" sqs list-queues >/dev/null 2>"$TMP/l1" || fail "the narrowed session could not ListQueues: $(head -c 300 "$TMP/l1")"
if Q1="$(as "$S1_AK" "$S1_SK" "$S1_TOK" sqs create-queue --queue-name "sp-probe-inline-$SFX" --query QueueUrl 2>"$TMP/q1")"; then
  QUEUES+=("$Q1"); fail "WIDER THAN AWS: a session narrowed to sqs:ListQueues created a queue"
fi
grep -q "AccessDenied" "$TMP/q1" || fail "the refusal is not AWS's AccessDenied: $(head -c 300 "$TMP/q1")"
log "  ✓ lists queues; refused CreateQueue with AccessDenied"

# --- 4. a managed session policy narrows it -------------------------------------------------------------
log "a session whose session policy is arn:aws:iam::aws:policy/ReadOnlyAccess"
read -r S2_AK S2_SK S2_TOK <<<"$(assume --policy-arns arn=arn:aws:iam::aws:policy/ReadOnlyAccess)"
[ -n "${S2_TOK:-}" ] || fail "assume-role with PolicyArns returned no credentials: $(head -c 300 "$TMP/ar")"
if Q2="$(as "$S2_AK" "$S2_SK" "$S2_TOK" sqs create-queue --queue-name "sp-probe-managed-$SFX" --query QueueUrl 2>"$TMP/q2")"; then
  QUEUES+=("$Q2"); fail "WIDER THAN AWS: a session narrowed to ReadOnlyAccess created a queue"
fi
grep -q "AccessDenied" "$TMP/q2" || fail "the refusal is not AWS's AccessDenied: $(head -c 300 "$TMP/q2")"
log "  ✓ refused CreateQueue with AccessDenied"

# --- 5. a malformed session policy is refused at AssumeRole ---------------------------------------------
if assume --policy '{"Statement":' >/dev/null; then fail "a malformed session policy was accepted"; fi
grep -q "MalformedPolicyDocument" "$TMP/ar" || fail "a malformed session policy was refused with the wrong error: $(head -c 300 "$TMP/ar")"
log "  ✓ a malformed session policy is MalformedPolicyDocument"

log "PASS: session policies narrow an assumed-role session (inline and managed), as on AWS"
