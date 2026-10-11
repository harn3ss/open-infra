#!/usr/bin/env bash
# Compatibility probe for aws:CurrentTime Date* conditions in the IAM policy importer (#266, time keys).
#
# The engine's unit tests already prove the datetime comparison (in-window allow, out-of-window deny,
# absent/malformed fail-closed). What THIS probe proves, end-to-end against the deployed shim, is the one
# thing a unit test cannot: that the live shim POPULATES aws:CurrentTime on every request and that the
# compiled Cedar datetime comparison actually gates a real S3 round-trip. It isolates currentTime as the
# sole deciding variable — two roles, identical in every way EXCEPT the time window on their policy:
#   - ROLE_IN  : Allow s3:GetObject WHERE aws:CurrentTime ∈ [2020, 2099)  → now is inside  → GetObject ALLOWED
#   - ROLE_PAST: Allow s3:GetObject WHERE aws:CurrentTime <  2020-01-01   → now is after   → GetObject DENIED
# Same bucket, same action, same object. If ROLE_IN reads and ROLE_PAST is denied, the only thing that could
# have flipped the decision is the request's wall-clock currentTime — which proves the shim set it and Cedar
# compared it. A translator that silently dropped the time condition would let ROLE_PAST read too (fail open);
# one that never populated currentTime would deny ROLE_IN as well (the forbid absent-key guard).
#
# On-demand (needs a deployed shim + STS AssumeRole + MinIO/S3 + the IAM CRDs + an openinfra:admins caller).
# Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE. Per polyhedron#157, a probe failure is a shim defect.
#
#   SHIM_ENDPOINT=http://localhost:4566 MINIO_ENDPOINT=http://localhost:9000 ./probe/aws-shim-iam-timecond.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
ACCOUNT="${ACCOUNT_ID:-open-infra}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

CREATED_KEYS=(); CREATED_USERS=(); CREATED_ROLES=(); CREATED_POLICIES=(); CREATED_BUCKETS=()
AAK=""; ASK=""
iam() { local ak="$1" sk="$2"; shift 2; AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text iam "$@"; }
s3op() { local ak="$1" sk="$2" tok="${3:-}"; shift 3; AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_SESSION_TOKEN="$tok" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager s3api "$@"; }
cleanup() {
  for r in "${CREATED_ROLES[@]:-}";    do [ -n "$r" ] && iam "$AAK" "$ASK" delete-role --role-name "$r" >/dev/null 2>&1 || true; done
  for p in "${CREATED_POLICIES[@]:-}"; do [ -n "$p" ] && iam "$AAK" "$ASK" delete-policy --policy-arn "arn:aws:iam::${ACCOUNT}:policy/$p" >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}";    do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for k in "${CREATED_KEYS[@]:-}";     do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
  kubectl -n "$USERS_NS" delete role.iam.openinfra.dev "tc-probe-role-in-$SFX" "tc-probe-role-past-$SFX" --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev "tc-probe-pol-in-$SFX" "tc-probe-pol-past-$SFX" "role-tc-probe-role-"*"-$SFX-"* --ignore-not-found >/dev/null 2>&1 || true
  if [ -n "${MINIO_USER:-}" ]; then
    for b in "${CREATED_BUCKETS[@]:-}"; do
      [ -n "$b" ] && { minio_s3 delete-object --bucket "$b" --key obj >/dev/null 2>&1; minio_s3 delete-bucket --bucket "$b" >/dev/null 2>&1; } || true
    done
  fi
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

# --- 1. Seed an IAM-admin caller (openinfra:admins) -------------------------------------------
log "seeding an IAM-admin caller (openinfra:admins) + key"
ADMIN="tc-probe-admin-$SFX"
read -r AAK ASK <<<"$(mint_key "$ADMIN" "admins")"
[ -n "$AAK" ] && [ -n "$ASK" ] || inconclusive "failed to mint an admin key"
sleep 2

# --- 2. Two policies, identical but for the aws:CurrentTime window (AWS JSON → Cedar datetime) --
BUCKET="tc-probe-$SFX"
POL_IN="tc-probe-pol-in-$SFX"; ROLE_IN="tc-probe-role-in-$SFX"
POL_PAST="tc-probe-pol-past-$SFX"; ROLE_PAST="tc-probe-role-past-$SFX"

log "create-policy ${POL_IN} (Allow s3:GetObject WHERE aws:CurrentTime ∈ [2020,2099))"
DOC_IN='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::'"$BUCKET"'/*","Condition":{"DateGreaterThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"},"DateLessThan":{"aws:CurrentTime":"2099-01-01T00:00:00Z"}}}]}'
ARN_IN="$(iam "$AAK" "$ASK" create-policy --policy-name "$POL_IN" --policy-document "$DOC_IN" --query 'Policy.Arn' 2>"$PWD/.tc_cp")" \
  || inconclusive "create-policy (in-window) failed — did the time condition import? $(cat "$PWD/.tc_cp" 2>/dev/null)"
[ -n "$ARN_IN" ] && [ "$ARN_IN" != "None" ] || inconclusive "create-policy (in-window) returned no ARN"
CREATED_POLICIES+=("$POL_IN"); rm -f "$PWD/.tc_cp"

log "create-policy ${POL_PAST} (Allow s3:GetObject WHERE aws:CurrentTime < 2020-01-01 — a past window)"
DOC_PAST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::'"$BUCKET"'/*","Condition":{"DateLessThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}}]}'
ARN_PAST="$(iam "$AAK" "$ASK" create-policy --policy-name "$POL_PAST" --policy-document "$DOC_PAST" --query 'Policy.Arn' 2>"$PWD/.tc_cp")" \
  || inconclusive "create-policy (past-window) failed: $(cat "$PWD/.tc_cp" 2>/dev/null)"
[ -n "$ARN_PAST" ] && [ "$ARN_PAST" != "None" ] || inconclusive "create-policy (past-window) returned no ARN"
CREATED_POLICIES+=("$POL_PAST"); rm -f "$PWD/.tc_cp"

TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::'"$ACCOUNT"':user/'"$ADMIN"'"},"Action":"sts:AssumeRole"}]}'
for pair in "$ROLE_IN:$ARN_IN" "$ROLE_PAST:$ARN_PAST"; do
  role="${pair%%:*}"; arn="${pair#*:}"
  log "create-role ${role} + attach its policy"
  iam "$AAK" "$ASK" create-role --role-name "$role" --assume-role-policy-document "$TRUST" >/dev/null 2>&1 || fail "create-role $role failed"
  CREATED_ROLES+=("$role")
  iam "$AAK" "$ASK" attach-role-policy --role-name "$role" --policy-arn "$arn" >/dev/null 2>&1 || fail "attach-role-policy $role failed"
done

# --- 3. Seed the bucket + object directly in MinIO (the shim reads it back through the dataPlane) ------
MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://minio.minio.svc.cluster.local:9000}"
MINIO_USER="$(kubectl -n minio get secret minio -o jsonpath='{.data.rootUser}' 2>/dev/null | base64 -d)"
MINIO_PW="$(kubectl -n minio get secret minio -o jsonpath='{.data.rootPassword}' 2>/dev/null | base64 -d)"
[ -n "$MINIO_USER" ] && [ -n "$MINIO_PW" ] || inconclusive "could not read MinIO root creds (secret minio/minio)"
minio_s3() { AWS_ACCESS_KEY_ID="$MINIO_USER" AWS_SECRET_ACCESS_KEY="$MINIO_PW" AWS_REGION="$REGION" aws --endpoint-url "$MINIO_ENDPOINT" --no-cli-pager s3api "$@"; }
curl -fsS -m 5 "${MINIO_ENDPOINT}/minio/health/live" >/dev/null 2>&1 || inconclusive "MinIO not reachable at ${MINIO_ENDPOINT} (port-forward svc/minio 9000)"
log "seeding bucket ${BUCKET} + object directly in MinIO"
minio_s3 create-bucket --bucket "$BUCKET" >/dev/null 2>&1 || inconclusive "could not create bucket $BUCKET in MinIO"
CREATED_BUCKETS+=("$BUCKET")
echo "hello-from-$BUCKET" > "/tmp/tc_obj_$SFX"
minio_s3 put-object --bucket "$BUCKET" --key "obj" --body "/tmp/tc_obj_$SFX" >/dev/null 2>&1 || inconclusive "could not put object in $BUCKET"
rm -f "/tmp/tc_obj_$SFX"

log "waiting ~35s for the data-plane policy loader to see the attached policies..."
sleep 35

# --- 4. The isolation test: assume each role, GetObject the SAME object -------------------------
assume() { # <role> -> "AK SK TOK" (empty on gated STS)
  local role="$1"
  AWS_ACCESS_KEY_ID="$AAK" AWS_SECRET_ACCESS_KEY="$ASK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager \
    sts assume-role --role-arn "arn:aws:iam::${ACCOUNT}:role/${role}" --role-session-name "tc-$SFX" \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text 2>"$PWD/.tc_ar" || true
}

log "sts assume-role into ${ROLE_IN} (in-window)"
CREDS_IN="$(assume "$ROLE_IN")"
if grep -qiE 'signing key|not enabled|AssumeRole is not' "$PWD/.tc_ar" 2>/dev/null; then
  rm -f "$PWD/.tc_ar"
  inconclusive "STS AssumeRole is not enabled on this shim (no Vault sts/signing-key) — the live time-window round-trip is gated. Enable STS and re-run."
fi
rm -f "$PWD/.tc_ar"
[ -n "$CREDS_IN" ] || fail "assume-role into $ROLE_IN returned no credentials"
read -r IAK ISK ITOK <<<"$CREDS_IN"

log "  ALLOW: the in-window session can GetObject ${BUCKET}/obj (now ∈ [2020,2099))"
s3op "$IAK" "$ISK" "$ITOK" get-object --bucket "$BUCKET" --key obj "/tmp/tc_got_$SFX" >/dev/null 2>"$PWD/.tc_g" \
  || fail "in-window session could NOT GetObject — currentTime is not populated, or the datetime compare is wrong (fail-closed on absent clock): $(cat "$PWD/.tc_g" 2>/dev/null)"
GOT="$(cat "/tmp/tc_got_$SFX" 2>/dev/null || true)"
rm -f "/tmp/tc_got_$SFX" "$PWD/.tc_g"
[ "$GOT" = "hello-from-$BUCKET" ] || fail "in-window GetObject returned the wrong content: '$GOT'"
log "    ✓ allowed (currentTime populated and inside the window)"

log "sts assume-role into ${ROLE_PAST} (past-window)"
CREDS_PAST="$(assume "$ROLE_PAST")"
rm -f "$PWD/.tc_ar"
[ -n "$CREDS_PAST" ] || fail "assume-role into $ROLE_PAST returned no credentials"
read -r PAK PSK PTOK <<<"$CREDS_PAST"

log "  DENY: the past-window session is denied GetObject ${BUCKET}/obj (now > 2020-01-01)"
if s3op "$PAK" "$PSK" "$PTOK" get-object --bucket "$BUCKET" --key obj "/tmp/tc_past_$SFX" >/dev/null 2>"$PWD/.tc_p"; then
  rm -f "/tmp/tc_past_$SFX"
  fail "FAIL-OPEN: past-window session READ the object — the aws:CurrentTime condition was dropped or never enforced"
fi
grep -qiE 'AccessDenied|denied|forbidden' "$PWD/.tc_p" || fail "past-window denial had the wrong error: $(cat "$PWD/.tc_p")"
rm -f "$PWD/.tc_p" "/tmp/tc_past_$SFX"
log "    ✓ denied (the ONLY difference from the allowed case is the time window → currentTime decided it)"

printf '\n✓ PASS — aws:CurrentTime Date* conditions enforce end-to-end: two roles identical but for the time\n'
printf '  window, same bucket/object; the in-window session READS and the past-window session is DENIED. The\n'
printf '  live shim populates currentTime and the compiled Cedar datetime comparison gates the real round-trip.\n'
