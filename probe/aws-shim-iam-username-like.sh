#!/usr/bin/env bash
# Compatibility probe for aws:username StringLike/StringNotLike conditions (#266, LikeConditions).
#
# #266 added StringLike import to the engine, but the live round-trip found (and 9bea243 fixed) that
# LikeConditions were silently dropped on the kind: Policy CR round-trip — the same write/read-parity
# fail-open that bit aws:CurrentTime. The engine's own unit tests passed while enforcement was open. This
# probe proves end-to-end that a wildcard-username Allow enforces, isolating the username match as the sole
# deciding variable: two roles whose ONLY difference is their name (hence their assumed-session username),
# governed by the SAME policy with a StringLike on aws:username:
#   - ROLE whose name matches "<prefix>-good-*" → GetObject ALLOWED
#   - ROLE whose name does NOT match           → GetObject DENIED
# Same bucket, same object, same policy pattern. If the match-name role reads and the other is denied, the
# only thing that flipped the decision is aws:username, which proves the StringLike condition persisted and
# the compiled Cedar `like` match gated the real round-trip. (For an assumed Role the shim's data-plane
# principal id — username — is the role name, so the role name IS the tested attribute.)
#
# On-demand (needs a deployed shim + STS AssumeRole + MinIO/S3 + the IAM CRDs + an openinfra:admins caller).
# Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE. By policy, a probe failure is a shim defect.
#
#   SHIM_ENDPOINT=http://localhost:4566 MINIO_ENDPOINT=http://localhost:9000 ./probe/aws-shim-iam-username-like.sh
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

# Role names: one matches the StringLike pattern "ul<sfx>-good-*", one does not.
GOOD="ul${SFX}-good-role"
BAD="ul${SFX}-bad-role"
PATTERN="ul${SFX}-good-*"

CREATED_KEYS=(); CREATED_USERS=(); CREATED_ROLES=(); CREATED_POLICIES=(); CREATED_BUCKETS=()
AAK=""; ASK=""
iam() { local ak="$1" sk="$2"; shift 2; AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text iam "$@"; }
s3op() { local ak="$1" sk="$2" tok="${3:-}"; shift 3; AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_SESSION_TOKEN="$tok" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager s3api "$@"; }
cleanup() {
  for r in "${CREATED_ROLES[@]:-}";    do [ -n "$r" ] && iam "$AAK" "$ASK" delete-role --role-name "$r" >/dev/null 2>&1 || true; done
  for p in "${CREATED_POLICIES[@]:-}"; do [ -n "$p" ] && iam "$AAK" "$ASK" delete-policy --policy-arn "arn:aws:iam::${ACCOUNT}:policy/$p" >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}";    do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for k in "${CREATED_KEYS[@]:-}";     do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
  kubectl -n "$USERS_NS" delete role.iam.openinfra.dev "$GOOD" "$BAD" --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev "ul${SFX}-pol" "role-${GOOD}-"* "role-${BAD}-"* --ignore-not-found >/dev/null 2>&1 || true
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
ADMIN="ul${SFX}-admin"
read -r AAK ASK <<<"$(mint_key "$ADMIN" "admins")"
[ -n "$AAK" ] && [ -n "$ASK" ] || inconclusive "failed to mint an admin key"
sleep 2

# --- 2. One policy with a StringLike aws:username condition, attached to BOTH roles --------------
BUCKET="ul${SFX}"
POL="ul${SFX}-pol"
log "create-policy ${POL} (Allow s3:GetObject WHERE StringLike aws:username = \"${PATTERN}\")"
DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::'"$BUCKET"'/*","Condition":{"StringLike":{"aws:username":"'"$PATTERN"'"}}}]}'
ARN="$(iam "$AAK" "$ASK" create-policy --policy-name "$POL" --policy-document "$DOC" --query 'Policy.Arn' 2>"$PWD/.ul_cp")" \
  || inconclusive "create-policy failed — did the StringLike condition import? $(cat "$PWD/.ul_cp" 2>/dev/null)"
[ -n "$ARN" ] && [ "$ARN" != "None" ] || inconclusive "create-policy returned no ARN"
CREATED_POLICIES+=("$POL"); rm -f "$PWD/.ul_cp"

TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::'"$ACCOUNT"':user/'"$ADMIN"'"},"Action":"sts:AssumeRole"}]}'
for role in "$GOOD" "$BAD"; do
  log "create-role ${role} + attach the shared policy"
  iam "$AAK" "$ASK" create-role --role-name "$role" --assume-role-policy-document "$TRUST" >/dev/null 2>&1 || fail "create-role $role failed"
  CREATED_ROLES+=("$role")
  iam "$AAK" "$ASK" attach-role-policy --role-name "$role" --policy-arn "$ARN" >/dev/null 2>&1 || fail "attach-role-policy $role failed"
done

# --- 3. Seed the bucket + object directly in MinIO ----------------------------------------------
MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://minio.minio.svc.cluster.local:9000}"
MINIO_USER="$(kubectl -n minio get secret minio -o jsonpath='{.data.rootUser}' 2>/dev/null | base64 -d)"
MINIO_PW="$(kubectl -n minio get secret minio -o jsonpath='{.data.rootPassword}' 2>/dev/null | base64 -d)"
[ -n "$MINIO_USER" ] && [ -n "$MINIO_PW" ] || inconclusive "could not read MinIO root creds (secret minio/minio)"
minio_s3() { AWS_ACCESS_KEY_ID="$MINIO_USER" AWS_SECRET_ACCESS_KEY="$MINIO_PW" AWS_REGION="$REGION" aws --endpoint-url "$MINIO_ENDPOINT" --no-cli-pager s3api "$@"; }
curl -fsS -m 5 "${MINIO_ENDPOINT}/minio/health/live" >/dev/null 2>&1 || inconclusive "MinIO not reachable at ${MINIO_ENDPOINT}"
log "seeding bucket ${BUCKET} + object directly in MinIO"
minio_s3 create-bucket --bucket "$BUCKET" >/dev/null 2>&1 || inconclusive "could not create bucket $BUCKET in MinIO"
CREATED_BUCKETS+=("$BUCKET")
echo "hello-from-$BUCKET" > "/tmp/ul_obj_$SFX"
minio_s3 put-object --bucket "$BUCKET" --key "obj" --body "/tmp/ul_obj_$SFX" >/dev/null 2>&1 || inconclusive "could not put object in $BUCKET"
rm -f "/tmp/ul_obj_$SFX"

log "waiting ~35s for the data-plane policy loader to see the attached policy..."
sleep 35

# --- 4. The isolation test: assume each role, GetObject the SAME object -------------------------
assume() { # <role> -> "AK SK TOK"
  AWS_ACCESS_KEY_ID="$AAK" AWS_SECRET_ACCESS_KEY="$ASK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager \
    sts assume-role --role-arn "arn:aws:iam::${ACCOUNT}:role/${1}" --role-session-name "ul-$SFX" \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text 2>"$PWD/.ul_ar" || true
}

log "sts assume-role into ${GOOD} (username matches \"${PATTERN}\")"
CREDS_G="$(assume "$GOOD")"
if grep -qiE 'signing key|not enabled|AssumeRole is not' "$PWD/.ul_ar" 2>/dev/null; then
  rm -f "$PWD/.ul_ar"
  inconclusive "STS AssumeRole is not enabled on this shim — the live username-match round-trip is gated. Enable STS and re-run."
fi
rm -f "$PWD/.ul_ar"
[ -n "$CREDS_G" ] || fail "assume-role into $GOOD returned no credentials"
read -r GAK GSK GTOK <<<"$CREDS_G"

log "  ALLOW: the matching-name session can GetObject ${BUCKET}/obj"
s3op "$GAK" "$GSK" "$GTOK" get-object --bucket "$BUCKET" --key obj "/tmp/ul_got_$SFX" >/dev/null 2>"$PWD/.ul_g" \
  || fail "matching-name session could NOT GetObject — the StringLike condition is wrong or username is not populated: $(cat "$PWD/.ul_g" 2>/dev/null)"
GOT="$(cat "/tmp/ul_got_$SFX" 2>/dev/null || true)"
rm -f "/tmp/ul_got_$SFX" "$PWD/.ul_g"
[ "$GOT" = "hello-from-$BUCKET" ] || fail "matching GetObject returned the wrong content: '$GOT'"
log "    ✓ allowed (username matched the pattern)"

log "sts assume-role into ${BAD} (username does NOT match \"${PATTERN}\")"
CREDS_B="$(assume "$BAD")"
rm -f "$PWD/.ul_ar"
[ -n "$CREDS_B" ] || fail "assume-role into $BAD returned no credentials"
read -r BAK BSK BTOK <<<"$CREDS_B"

log "  DENY: the non-matching-name session is denied GetObject ${BUCKET}/obj"
if s3op "$BAK" "$BSK" "$BTOK" get-object --bucket "$BUCKET" --key obj "/tmp/ul_bad_$SFX" >/dev/null 2>"$PWD/.ul_b"; then
  rm -f "/tmp/ul_bad_$SFX"
  fail "FAIL-OPEN: non-matching session READ the object — the StringLike aws:username condition was dropped or never enforced"
fi
grep -qiE 'AccessDenied|denied|forbidden' "$PWD/.ul_b" || fail "non-matching denial had the wrong error: $(cat "$PWD/.ul_b")"
rm -f "$PWD/.ul_b" "/tmp/ul_bad_$SFX"
log "    ✓ denied (the ONLY difference from the allowed case is the username → the StringLike match decided it)"

printf '\n✓ PASS — aws:username StringLike conditions enforce end-to-end: two roles governed by the same\n'
printf '  policy, differing only in name/username; the matching session READS and the non-matching session is\n'
printf '  DENIED. The live shim populates username and the compiled Cedar `like` match gates the real round-trip.\n'
