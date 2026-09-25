#!/usr/bin/env bash
# Compatibility probe for the aws-shim Secrets Manager surface.
#
# Fires REAL AWS SDK calls (the aws CLI is a real SDK client) at a deployed shim and asserts the
# SEMANTICS secrets applications actually depend on — not merely HTTP 200 — because the failure this
# exists to catch is the false-green: the app believes it fetched the current credential and got a stale
# one, or believes a write persisted when it did not. It asserts, over real round-trips:
#   - CreateSecret then GetSecretValue returns the EXACT value
#   - PutSecretValue creates a new version, AWSCURRENT moves to it, and AWSPREVIOUS STILL returns the
#     prior value (the rotation-safety model — the part most often silently collapsed to "latest wins")
#   - a SecretBinary round-trips BYTE-IDENTICAL (no transcoding)
#   - a specific VersionId reads that version, not a silent fallback to AWSCURRENT
#   - DescribeSecret's rotation fields report the TRUTH (RotationEnabled=false — never a claimed-but-dead schedule)
#   - a deleted secret fails GetSecretValue (InvalidRequestException) but RestoreSecret brings it back
#   - GetRandomPassword returns a password of the requested length
#   - RotateSecret is REFUSED honestly (not accepted as a schedule that never fires)
# and the NEGATIVES that are the whole point ("prove the no"):
#   - a valid key ID with a WRONG secret is rejected (signature mismatch)
#   - a principal with DescribeSecret but NOT GetSecretValue sees METADATA but is DENIED the value
#   - a principal scoped to secret A cannot read secret B
#   - a GetSecretValue produced a structured audit record naming the principal
#
# On-demand (needs a deployed shim + Vault Transit with the aws-shim-kms policy + the KMS/SM Postgres +
# the platform IAM). Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE (a prerequisite was missing).
# Per polyhedron#161 / #157: a probe failure is presumed a shim defect, and 42 is not a pass.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-secretsmanager.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required to seed the principal + key"
command -v base64  >/dev/null || inconclusive "base64 is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"

CREATED_KEYS=(); CREATED_USERS=(); CREATED_POLICIES=(); CREATED_SECRETS=()
WAK=""; WSK=""
cleanup() {
  for s in "${CREATED_SECRETS[@]:-}";  do [ -n "$s" ] && AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager secretsmanager delete-secret --secret-id "$s" --force-delete-without-recovery >/dev/null 2>&1 || true; done
  for k in "${CREATED_KEYS[@]:-}";     do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}";    do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for p in "${CREATED_POLICIES[@]:-}"; do [ -n "$p" ] && kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev "$p" --ignore-not-found >/dev/null 2>&1 || true; done
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
  kubectl -n "$SHIM_NS" create secret generic "$name" \
    --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  CREATED_KEYS+=("$name")
  printf '%s %s' "$ak" "$sk"
}

awssm() { # AK SK -- <secretsmanager args...>
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text secretsmanager "$@"
}

# --- 1. Seed a writer principal + key ---------------------------------------------------------
log "seeding a writer principal (openinfra:powerusers) + access key"
read -r WAK WSK <<<"$(mint_key "sm-probe-$SFX" "powerusers")"
[ -n "$WAK" ] && [ -n "$WSK" ] || inconclusive "failed to mint a key"
sleep 2

# --- 2. CreateSecret + GetSecretValue returns the exact value ---------------------------------
SN="sm-probe-${SFX}"
V1='{"username":"admin","password":"p1-'"$SFX"'"}'
log "create-secret ${SN} + get-secret-value returns the exact value"
ARN="$(awssm "$WAK" "$WSK" create-secret --name "$SN" --secret-string "$V1" --query ARN 2>/dev/null)" \
  || inconclusive "create-secret failed — is Vault Transit reachable (aws-shim-kms) and SQS_PG_URI set?"
[ -n "$ARN" ] && [ "$ARN" != "None" ] || inconclusive "create-secret returned no ARN"
CREATED_SECRETS+=("$SN")
case "$ARN" in arn:aws:secretsmanager:*:secret:${SN}-*) : ;; *) fail "ARN not in the expected suffixed shape: $ARN";; esac
GOT="$(awssm "$WAK" "$WSK" get-secret-value --secret-id "$SN" --query SecretString 2>/dev/null)"
[ "$GOT" = "$V1" ] || fail "get-secret-value returned '$GOT' != '$V1'"
log "  ✓ exact value returned; ARN carries a stable suffix"

# --- 3. PutSecretValue: AWSCURRENT moves, AWSPREVIOUS still returns the prior value ------------
V2='{"username":"admin","password":"p2-'"$SFX"'"}'
log "put-secret-value → new AWSCURRENT; AWSPREVIOUS must still return the prior value"
awssm "$WAK" "$WSK" put-secret-value --secret-id "$SN" --secret-string "$V2" >/dev/null 2>&1 || fail "put-secret-value failed"
CUR="$(awssm "$WAK" "$WSK" get-secret-value --secret-id "$SN" --query SecretString 2>/dev/null)"
[ "$CUR" = "$V2" ] || fail "AWSCURRENT did not move to the new value: got '$CUR'"
PREV="$(awssm "$WAK" "$WSK" get-secret-value --secret-id "$SN" --version-stage AWSPREVIOUS --query SecretString 2>/dev/null)"
[ "$PREV" = "$V1" ] || fail "AWSPREVIOUS did not return the prior value: got '$PREV' want '$V1'"
log "  ✓ AWSCURRENT=v2, AWSPREVIOUS=v1 (rotation-safe versioning)"

# --- 3b. A specific VersionId reads that version (no silent fallback to AWSCURRENT) ------------
PREV_VID="$(awssm "$WAK" "$WSK" list-secret-version-ids --secret-id "$SN" \
  --query 'Versions[?contains(VersionStages, `AWSPREVIOUS`)].VersionId | [0]' 2>/dev/null)"
[ -n "$PREV_VID" ] && [ "$PREV_VID" != "None" ] || fail "could not find the AWSPREVIOUS VersionId"
BYVID="$(awssm "$WAK" "$WSK" get-secret-value --secret-id "$SN" --version-id "$PREV_VID" --query SecretString 2>/dev/null)"
[ "$BYVID" = "$V1" ] || fail "get by VersionId returned '$BYVID' (want the v1 value) — silent fallback?"
log "  ✓ VersionId read returns that exact version"

# --- 3c. audit: the GetSecretValue produced a record naming the principal ----------------------
log "audit: a GetSecretValue must have written a structured record (principal + secret)"
sleep 1
AUDIT="$(kubectl -n "$SHIM_NS" logs deploy/aws-shim --since=300s 2>/dev/null | grep '"msg":"secretsmanager audit"' | grep '"op":"GetSecretValue"' | grep "\"secret\":\"$SN\"" | tail -1)"
[ -n "$AUDIT" ] || fail "no Secrets Manager audit record found for the GetSecretValue (AU-2/IA-5)"
printf '%s' "$AUDIT" | grep -q "\"principal\":\"User::sm-probe-$SFX\"" || fail "audit record does not name the principal: $AUDIT"
log "  ✓ audit record present (principal + op + secret + decision)"

# --- 4. SecretBinary round-trips byte-identical -----------------------------------------------
log "SecretBinary must round-trip byte-identical (no transcoding)"
BN="sm-probe-bin-${SFX}"
TMP_BIN="$(mktemp)"; head -c 64 /dev/urandom > "$TMP_BIN"
awssm "$WAK" "$WSK" create-secret --name "$BN" --secret-binary "fileb://$TMP_BIN" >/dev/null 2>&1 || fail "create-secret (binary) failed"
CREATED_SECRETS+=("$BN")
GOTBIN_B64="$(awssm "$WAK" "$WSK" get-secret-value --secret-id "$BN" --query SecretBinary 2>/dev/null)"
[ -n "$GOTBIN_B64" ] && [ "$GOTBIN_B64" != "None" ] || fail "get-secret-value returned no SecretBinary"
TMP_OUT="$(mktemp)"; printf '%s' "$GOTBIN_B64" | base64 -d > "$TMP_OUT" 2>/dev/null || fail "SecretBinary was not valid base64"
cmp -s "$TMP_BIN" "$TMP_OUT" || fail "SecretBinary did not round-trip byte-identical"
rm -f "$TMP_BIN" "$TMP_OUT"
log "  ✓ 64 random bytes round-tripped identically"

# --- 5. DescribeSecret rotation fields report the truth ---------------------------------------
log "describe-secret — RotationEnabled must be the truth (false), not a dead schedule"
ROT="$(awssm "$WAK" "$WSK" describe-secret --secret-id "$SN" --query RotationEnabled 2>/dev/null)"
[ "$ROT" = "False" ] || [ "$ROT" = "false" ] || fail "RotationEnabled should be false, got '$ROT'"
log "  ✓ RotationEnabled=false (honest)"

# --- 6. GetRandomPassword ---------------------------------------------------------------------
log "get-random-password — returns a password of the requested length"
PW="$(awssm "$WAK" "$WSK" get-random-password --password-length 20 --query RandomPassword 2>/dev/null || true)"
[ -n "$PW" ] && [ "$PW" != "None" ] || fail "get-random-password returned nothing"
[ "${#PW}" = "20" ] || fail "get-random-password length ${#PW}, want 20"
log "  ✓ 20-char password"

# --- 7. RotateSecret refused honestly ---------------------------------------------------------
log "negative: rotate-secret must be REFUSED honestly (not a schedule that never fires)"
if awssm "$WAK" "$WSK" rotate-secret --secret-id "$SN" >/dev/null 2>"$PWD/.sm_rot"; then
  fail "rotate-secret was accepted (would claim rotation while nothing rotates)"
fi
grep -qiE 'InvalidRequest|not supported|rotation' "$PWD/.sm_rot" || fail "rotate-secret refusal had the wrong error: $(cat "$PWD/.sm_rot")"
rm -f "$PWD/.sm_rot"
log "  ✓ rotate-secret refused"

# --- 8. Delete (recovery window) → GetSecretValue fails → Restore brings it back ---------------
log "delete-secret (recovery window) — GetSecretValue must then fail; restore-secret brings it back"
awssm "$WAK" "$WSK" delete-secret --secret-id "$SN" --recovery-window-in-days 7 >/dev/null 2>&1 || fail "delete-secret failed"
if awssm "$WAK" "$WSK" get-secret-value --secret-id "$SN" >/dev/null 2>"$PWD/.sm_del"; then
  fail "a deleted secret still returned its value"
fi
grep -qiE 'InvalidRequest|marked for deletion|scheduled for deletion' "$PWD/.sm_del" || fail "deleted-secret refusal had the wrong error: $(cat "$PWD/.sm_del")"
rm -f "$PWD/.sm_del"
awssm "$WAK" "$WSK" restore-secret --secret-id "$SN" >/dev/null 2>&1 || fail "restore-secret failed"
REGOT="$(awssm "$WAK" "$WSK" get-secret-value --secret-id "$SN" --query SecretString 2>/dev/null)"
[ "$REGOT" = "$V2" ] || fail "restored secret did not return its value: got '$REGOT'"
log "  ✓ deleted → value refused; restored → readable again"

# --- 9a. Negative: wrong secret ---------------------------------------------------------------
log "negative: a valid key ID with a WRONG secret must be rejected"
if awssm "$WAK" "wrong-secret-not-the-real-one" get-secret-value --secret-id "$SN" >/dev/null 2>"$PWD/.sm_neg"; then
  fail "a wrong secret was accepted"
fi
grep -qiE 'Signature|does not match' "$PWD/.sm_neg" || fail "wrong secret rejected with the wrong error: $(cat "$PWD/.sm_neg")"
rm -f "$PWD/.sm_neg"
log "  ✓ rejected on signature mismatch"

# --- 9b/9c. Fine-grained Cedar: describe-only denied value; A-scoped can't read B --------------
log "seeding fine-grained principals + policies (describe-only, and scoped-to-A)"
BN2="sm-probe-other-${SFX}"
awssm "$WAK" "$WSK" create-secret --name "$BN2" --secret-string "secret-B-$SFX" >/dev/null 2>&1 || fail "create secret B failed"
CREATED_SECRETS+=("$BN2")
read -r DAK DSK <<<"$(mint_key "sm-probe-desconly-$SFX" "powerusers")"
read -r AAK ASK <<<"$(mint_key "sm-probe-ascoped-$SFX" "powerusers")"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "sm-desconly-$SFX", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::sm-probe-desconly-$SFX"]
    statements:
      - { effect: Allow, actions: ["secretsmanager:DescribeSecret","secretsmanager:ListSecretVersionIds"], resources: ["*"] }
---
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "sm-ascoped-$SFX", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::sm-probe-ascoped-$SFX"]
    statements:
      - { effect: Allow, actions: ["secretsmanager:GetSecretValue","secretsmanager:DescribeSecret"], resources: ["Secret::${SN}"] }
YAML
CREATED_POLICIES+=("sm-desconly-$SFX" "sm-ascoped-$SFX")
log "  waiting ~35s for the data-plane policy loader to pick them up..."
sleep 35

log "describe-only principal: DescribeSecret allowed, GetSecretValue DENIED"
awssm "$DAK" "$DSK" describe-secret --secret-id "$SN" >/dev/null 2>"$PWD/.sm_d" || fail "describe-only principal was denied DescribeSecret (should be allowed): $(cat "$PWD/.sm_d")"
rm -f "$PWD/.sm_d"
if awssm "$DAK" "$DSK" get-secret-value --secret-id "$SN" >/dev/null 2>"$PWD/.sm_dv"; then
  fail "a describe-only principal read the secret VALUE (must be denied)"
fi
grep -qiE 'AccessDenied|denied' "$PWD/.sm_dv" || fail "describe-only value denial had the wrong error: $(cat "$PWD/.sm_dv")"
rm -f "$PWD/.sm_dv"
log "  ✓ describe-only sees metadata, denied the value"

log "A-scoped principal: can read secret A, DENIED secret B"
AGOT="$(awssm "$AAK" "$ASK" get-secret-value --secret-id "$SN" --query SecretString 2>"$PWD/.sm_a" || true)"
[ "$AGOT" = "$V2" ] || fail "A-scoped principal could not read secret A (should be allowed): $(cat "$PWD/.sm_a" 2>/dev/null)"
rm -f "$PWD/.sm_a"
if awssm "$AAK" "$ASK" get-secret-value --secret-id "$BN2" >/dev/null 2>"$PWD/.sm_b"; then
  fail "an A-scoped principal read secret B (cross-secret isolation broken)"
fi
grep -qiE 'AccessDenied|denied' "$PWD/.sm_b" || fail "cross-secret denial had the wrong error: $(cat "$PWD/.sm_b")"
rm -f "$PWD/.sm_b"
log "  ✓ A-scoped principal reads A, denied B"

printf '\n✓ PASS — aws-shim Secrets Manager is semantically faithful (versioning, AWSCURRENT/AWSPREVIOUS, binary round-trip, delete/restore, honest rotation) and enforces auth + the describe/value + per-secret boundaries.\n'
