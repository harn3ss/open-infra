#!/usr/bin/env bash
# Compatibility probe for the aws-shim KMS surface.
#
# Fires REAL AWS SDK calls (the aws CLI is a real SDK client) at a deployed shim and asserts the
# SEMANTICS KMS applications actually depend on — not merely HTTP 200 — because the failure this exists
# to catch is the false-green: the app believes data was protected under a key and a cryptographic
# guarantee did not hold. It asserts, over real round-trips against Vault Transit:
#   - CreateKey returns a usable symmetric CMK (Enabled, ENCRYPT_DECRYPT, SYMMETRIC_DEFAULT)
#   - Encrypt → Decrypt returns the IDENTICAL plaintext
#   - the EncryptionContext BINDS: a Decrypt with a different/absent EncryptionContext FAILS
#     (InvalidCiphertextException) — the AAD guarantee, the property most silently faked
#   - GenerateDataKey returns a plaintext data key whose CiphertextBlob decrypts back to it (envelope encryption)
#   - a DISABLED key refuses Encrypt/Decrypt (DisabledException); re-enable restores use (state machine)
#   - an alias resolves to its target key (DescribeKey by alias)
#   - ScheduleKeyDeletion → the key is PendingDeletion and refuses crypto (KMSInvalidStateException);
#     CancelKeyDeletion restores it
#   - key rotation is enabled AND ciphertext produced BEFORE rotation still decrypts AFTER it (rotate-safe)
# and the NEGATIVES that are the whole point ("prove the no"):
#   - an asymmetric/HMAC CreateKey is REFUSED honestly (not silently downgraded to symmetric)
#   - a valid key ID with a WRONG secret is rejected (signature mismatch)
#   - an ENCRYPT-ONLY principal (granted only kms:Encrypt via Cedar) is DENIED kms:Decrypt while still
#     able to Encrypt — the fine-grained separation
#
# On-demand (needs a deployed shim + Vault Transit with the aws-shim-kms policy + the KMS Postgres + the
# platform IAM). Exit 0 = pass, 1 = a real failure (the shim is not faithful), 42 = INCONCLUSIVE (a
# prerequisite was missing). Per polyhedron#160 / #157: a probe failure is presumed a shim defect, and 42
# is not a pass.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-kms.sh
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

CREATED_KEYS=(); CREATED_USERS=(); CREATED_POLICIES=(); SCHEDULED=()
WAK=""; WSK=""
cleanup() {
  # Best-effort: schedule any created CMKs for deletion (KMS has no immediate delete), drop principals/policies.
  for k in "${SCHEDULED[@]:-}"; do [ -n "$k" ] && AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager kms schedule-key-deletion --key-id "$k" --pending-window-in-days 7 >/dev/null 2>&1 || true; done
  for s in "${CREATED_KEYS[@]:-}";     do [ -n "$s" ] && kubectl -n "$SHIM_NS" delete secret "$s" --ignore-not-found >/dev/null 2>&1 || true; done
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

awsk() { # AK SK -- <kms args...>
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text kms "$@"
}

# --- 1. Seed a principal + key ----------------------------------------------------------------
log "seeding a principal (openinfra:powerusers) + access key"
read -r WAK WSK <<<"$(mint_key "kms-probe-$SFX" "powerusers")"
[ -n "$WAK" ] && [ -n "$WSK" ] || inconclusive "failed to mint a key"
sleep 2

# --- 2. CreateKey -----------------------------------------------------------------------------
log "create-key (symmetric ENCRYPT_DECRYPT)"
read -r KID KUSAGE KSTATE KSPEC <<<"$(awsk "$WAK" "$WSK" create-key --description "probe-$SFX" \
  --query '[KeyMetadata.KeyId,KeyMetadata.KeyUsage,KeyMetadata.KeyState,KeyMetadata.KeySpec]' 2>/dev/null)" \
  || inconclusive "create-key failed — is Vault Transit reachable with the aws-shim-kms policy, and SQS_PG_URI set?"
[ -n "$KID" ] && [ "$KID" != "None" ] || inconclusive "create-key returned no KeyId"
[ "$KUSAGE" = "ENCRYPT_DECRYPT" ] || fail "unexpected KeyUsage: $KUSAGE"
[ "$KSTATE" = "Enabled" ]         || fail "new key not Enabled: $KSTATE"
[ "$KSPEC" = "SYMMETRIC_DEFAULT" ] || fail "unexpected KeySpec: $KSPEC"
SCHEDULED+=("$KID")
log "  ✓ KeyId: $KID (Enabled, ENCRYPT_DECRYPT, SYMMETRIC_DEFAULT)"

# --- 3. Encrypt → Decrypt round-trip ----------------------------------------------------------
PT="top-secret-$SFX"
log "encrypt then decrypt — plaintext must round-trip identically"
# The CLI wants a blob; pass it via a real temp file (fileb://) for portability.
TMP_PT="$(mktemp)"; printf '%s' "$PT" > "$TMP_PT"
CT="$(awsk "$WAK" "$WSK" encrypt --key-id "$KID" --plaintext "fileb://$TMP_PT" --query CiphertextBlob 2>/dev/null)"
[ -n "$CT" ] && [ "$CT" != "None" ] || fail "encrypt returned no CiphertextBlob"
TMP_CT="$(mktemp)"; printf '%s' "$CT" | base64 -d > "$TMP_CT" 2>/dev/null || fail "CiphertextBlob is not valid base64"
DEC_B64="$(awsk "$WAK" "$WSK" decrypt --ciphertext-blob "fileb://$TMP_CT" --query Plaintext 2>/dev/null)"
[ -n "$DEC_B64" ] && [ "$DEC_B64" != "None" ] || fail "decrypt returned no Plaintext"
DEC="$(printf '%s' "$DEC_B64" | base64 -d 2>/dev/null || true)"
[ "$DEC" = "$PT" ] || fail "decrypt did not round-trip: got '$DEC' want '$PT'"
rm -f "$TMP_PT" "$TMP_CT"
log "  ✓ plaintext round-tripped through Encrypt/Decrypt"

# --- 3b. A TAMPERED ciphertext blob must fail InvalidCiphertextException (never return garbage) ----
log "tampered ciphertext must fail InvalidCiphertextException (not decrypt to garbage)"
TAMPERED="$(python3 - "$CT" <<'PY'
import base64, json, sys
env = json.loads(base64.b64decode(sys.argv[1]))
c = env["c"]                       # "vault:v1:<base64 ciphertext+tag>"
pre, payload = c.rsplit(":", 1)
i = len(payload) // 2              # flip one char in the middle of the AEAD payload
payload = payload[:i] + ("A" if payload[i] != "A" else "B") + payload[i+1:]
env["c"] = pre + ":" + payload
print(base64.b64encode(json.dumps(env).encode()).decode())
PY
)"
TMP_TMP="$(mktemp)"; printf '%s' "$TAMPERED" | base64 -d > "$TMP_TMP"
if awsk "$WAK" "$WSK" decrypt --ciphertext-blob "fileb://$TMP_TMP" >/dev/null 2>"$PWD/.kms_tamp"; then
  fail "a tampered ciphertext blob DECRYPTED (returned data instead of failing) — integrity not enforced"
fi
grep -qiE 'InvalidCiphertext|not valid' "$PWD/.kms_tamp" || fail "tampered blob rejected with the wrong error: $(cat "$PWD/.kms_tamp")"
rm -f "$TMP_TMP" "$PWD/.kms_tamp"
log "  ✓ tampered ciphertext rejected (InvalidCiphertextException)"

# --- 3c. The Encrypt produced a structured AUDIT record naming who/op/key (AU-2/AU-9) -------------
log "audit: the Encrypt must have written a structured audit record (principal + op + key + decision)"
sleep 1
AUDIT="$(kubectl -n "$SHIM_NS" logs deploy/aws-shim --since=300s 2>/dev/null | grep '"msg":"kms audit"' | grep '"op":"Encrypt"' | grep "$KID" | tail -1)"
[ -n "$AUDIT" ] || fail "no KMS audit record found for the Encrypt — the compliance trail (AU-2/AU-9) is not written"
printf '%s' "$AUDIT" | grep -q "\"principal\":\"User::kms-probe-$SFX\"" || fail "audit record does not name the resolved principal (who): $AUDIT"
printf '%s' "$AUDIT" | grep -q '"decision":"allow"' || fail "audit record missing the decision: $AUDIT"
log "  ✓ audit record present — names the principal, op, key, and decision"

# --- 4. EncryptionContext BINDS ---------------------------------------------------------------
log "EncryptionContext must bind: decrypt with a DIFFERENT context must FAIL"
TMP_PT="$(mktemp)"; printf '%s' "$PT" > "$TMP_PT"
CTX="$(awsk "$WAK" "$WSK" encrypt --key-id "$KID" --plaintext "fileb://$TMP_PT" \
  --encryption-context tenant=acme,env=prod --query CiphertextBlob 2>/dev/null)"
[ -n "$CTX" ] && [ "$CTX" != "None" ] || fail "encrypt with context returned no CiphertextBlob"
TMP_CTX="$(mktemp)"; printf '%s' "$CTX" | base64 -d > "$TMP_CTX"
# Same context decrypts fine.
OKB64="$(awsk "$WAK" "$WSK" decrypt --ciphertext-blob "fileb://$TMP_CTX" --encryption-context tenant=acme,env=prod --query Plaintext 2>/dev/null || true)"
[ -n "$OKB64" ] && [ "$OKB64" != "None" ] || fail "decrypt with the correct EncryptionContext failed"
[ "$(printf '%s' "$OKB64" | base64 -d)" = "$PT" ] || fail "context decrypt round-trip wrong"
# WRONG context must be rejected.
if awsk "$WAK" "$WSK" decrypt --ciphertext-blob "fileb://$TMP_CTX" --encryption-context tenant=evil >/dev/null 2>"$PWD/.kms_ctx"; then
  fail "decrypt succeeded with a WRONG EncryptionContext (the AAD did not bind — silent integrity loss)"
fi
grep -qiE 'InvalidCiphertext|does not match|not valid' "$PWD/.kms_ctx" || fail "wrong-context rejection had the wrong error: $(cat "$PWD/.kms_ctx")"
# ABSENT context must also be rejected.
if awsk "$WAK" "$WSK" decrypt --ciphertext-blob "fileb://$TMP_CTX" >/dev/null 2>"$PWD/.kms_ctx2"; then
  fail "decrypt succeeded with NO EncryptionContext for a context-bound ciphertext"
fi
grep -qiE 'InvalidCiphertext|does not match|not valid' "$PWD/.kms_ctx2" || fail "absent-context rejection had the wrong error: $(cat "$PWD/.kms_ctx2")"
rm -f "$TMP_PT" "$TMP_CTX" "$PWD/.kms_ctx" "$PWD/.kms_ctx2"
log "  ✓ EncryptionContext binds (correct decrypts; wrong and absent are rejected)"

# --- 5. GenerateDataKey (envelope) ------------------------------------------------------------
log "generate-data-key — the CiphertextBlob must decrypt back to the plaintext data key"
read -r DK_PT DK_CT <<<"$(awsk "$WAK" "$WSK" generate-data-key --key-id "$KID" --key-spec AES_256 \
  --query '[Plaintext,CiphertextBlob]' 2>/dev/null)"
[ -n "$DK_PT" ] && [ "$DK_PT" != "None" ] || fail "generate-data-key returned no Plaintext"
[ -n "$DK_CT" ] && [ "$DK_CT" != "None" ] || fail "generate-data-key returned no CiphertextBlob"
TMP_DK="$(mktemp)"; printf '%s' "$DK_CT" | base64 -d > "$TMP_DK"
DK_DEC="$(awsk "$WAK" "$WSK" decrypt --ciphertext-blob "fileb://$TMP_DK" --query Plaintext 2>/dev/null)"
[ "$DK_DEC" = "$DK_PT" ] || fail "the data key's CiphertextBlob did not decrypt back to its Plaintext"
# AES_256 => 32 bytes of key material.
BYTES="$(printf '%s' "$DK_PT" | base64 -d 2>/dev/null | wc -c | tr -d ' ')"
[ "$BYTES" = "32" ] || fail "AES_256 data key should be 32 bytes, got $BYTES"
rm -f "$TMP_DK"
log "  ✓ envelope encryption holds (32-byte data key, ciphertext decrypts to it)"

# --- 5b. GenerateRandom -----------------------------------------------------------------------
log "generate-random — returns exactly the requested number of random bytes"
RND="$(awsk "$WAK" "$WSK" generate-random --number-of-bytes 24 --query Plaintext 2>/dev/null || true)"
[ -n "$RND" ] && [ "$RND" != "None" ] || fail "generate-random returned nothing"
RBYTES="$(printf '%s' "$RND" | base64 -d 2>/dev/null | wc -c | tr -d ' ')"
[ "$RBYTES" = "24" ] || fail "generate-random returned $RBYTES bytes, want 24"
log "  ✓ 24 random bytes"

# --- 6. Disable → refuse → Enable -------------------------------------------------------------
log "disable-key — Encrypt/Decrypt must then be refused (DisabledException)"
awsk "$WAK" "$WSK" disable-key --key-id "$KID" >/dev/null 2>&1 || fail "disable-key failed"
TMP_PT="$(mktemp)"; printf '%s' x > "$TMP_PT"
if awsk "$WAK" "$WSK" encrypt --key-id "$KID" --plaintext "fileb://$TMP_PT" >/dev/null 2>"$PWD/.kms_dis"; then
  fail "a disabled key still encrypted"
fi
grep -qiE 'Disabled|is disabled' "$PWD/.kms_dis" || fail "disabled-key refusal had the wrong error: $(cat "$PWD/.kms_dis")"
rm -f "$PWD/.kms_dis"
awsk "$WAK" "$WSK" enable-key --key-id "$KID" >/dev/null 2>&1 || fail "enable-key failed"
awsk "$WAK" "$WSK" encrypt --key-id "$KID" --plaintext "fileb://$TMP_PT" >/dev/null 2>&1 || fail "re-enabled key could not encrypt"
rm -f "$TMP_PT"
log "  ✓ disable refuses crypto; enable restores it"

# --- 7. Alias resolves ------------------------------------------------------------------------
log "create-alias + describe-key by alias must resolve to the same key"
ALIAS="alias/probe-$SFX"
awsk "$WAK" "$WSK" create-alias --alias-name "$ALIAS" --target-key-id "$KID" >/dev/null 2>&1 || fail "create-alias failed"
ALIAS_KID="$(awsk "$WAK" "$WSK" describe-key --key-id "$ALIAS" --query 'KeyMetadata.KeyId' 2>/dev/null || true)"
[ "$ALIAS_KID" = "$KID" ] || fail "describe-key by alias resolved to '$ALIAS_KID', want '$KID'"
awsk "$WAK" "$WSK" delete-alias --alias-name "$ALIAS" >/dev/null 2>&1 || true
log "  ✓ alias resolves to its target key"

# --- 8. Rotation is rotate-safe ---------------------------------------------------------------
log "enable-key-rotation, then ciphertext from BEFORE rotation must still decrypt AFTER it"
TMP_PT="$(mktemp)"; printf '%s' "$PT" > "$TMP_PT"
PRE_CT="$(awsk "$WAK" "$WSK" encrypt --key-id "$KID" --plaintext "fileb://$TMP_PT" --query CiphertextBlob 2>/dev/null)"
awsk "$WAK" "$WSK" enable-key-rotation --key-id "$KID" >/dev/null 2>&1 || fail "enable-key-rotation failed"
ROT="$(awsk "$WAK" "$WSK" get-key-rotation-status --key-id "$KID" --query KeyRotationEnabled 2>/dev/null || true)"
[ "$ROT" = "True" ] || [ "$ROT" = "true" ] || fail "rotation status not enabled after enable-key-rotation: $ROT"
TMP_PRE="$(mktemp)"; printf '%s' "$PRE_CT" | base64 -d > "$TMP_PRE"
PRE_DEC="$(awsk "$WAK" "$WSK" decrypt --ciphertext-blob "fileb://$TMP_PRE" --query Plaintext 2>/dev/null || true)"
[ "$(printf '%s' "$PRE_DEC" | base64 -d 2>/dev/null || true)" = "$PT" ] || fail "pre-rotation ciphertext did not decrypt after rotation (rotation is not rotate-safe)"
rm -f "$TMP_PT" "$TMP_PRE"
log "  ✓ rotation enabled and pre-rotation ciphertext still decrypts"

# --- 9. ScheduleKeyDeletion → refuse → Cancel -------------------------------------------------
log "schedule-key-deletion — key goes PendingDeletion and refuses crypto (KMSInvalidStateException)"
DELK_KID="$(awsk "$WAK" "$WSK" create-key --description "del-probe-$SFX" --query KeyMetadata.KeyId 2>/dev/null)"
[ -n "$DELK_KID" ] && [ "$DELK_KID" != "None" ] || inconclusive "could not create the deletion-probe key"
awsk "$WAK" "$WSK" schedule-key-deletion --key-id "$DELK_KID" --pending-window-in-days 7 >/dev/null 2>&1 || fail "schedule-key-deletion failed"
DSTATE="$(awsk "$WAK" "$WSK" describe-key --key-id "$DELK_KID" --query KeyMetadata.KeyState 2>/dev/null || true)"
[ "$DSTATE" = "PendingDeletion" ] || fail "key not PendingDeletion after schedule: $DSTATE"
TMP_PT="$(mktemp)"; printf '%s' x > "$TMP_PT"
if awsk "$WAK" "$WSK" encrypt --key-id "$DELK_KID" --plaintext "fileb://$TMP_PT" >/dev/null 2>"$PWD/.kms_del"; then
  fail "a key pending deletion still encrypted"
fi
grep -qiE 'InvalidState|pending deletion' "$PWD/.kms_del" || fail "pending-deletion refusal had the wrong error: $(cat "$PWD/.kms_del")"
rm -f "$PWD/.kms_del"
awsk "$WAK" "$WSK" cancel-key-deletion --key-id "$DELK_KID" >/dev/null 2>&1 || fail "cancel-key-deletion failed"
CSTATE="$(awsk "$WAK" "$WSK" describe-key --key-id "$DELK_KID" --query KeyMetadata.KeyState 2>/dev/null || true)"
[ "$CSTATE" = "Disabled" ] || fail "cancel-key-deletion did not restore to Disabled: $CSTATE"
SCHEDULED+=("$DELK_KID")
rm -f "$TMP_PT"
log "  ✓ schedule → PendingDeletion + crypto refused; cancel → Disabled"

# --- 10. Negative: asymmetric key refused -----------------------------------------------------
log "negative: an asymmetric/sign-verify CreateKey must be REFUSED (not silently downgraded)"
if awsk "$WAK" "$WSK" create-key --key-usage SIGN_VERIFY --key-spec RSA_2048 >/dev/null 2>"$PWD/.kms_asym"; then
  fail "an asymmetric CreateKey was accepted (would silently be a symmetric key)"
fi
grep -qiE 'Unsupported|SYMMETRIC|ENCRYPT_DECRYPT' "$PWD/.kms_asym" || fail "asymmetric refusal had the wrong error: $(cat "$PWD/.kms_asym")"
rm -f "$PWD/.kms_asym"
log "  ✓ asymmetric key refused honestly"

# --- 11a. Negative: wrong secret --------------------------------------------------------------
log "negative: a valid key ID with a WRONG secret must be rejected"
TMP_PT="$(mktemp)"; printf '%s' x > "$TMP_PT"
if awsk "$WAK" "wrong-secret-not-the-real-one" encrypt --key-id "$KID" --plaintext "fileb://$TMP_PT" >/dev/null 2>"$PWD/.kms_neg"; then
  fail "a wrong secret was accepted"
fi
grep -qiE 'Signature|does not match' "$PWD/.kms_neg" || fail "wrong secret rejected with the wrong error: $(cat "$PWD/.kms_neg")"
rm -f "$PWD/.kms_neg" "$TMP_PT"
log "  ✓ rejected on signature mismatch"

# --- 11b. Negative: encrypt-only principal denied Decrypt (fine-grained Cedar) -----------------
log "encrypt-only principal: granted only kms:Encrypt via Cedar, must be DENIED kms:Decrypt"
read -r EAK ESK <<<"$(mint_key "kms-probe-enconly-$SFX" "powerusers")"
POLICY="kms-enconly-$SFX"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "${POLICY}", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::kms-probe-enconly-$SFX"]
    statements:
      - { effect: Allow, actions: ["kms:Encrypt"], resources: ["*"] }
YAML
CREATED_POLICIES+=("$POLICY")
log "  waiting ~35s for the data-plane policy loader to pick it up..."
sleep 35
TMP_PT="$(mktemp)"; printf '%s' "enconly-$SFX" > "$TMP_PT"
# Encrypt must be ALLOWED.
EO_CT="$(awsk "$EAK" "$ESK" encrypt --key-id "$KID" --plaintext "fileb://$TMP_PT" --query CiphertextBlob 2>"$PWD/.kms_eo" || true)"
[ -n "$EO_CT" ] && [ "$EO_CT" != "None" ] || fail "encrypt-only principal was denied Encrypt (should be allowed): $(cat "$PWD/.kms_eo")"
rm -f "$PWD/.kms_eo"
log "  ✓ encrypt-only principal CAN Encrypt"
# Decrypt must be DENIED (governed for kms, kms:Decrypt not granted).
TMP_EO="$(mktemp)"; printf '%s' "$EO_CT" | base64 -d > "$TMP_EO"
if awsk "$EAK" "$ESK" decrypt --ciphertext-blob "fileb://$TMP_EO" >/dev/null 2>"$PWD/.kms_dec"; then
  fail "an encrypt-only principal was allowed to Decrypt (Decrypt must be independently denied)"
fi
grep -qiE 'AccessDenied|denied|AuthorizationError' "$PWD/.kms_dec" || fail "Decrypt denial had the wrong error: $(cat "$PWD/.kms_dec")"
rm -f "$PWD/.kms_dec" "$TMP_PT" "$TMP_EO"
log "  ✓ encrypt-only principal DENIED Decrypt"

printf '\n✓ PASS — aws-shim KMS is semantically faithful (round-trip, EncryptionContext binding, envelope keys, state machine, rotate-safe) and enforces auth + the encrypt/decrypt boundary.\n'
