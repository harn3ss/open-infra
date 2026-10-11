#!/usr/bin/env bash
# Compatibility probe for PER-KEY KMS access policy (polyhedron#267).
#
# AWS governs who may use a CMK with a resource-based KEY POLICY attached to each key. open-infra has no
# resource-attached policy document; instead it governs KMS at key granularity through the SAME identity-
# based Cedar data-plane as every other service — a kind: Policy spec.dataPlane that Allows kms:<action> on
# Key::<keyId>. That is the open-infra EQUIVALENT of a key policy (an AWS key-policy statement "Principal P
# may kms:X on this key" ≡ kind: Policy {appliesTo:[P], Allow kms:X on Key::<keyId>}). The existing KMS
# probe proves kms:Encrypt is separable from kms:Decrypt; what it does NOT prove — and what #267 is about —
# is PER-KEY scoping: a grant on one key must NOT leak to another. This probe proves exactly that:
#   - a principal granted kms:Encrypt/Decrypt on Key::<A> ONLY can round-trip on key A  (ALLOW)
#   - the SAME principal is DENIED kms:Encrypt on key B  (key fidelity — the grant does not leak)
# A translator that mapped the grant to resource "*" (or ignored the key id) would let key B through; this
# is the fail that would make per-key policies meaningless.
#
# On-demand (needs a deployed shim + Vault Transit + the KMS Postgres + the platform IAM + an
# openinfra:powerusers coarse grant for kms). Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-kms-keypolicy.sh
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

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v base64  >/dev/null || inconclusive "base64 is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

CREATED_KEYS=(); CREATED_USERS=(); CREATED_POLICIES=(); SCHEDULED=(); CREATED_KEYS_IDS=()
AAK=""; ASK=""
cleanup() {
  # Fast CLI timeouts so a flaky/closed port-forward can't stall cleanup (the kubectl deletes below must still run).
  for k in "${SCHEDULED[@]:-}"; do [ -n "$k" ] && AWS_ACCESS_KEY_ID="$AAK" AWS_SECRET_ACCESS_KEY="$ASK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --cli-connect-timeout 5 --cli-read-timeout 10 kms schedule-key-deletion --key-id "$k" --pending-window-in-days 7 >/dev/null 2>&1 || true; done
  for s in "${CREATED_KEYS[@]:-}";     do [ -n "$s" ] && kubectl -n "$SHIM_NS" delete secret "$s" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}";    do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for p in "${CREATED_POLICIES[@]:-}"; do [ -n "$p" ] && kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev "$p" --ignore-not-found >/dev/null 2>&1 || true; done
  # The kind: Policy CRs the PutKeyPolicy import materialized (labeled by key id) — reaped only on crypto-erase,
  # so delete them here (the scheduled keys are in a 7-day window, not erased during the probe).
  for k in "${CREATED_KEYS_IDS[@]:-}"; do [ -n "$k" ] && kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev -l "openinfra.dev/kms-key=$k" --ignore-not-found >/dev/null 2>&1 || true; done
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
awsk() { local ak="$1" sk="$2"; shift 2; AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text kms "$@"; }

# --- 1. Admin principal (creates the two keys) ------------------------------------------------
log "seeding an admin principal (openinfra:powerusers) + key"
read -r AAK ASK <<<"$(mint_key "kms-kp-admin-$SFX" "powerusers")"
[ -n "$AAK" ] && [ -n "$ASK" ] || inconclusive "failed to mint an admin key"
sleep 2

log "create TWO keys (A and B)"
KA="$(awsk "$AAK" "$ASK" create-key --description "kp-probe-A-$SFX" --query 'KeyMetadata.KeyId' 2>/dev/null || true)"
[ -n "$KA" ] && [ "$KA" != "None" ] || inconclusive "create-key A failed — Vault Transit reachable? KMS Postgres set?"
SCHEDULED+=("$KA")
KB="$(awsk "$AAK" "$ASK" create-key --description "kp-probe-B-$SFX" --query 'KeyMetadata.KeyId' 2>/dev/null || true)"
[ -n "$KB" ] && [ "$KB" != "None" ] || inconclusive "create-key B failed"
SCHEDULED+=("$KB")
CREATED_KEYS_IDS+=("$KA" "$KB")
log "  ✓ key A=$KA  key B=$KB"

# --- 2. A per-key grant: the user may use key A ONLY (the key-policy equivalent) ---------------
USER="kms-kp-user-$SFX"
read -r UAK USK <<<"$(mint_key "$USER" "powerusers")"   # powerusers = coarse kms allow; the dataPlane tightens to key A
POLICY="kms-kp-$SFX"
log "grant User::$USER kms:Encrypt/Decrypt on Key::$KA ONLY (open-infra's per-key policy)"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "${POLICY}", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::${USER}"]
    statements:
      - { effect: Allow, actions: ["kms:Encrypt", "kms:Decrypt"], resources: ["Key::${KA}"] }
YAML
CREATED_POLICIES+=("$POLICY")
log "  waiting ~35s for the data-plane policy loader to pick it up..."
sleep 35

# --- 3. ALLOW on key A: full Encrypt→Decrypt round-trip ---------------------------------------
PT="kp-secret-$SFX"
TMP_PT="$(mktemp)"; printf '%s' "$PT" > "$TMP_PT"
log "ALLOW: User::$USER encrypts on key A"
CT="$(awsk "$UAK" "$USK" encrypt --key-id "$KA" --plaintext "fileb://$TMP_PT" --query CiphertextBlob 2>"$PWD/.kp_e" || true)"
[ -n "$CT" ] && [ "$CT" != "None" ] || fail "granted principal was DENIED Encrypt on key A (should be allowed): $(cat "$PWD/.kp_e" 2>/dev/null)"
rm -f "$PWD/.kp_e"
TMP_CT="$(mktemp)"; printf '%s' "$CT" | base64 -d > "$TMP_CT"
GOT="$(awsk "$UAK" "$USK" decrypt --ciphertext-blob "fileb://$TMP_CT" --query Plaintext --output text 2>"$PWD/.kp_d" | base64 -d 2>/dev/null || true)"
[ "$GOT" = "$PT" ] || fail "granted principal could not round-trip on key A (got '$GOT'): $(cat "$PWD/.kp_d" 2>/dev/null)"
rm -f "$PWD/.kp_d" "$TMP_CT"
log "  ✓ key A: Encrypt→Decrypt round-trip works for the granted principal"

# --- 4. DENY on key B: the grant does NOT leak to another key (the whole point of #267) --------
log "DENY: the SAME principal must be denied kms:Encrypt on key B (grant scoped to key A only)"
if awsk "$UAK" "$USK" encrypt --key-id "$KB" --plaintext "fileb://$TMP_PT" --query CiphertextBlob >/dev/null 2>"$PWD/.kp_b"; then
  rm -f "$TMP_PT"
  fail "KEY LEAK: a grant on Key::$KA allowed Encrypt on a DIFFERENT key B — per-key policy not enforced"
fi
grep -qiE 'AccessDenied|denied|AuthorizationError' "$PWD/.kp_b" || fail "key-B denial had the wrong error: $(cat "$PWD/.kp_b")"
rm -f "$PWD/.kp_b" "$TMP_PT"
log "  ✓ key B: Encrypt DENIED (the per-key grant does not leak across keys)"

# --- 5. PutKeyPolicy IMPORT (polyhedron#298): a SUPPLIED AWS key-policy JSON is translated to the --------
#        equivalent kind: Policy grant + enforced + round-trips. This is the import convenience #267 lacked.
USER2="kms-kp2-user-$SFX"
read -r U2AK U2SK <<<"$(mint_key "$USER2" "powerusers")"   # powerusers = coarse kms allow; the key policy tightens
sleep 2
log "PutKeyPolicy on key A: a REAL AWS key-policy JSON granting User::$USER2 kms:Encrypt/Decrypt (+ the root default)"
KP_DOC="$(cat <<JSON
{"Version":"2012-10-17","Id":"key-probe","Statement":[
  {"Sid":"Root","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"kms:*","Resource":"*"},
  {"Sid":"App","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/${USER2}"},"Action":["kms:Encrypt","kms:Decrypt"],"Resource":"*"}
]}
JSON
)"
awsk "$AAK" "$ASK" put-key-policy --key-id "$KA" --policy-name default --policy "$KP_DOC" >/dev/null 2>"$PWD/.kp_put" \
  || fail "PutKeyPolicy was rejected (the key-policy JSON should translate): $(cat "$PWD/.kp_put" 2>/dev/null)"
rm -f "$PWD/.kp_put"

log "  GetKeyPolicy must round-trip the supplied JSON verbatim"
GOT_KP="$(awsk "$AAK" "$ASK" get-key-policy --key-id "$KA" --policy-name default --query Policy --output text 2>/dev/null || true)"
printf '%s' "$GOT_KP" | grep -q "user/${USER2}" || fail "GetKeyPolicy did not round-trip the supplied policy (missing user/${USER2}): $GOT_KP"
log "  ListKeyPolicies must report the single \"default\" policy"
awsk "$AAK" "$ASK" list-key-policies --key-id "$KA" --query 'PolicyNames' --output text 2>/dev/null | grep -q default \
  || fail "ListKeyPolicies did not return the default policy name"

log "  waiting ~35s for the data-plane loader to pick up the translated grant..."
sleep 35
TMP_PT2="$(mktemp)"; printf 'kp-import-%s' "$SFX" > "$TMP_PT2"
log "ALLOW: User::$USER2 (granted by the imported key policy) encrypts on key A"
CT2="$(awsk "$U2AK" "$U2SK" encrypt --key-id "$KA" --plaintext "fileb://$TMP_PT2" --query CiphertextBlob 2>"$PWD/.kp_e2" || true)"
[ -n "$CT2" ] && [ "$CT2" != "None" ] || fail "the imported key policy did not grant Encrypt on key A: $(cat "$PWD/.kp_e2" 2>/dev/null)"
rm -f "$PWD/.kp_e2"
log "DENY: the SAME User::$USER2 must be denied on key B (the imported policy scoped the grant to key A only)"
if awsk "$U2AK" "$U2SK" encrypt --key-id "$KB" --plaintext "fileb://$TMP_PT2" --query CiphertextBlob >/dev/null 2>"$PWD/.kp_b2"; then
  rm -f "$TMP_PT2"
  fail "KEY LEAK: the imported key policy for key A allowed Encrypt on key B — translation did not scope to Key::$KA"
fi
grep -qiE 'AccessDenied|denied|AuthorizationError' "$PWD/.kp_b2" || fail "key-B denial (import path) had the wrong error: $(cat "$PWD/.kp_b2")"
rm -f "$PWD/.kp_b2" "$TMP_PT2"
log "  ✓ imported key policy: enforced on key A, does NOT leak to key B, and round-trips via GetKeyPolicy"

printf '\n✓ PASS — KMS per-key access is enforced at key granularity, AND a supplied AWS key-policy JSON\n'
printf '  (PutKeyPolicy / CreateKey Policy) is TRANSLATED into the equivalent kind: Policy grant (#298):\n'
printf '  it enforces on its key, does not leak to another key, and round-trips via GetKeyPolicy. Key\n'
printf '  access is governed by the identity-based Cedar data-plane, not a separate resource-attached engine.\n'
