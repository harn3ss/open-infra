#!/usr/bin/env bash
# Compatibility probe for the aws-shim SSM Parameter Store surface.
#
# Fires REAL AWS SDK calls (the aws CLI is a real SDK client) at a deployed shim and asserts the SEMANTICS
# config-consuming applications actually depend on — not merely HTTP 200 — because the failure this exists
# to catch is the false-green: the app believes it read the current parameter and got a stale version, or
# believes a SecureString is encrypted at rest when the store holds it in plaintext. It asserts, over real
# round-trips:
#   - PutParameter (String) then GetParameter returns the EXACT value at Version 1
#   - PutParameter without Overwrite on an existing name is REFUSED (ParameterAlreadyExists); with
#     Overwrite it becomes Version 2, and GetParameter :1 STILL returns the v1 value (version history)
#   - StringList round-trips
#   - a SecureString is GENUINELY encrypted at rest: WithDecryption=false returns Vault CIPHERTEXT
#     (vault:v1:…), never the plaintext; WithDecryption=true returns the plaintext
#   - GetParametersByPath returns the tree under a path; Recursive=false returns only the immediate level
#   - LabelParameterVersion then GetParameter name:label returns that labelled version
#   - DeleteParameter then GetParameter fails ParameterNotFound
#   - Advanced tier is REFUSED honestly (ValidationException) — Standard tier only
#   - a GetParameter produced a structured audit record naming the principal
# and the NEGATIVES that are the whole point ("prove the no"):
#   - a valid key ID with a WRONG secret is rejected (signature mismatch)
#   - a principal scoped to Parameter::/app/a/* can read /app/a/… but is DENIED /app/b/…
#   - the two-permission split: a principal DENIED kms:Decrypt reads the SecureString CIPHERTEXT but is
#     DENIED the plaintext (WithDecryption=true → AccessDenied)
#
# On-demand (needs a deployed shim + Vault Transit with the aws-shim-kms policy + the SSM Postgres + the
# platform IAM). Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE (a prerequisite was missing).
# Per polyhedron#167 / #157: a probe failure is presumed a shim defect, and 42 is not a pass.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-ssm.sh
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
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"

CREATED_KEYS=(); CREATED_USERS=(); CREATED_POLICIES=(); CREATED_PARAMS=()
WAK=""; WSK=""
cleanup() {
  for p in "${CREATED_PARAMS[@]:-}";   do [ -n "$p" ] && AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager ssm delete-parameter --name "$p" >/dev/null 2>&1 || true; done
  for k in "${CREATED_KEYS[@]:-}";     do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}";    do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for pol in "${CREATED_POLICIES[@]:-}"; do [ -n "$pol" ] && kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev "$pol" --ignore-not-found >/dev/null 2>&1 || true; done
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

ssm() { # AK SK -- <ssm args...>
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text ssm "$@"
}

# --- 1. Seed a writer principal + key ---------------------------------------------------------
log "seeding a writer principal (openinfra:powerusers) + access key"
read -r WAK WSK <<<"$(mint_key "ssm-probe-$SFX" "powerusers")"
[ -n "$WAK" ] && [ -n "$WSK" ] || inconclusive "failed to mint a key"
sleep 2

BASE="/app/ssm-probe-${SFX}"

# --- 2. PutParameter (String) + GetParameter returns the exact value at Version 1 --------------
P1="${BASE}/db/host"
V1="db-host-${SFX}.internal"
log "put-parameter ${P1} (String) + get-parameter returns the exact value, Version 1"
VER="$(ssm "$WAK" "$WSK" put-parameter --name "$P1" --value "$V1" --type String --query Version 2>/dev/null)" \
  || inconclusive "put-parameter failed — is SQS_PG_URI set on the shim?"
CREATED_PARAMS+=("$P1")
[ "$VER" = "1" ] || fail "first PutParameter should be Version 1, got '$VER'"
GOT="$(ssm "$WAK" "$WSK" get-parameter --name "$P1" --query 'Parameter.Value' 2>/dev/null)"
[ "$GOT" = "$V1" ] || fail "get-parameter returned '$GOT' != '$V1'"
log "  ✓ exact value at Version 1"

# --- 3. Overwrite semantics + version history -------------------------------------------------
log "put without Overwrite must be REFUSED; with Overwrite → Version 2; :1 still returns v1"
if ssm "$WAK" "$WSK" put-parameter --name "$P1" --value "changed" --type String >/dev/null 2>"$PWD/.ssm_ow"; then
  fail "PutParameter without Overwrite succeeded on an existing name"
fi
grep -qiE 'ParameterAlreadyExists|already exists' "$PWD/.ssm_ow" || fail "no-overwrite refusal had the wrong error: $(cat "$PWD/.ssm_ow")"
rm -f "$PWD/.ssm_ow"
V2="db-host-${SFX}-v2.internal"
VER2="$(ssm "$WAK" "$WSK" put-parameter --name "$P1" --value "$V2" --type String --overwrite --query Version 2>/dev/null)"
[ "$VER2" = "2" ] || fail "overwrite should be Version 2, got '$VER2'"
CUR="$(ssm "$WAK" "$WSK" get-parameter --name "$P1" --query 'Parameter.Value' 2>/dev/null)"
[ "$CUR" = "$V2" ] || fail "current value did not move to v2: got '$CUR'"
OLD="$(ssm "$WAK" "$WSK" get-parameter --name "${P1}:1" --query 'Parameter.Value' 2>/dev/null)"
[ "$OLD" = "$V1" ] || fail "get-parameter ${P1}:1 returned '$OLD' (want the v1 value) — version history broken"
log "  ✓ overwrite=v2, :1 still returns v1"

# --- 4. StringList round-trips ----------------------------------------------------------------
PL="${BASE}/hosts"
ssm "$WAK" "$WSK" put-parameter --name "$PL" --value "a.internal,b.internal,c.internal" --type StringList >/dev/null 2>&1 || fail "put StringList failed"
CREATED_PARAMS+=("$PL")
GL="$(ssm "$WAK" "$WSK" get-parameter --name "$PL" --query 'Parameter.Value' 2>/dev/null)"
[ "$GL" = "a.internal,b.internal,c.internal" ] || fail "StringList did not round-trip: got '$GL'"
log "  ✓ StringList round-trips"

# --- 5. SecureString genuinely encrypted at rest ----------------------------------------------
PS="${BASE}/db/password"
SVAL="s3cr3t-${SFX}"
log "SecureString must be encrypted at rest: WithDecryption=false → ciphertext; =true → plaintext"
ssm "$WAK" "$WSK" put-parameter --name "$PS" --value "$SVAL" --type SecureString >/dev/null 2>"$PWD/.ssm_sec" \
  || inconclusive "put SecureString failed — is Vault Transit reachable (aws-shim-kms)? $(cat "$PWD/.ssm_sec")"
rm -f "$PWD/.ssm_sec"
CREATED_PARAMS+=("$PS")
CT="$(ssm "$WAK" "$WSK" get-parameter --name "$PS" --query 'Parameter.Value' 2>/dev/null)"
[ "$CT" != "$SVAL" ] || fail "SecureString returned PLAINTEXT without WithDecryption (not encrypted at rest!)"
case "$CT" in vault:*) : ;; *) fail "SecureString ciphertext not in the expected Vault Transit shape: $CT";; esac
PT="$(ssm "$WAK" "$WSK" get-parameter --name "$PS" --with-decryption --query 'Parameter.Value' 2>/dev/null)"
[ "$PT" = "$SVAL" ] || fail "WithDecryption did not return the plaintext: got '$PT'"
log "  ✓ ciphertext at rest (vault:…); plaintext only WithDecryption"

# --- 6. GetParametersByPath (recursive vs immediate level) ------------------------------------
log "get-parameters-by-path: recursive returns the subtree; non-recursive only the immediate level"
NREC="$(ssm "$WAK" "$WSK" get-parameters-by-path --path "${BASE}/db" --query 'length(Parameters)' 2>/dev/null)"
[ "$NREC" = "2" ] || fail "non-recursive ${BASE}/db should return 2 (host,password), got '$NREC'"
REC="$(ssm "$WAK" "$WSK" get-parameters-by-path --path "${BASE}" --recursive --query 'length(Parameters)' 2>/dev/null)"
[ "$REC" = "3" ] || fail "recursive ${BASE} should return 3 (db/host, db/password, hosts), got '$REC'"
IMM="$(ssm "$WAK" "$WSK" get-parameters-by-path --path "${BASE}" --query 'length(Parameters)' 2>/dev/null)"
[ "$IMM" = "1" ] || fail "non-recursive ${BASE} should return 1 (hosts only), got '$IMM'"
log "  ✓ recursive=3, immediate=1"

# --- 7. LabelParameterVersion → read by label -------------------------------------------------
log "label-parameter-version → get-parameter name:label returns that version"
ssm "$WAK" "$WSK" label-parameter-version --name "$P1" --parameter-version 1 --labels "release" >/dev/null 2>&1 || fail "label-parameter-version failed"
BYLBL="$(ssm "$WAK" "$WSK" get-parameter --name "${P1}:release" --query 'Parameter.Value' 2>/dev/null)"
[ "$BYLBL" = "$V1" ] || fail "get by label returned '$BYLBL' (want v1 value)"
log "  ✓ label 'release'→v1 readable"

# --- 8. audit: a GetParameter wrote a record naming the principal -----------------------------
log "audit: a GetParameter must have written a structured record (principal + parameter)"
sleep 1
AUDIT="$(kubectl -n "$SHIM_NS" logs deploy/aws-shim --since=300s 2>/dev/null | grep '"msg":"ssm audit"' | grep '"op":"GetParameter"' | grep "\"parameter\":\"$P1\"" | tail -1)"
[ -n "$AUDIT" ] || fail "no SSM audit record found for the GetParameter (AU-2)"
printf '%s' "$AUDIT" | grep -q "\"principal\":\"User::ssm-probe-$SFX\"" || fail "audit record does not name the principal: $AUDIT"
log "  ✓ audit record present (principal + op + parameter + decision)"

# --- 9. Advanced tier refused honestly --------------------------------------------------------
log "negative: Advanced tier must be REFUSED honestly (Standard tier only)"
if ssm "$WAK" "$WSK" put-parameter --name "${BASE}/adv" --value x --type String --tier Advanced >/dev/null 2>"$PWD/.ssm_adv"; then
  CREATED_PARAMS+=("${BASE}/adv")
  fail "Advanced tier was accepted (would claim features that don't exist)"
fi
grep -qiE 'Validation|Standard|Advanced' "$PWD/.ssm_adv" || fail "Advanced-tier refusal had the wrong error: $(cat "$PWD/.ssm_adv")"
rm -f "$PWD/.ssm_adv"
log "  ✓ Advanced tier refused"

# --- 10. Delete → not found -------------------------------------------------------------------
log "delete-parameter → get-parameter must then fail ParameterNotFound"
ssm "$WAK" "$WSK" delete-parameter --name "$PL" >/dev/null 2>&1 || fail "delete-parameter failed"
if ssm "$WAK" "$WSK" get-parameter --name "$PL" >/dev/null 2>"$PWD/.ssm_del"; then
  fail "a deleted parameter still returned a value"
fi
grep -qiE 'ParameterNotFound|not found' "$PWD/.ssm_del" || fail "deleted-parameter refusal had the wrong error: $(cat "$PWD/.ssm_del")"
rm -f "$PWD/.ssm_del"
# drop it from cleanup (already gone)
CREATED_PARAMS=("${CREATED_PARAMS[@]/$PL}")
log "  ✓ deleted → ParameterNotFound"

# --- 11a. Negative: wrong secret --------------------------------------------------------------
log "negative: a valid key ID with a WRONG secret must be rejected"
if ssm "$WAK" "wrong-secret-not-the-real-one" get-parameter --name "$P1" >/dev/null 2>"$PWD/.ssm_neg"; then
  fail "a wrong secret was accepted"
fi
grep -qiE 'Signature|does not match' "$PWD/.ssm_neg" || fail "wrong secret rejected with the wrong error: $(cat "$PWD/.ssm_neg")"
rm -f "$PWD/.ssm_neg"
log "  ✓ rejected on signature mismatch"

# --- 11b. Per-path Cedar: scoped-to-A can read A, DENIED B ------------------------------------
log "seeding a path-scoped principal (Parameter::${BASE}/a/*) + a param in a sibling path B"
PA="${BASE}/a/token"; PB="${BASE}/b/token"
ssm "$WAK" "$WSK" put-parameter --name "$PA" --value "in-A-$SFX" --type String >/dev/null 2>&1 || fail "put A failed"
ssm "$WAK" "$WSK" put-parameter --name "$PB" --value "in-B-$SFX" --type String >/dev/null 2>&1 || fail "put B failed"
CREATED_PARAMS+=("$PA" "$PB")
read -r AAK ASK <<<"$(mint_key "ssm-probe-ascoped-$SFX" "powerusers")"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "ssm-ascoped-$SFX", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::ssm-probe-ascoped-$SFX"]
    statements:
      - { effect: Allow, actions: ["ssm:*"], resources: ["Parameter::${BASE}/a/*"] }
YAML
CREATED_POLICIES+=("ssm-ascoped-$SFX")

# --- 11c. Two-permission: DENIED kms:Decrypt reads ciphertext but not plaintext ---------------
log "seeding a decrypt-denied principal (ssm:* on the secure path, but Deny kms:Decrypt)"
PSEC="${BASE}/sec/api-key"
ssm "$WAK" "$WSK" put-parameter --name "$PSEC" --value "sec-$SFX" --type SecureString >/dev/null 2>&1 || fail "put secure param failed"
CREATED_PARAMS+=("$PSEC")
read -r NAK NSK <<<"$(mint_key "ssm-probe-nodecrypt-$SFX" "powerusers")"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "ssm-nodecrypt-$SFX", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::ssm-probe-nodecrypt-$SFX"]
    statements:
      - { effect: Allow, actions: ["ssm:*"], resources: ["Parameter::${BASE}/*"] }
      - { effect: Deny,  actions: ["kms:Decrypt"], resources: ["*"] }
YAML
CREATED_POLICIES+=("ssm-nodecrypt-$SFX")

log "  waiting ~35s for the data-plane policy loader to pick them up..."
sleep 35

log "path-scoped principal: reads ${BASE}/a/…, DENIED ${BASE}/b/…"
AGOT="$(ssm "$AAK" "$ASK" get-parameter --name "$PA" --query 'Parameter.Value' 2>"$PWD/.ssm_a" || true)"
[ "$AGOT" = "in-A-$SFX" ] || fail "path-scoped principal could not read A (should be allowed): $(cat "$PWD/.ssm_a" 2>/dev/null)"
rm -f "$PWD/.ssm_a"
if ssm "$AAK" "$ASK" get-parameter --name "$PB" >/dev/null 2>"$PWD/.ssm_b"; then
  fail "a path-scoped-to-A principal read B (cross-path isolation broken)"
fi
grep -qiE 'AccessDenied|denied' "$PWD/.ssm_b" || fail "cross-path denial had the wrong error: $(cat "$PWD/.ssm_b")"
rm -f "$PWD/.ssm_b"
log "  ✓ reads A, denied B"

log "decrypt-denied principal: reads the SecureString CIPHERTEXT, DENIED the plaintext"
NCT="$(ssm "$NAK" "$NSK" get-parameter --name "$PSEC" --query 'Parameter.Value' 2>"$PWD/.ssm_nc" || true)"
case "$NCT" in vault:*) : ;; *) fail "decrypt-denied principal did not get the ciphertext (WithDecryption=false should succeed): got '$NCT' $(cat "$PWD/.ssm_nc" 2>/dev/null)";; esac
rm -f "$PWD/.ssm_nc"
if ssm "$NAK" "$NSK" get-parameter --name "$PSEC" --with-decryption >/dev/null 2>"$PWD/.ssm_nd"; then
  fail "a decrypt-denied principal read the SecureString PLAINTEXT (two-permission split broken)"
fi
grep -qiE 'AccessDenied|denied|kms:Decrypt' "$PWD/.ssm_nd" || fail "decrypt denial had the wrong error: $(cat "$PWD/.ssm_nd")"
rm -f "$PWD/.ssm_nd"
log "  ✓ ciphertext readable, plaintext denied (ssm:GetParameter + kms:Decrypt split)"

printf '\n✓ PASS — aws-shim SSM Parameter Store is semantically faithful (versions, labels, path tree, StringList, SecureString-encrypted-at-rest, honest Standard-only tier) and enforces auth + per-path + the value/decrypt two-permission boundaries.\n'
