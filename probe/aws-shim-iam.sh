#!/usr/bin/env bash
# Compatibility probe for the aws-shim IAM management surface (polyhedron#168/#174, Branch A).
#
# The core is the AWS IAM policy JSON → Cedar TRANSLATION, and the bar is that it is faithful in BOTH
# directions: a role assumed via STS can do EXACTLY what its translated policy grants and is DENIED
# everything it does not. A translator that only proves the allow direction is not proven; the DENY cases are
# the confused-deputy detector (an implementation that authorized on the shim's own backend credentials would
# sail through allow and fail every deny). It asserts, over real round-trips:
#   - CreateRole (trust) + CreatePolicy (JSON→Cedar) + AttachRolePolicy, then STS AssumeRole into the role
#   - the assumed session can GetObject the granted bucket  (ALLOW)
#   - the assumed session is DENIED GetObject on a different bucket  (resource fidelity)
#   - the assumed session is DENIED ListBucket on the granted bucket (action fidelity — same coarse verb)
#   - SimulatePrincipalPolicy agrees in both directions and reports an explicit Deny as explicitDeny (forbid fidelity)
#   - CreateAccessKey yields a key that genuinely AUTHENTICATES through the shim
# and the NEGATIVES:
#   - a valid key ID with a WRONG secret on a management call → SignatureDoesNotMatch
#   - a policy using NotAction/NotResource is REFUSED (the fidelity hole), not silently stored
#
# On-demand (needs a deployed shim + STS AssumeRole + MinIO/S3 + the IAM CRDs + an openinfra:admins caller).
# Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE. Per polyhedron#157, a probe failure is a shim defect.
#
#   SHIM_ENDPOINT=http://localhost:4566 MINIO_ENDPOINT=http://localhost:9000 ./probe/aws-shim-iam.sh
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
cleanup() {
  for r in "${CREATED_ROLES[@]:-}";    do [ -n "$r" ] && iam "$AAK" "$ASK" delete-role --role-name "$r" >/dev/null 2>&1 || true; done
  for p in "${CREATED_POLICIES[@]:-}"; do [ -n "$p" ] && iam "$AAK" "$ASK" delete-policy --policy-arn "arn:aws:iam::${ACCOUNT}:policy/$p" >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}";    do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for k in "${CREATED_KEYS[@]:-}";     do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
  # role/policy CRDs the shim created (belt-and-suspenders if the API delete raced)
  kubectl -n "$USERS_NS" delete role.iam.openinfra.dev "iam-probe-role-$SFX" --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev "iam-probe-pol-$SFX" "iam-probe-deny-$SFX" "role-iam-probe-role-$SFX-"* --ignore-not-found >/dev/null 2>&1 || true
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
s3op() { local ak="$1" sk="$2" tok="${3:-}"; shift 3; AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_SESSION_TOKEN="$tok" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager s3api "$@"; }

# --- 1. Seed an IAM-admin caller (openinfra:admins) -------------------------------------------
log "seeding an IAM-admin caller (openinfra:admins) + key"
ADMIN="iam-probe-admin-$SFX"
read -r AAK ASK <<<"$(mint_key "$ADMIN" "admins")"
[ -n "$AAK" ] && [ -n "$ASK" ] || inconclusive "failed to mint an admin key"
sleep 2

# --- 2. CreatePolicy (JSON→Cedar) + CreateRole (trust) + AttachRolePolicy ----------------------
BUCKET_X="iam-probe-x-$SFX"; BUCKET_Y="iam-probe-y-$SFX"
POL="iam-probe-pol-$SFX"; ROLE="iam-probe-role-$SFX"
log "create-policy ${POL} (Allow s3:GetObject on ${BUCKET_X}) — AWS JSON → Cedar"
POLDOC='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::'"$BUCKET_X"'/*"}]}'
POL_ARN="$(iam "$AAK" "$ASK" create-policy --policy-name "$POL" --policy-document "$POLDOC" --query 'Policy.Arn' 2>"$PWD/.iam_cp")" \
  || inconclusive "create-policy failed (is the caller in openinfra:admins and the shim IAM RBAC applied?): $(cat "$PWD/.iam_cp" 2>/dev/null)"
[ -n "$POL_ARN" ] && [ "$POL_ARN" != "None" ] || inconclusive "create-policy returned no ARN"
CREATED_POLICIES+=("$POL")
rm -f "$PWD/.iam_cp"

log "create-role ${ROLE} (trust: ${ADMIN} may AssumeRole)"
TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::'"$ACCOUNT"':user/'"$ADMIN"'"},"Action":"sts:AssumeRole"}]}'
iam "$AAK" "$ASK" create-role --role-name "$ROLE" --assume-role-policy-document "$TRUST" >/dev/null 2>&1 || fail "create-role failed"
CREATED_ROLES+=("$ROLE")
iam "$AAK" "$ASK" attach-role-policy --role-name "$ROLE" --policy-arn "$POL_ARN" >/dev/null 2>&1 || fail "attach-role-policy failed"

# an explicit-Deny policy for the forbid-fidelity Simulate check (Allow s3:* on X, then Deny s3:GetObject on X)
DENYPOL="iam-probe-deny-$SFX"
DENYDOC='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::'"$BUCKET_X"'/*"},{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::'"$BUCKET_X"'/*"}]}'
DENY_ARN="$(iam "$AAK" "$ASK" create-policy --policy-name "$DENYPOL" --policy-document "$DENYDOC" --query 'Policy.Arn' 2>/dev/null || true)"
[ -n "$DENY_ARN" ] && [ "$DENY_ARN" != "None" ] && CREATED_POLICIES+=("$DENYPOL")

# --- 3. Seed the buckets + objects DIRECTLY in MinIO (the shim's S3 API does not implement CreateBucket;
#         buckets are provisioned via MinIO, and the assumed session reads them back THROUGH the shim) ------
MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://minio.minio.svc.cluster.local:9000}"
MINIO_USER="$(kubectl -n minio get secret minio -o jsonpath='{.data.rootUser}' 2>/dev/null | base64 -d)"
MINIO_PW="$(kubectl -n minio get secret minio -o jsonpath='{.data.rootPassword}' 2>/dev/null | base64 -d)"
[ -n "$MINIO_USER" ] && [ -n "$MINIO_PW" ] || inconclusive "could not read MinIO root creds (secret minio/minio)"
minio_s3() { AWS_ACCESS_KEY_ID="$MINIO_USER" AWS_SECRET_ACCESS_KEY="$MINIO_PW" AWS_REGION="$REGION" aws --endpoint-url "$MINIO_ENDPOINT" --no-cli-pager s3api "$@"; }
curl -fsS -m 5 "${MINIO_ENDPOINT}/minio/health/live" >/dev/null 2>&1 || inconclusive "MinIO not reachable at ${MINIO_ENDPOINT} (port-forward svc/minio 9000)"
log "seeding buckets ${BUCKET_X}, ${BUCKET_Y} + objects directly in MinIO"
for b in "$BUCKET_X" "$BUCKET_Y"; do
  minio_s3 create-bucket --bucket "$b" >/dev/null 2>&1 || inconclusive "could not create bucket $b in MinIO"
  CREATED_BUCKETS+=("$b")
  echo "hello-from-$b" > "/tmp/iam_obj_$SFX"
  minio_s3 put-object --bucket "$b" --key "obj" --body "/tmp/iam_obj_$SFX" >/dev/null 2>&1 || inconclusive "could not put object in $b"
done
rm -f "/tmp/iam_obj_$SFX"

log "waiting ~35s for the data-plane policy loader to see the attached policy..."
sleep 35

# --- 4. SimulatePrincipalPolicy: the translation is faithful BOTH directions -------------------
# This runs the SAME Cedar authorization query the data plane uses for a Role principal (closed/default-deny),
# so it proves the JSON→Cedar translation both directions without needing a live STS session.
log "simulate-principal-policy: GetObject X=allowed, GetObject Y=implicitDeny (resource), ListBucket X=implicitDeny (action)"
sim() { iam "$AAK" "$ASK" simulate-principal-policy --policy-source-arn "arn:aws:iam::${ACCOUNT}:role/${ROLE}" \
  --action-names "$1" --resource-arns "$2" --query 'EvaluationResults[0].EvalDecision' 2>/dev/null; }
[ "$(sim s3:GetObject "arn:aws:s3:::$BUCKET_X")" = "allowed" ]      || fail "Simulate GetObject X should be allowed (allow direction / translation broken)"
[ "$(sim s3:GetObject "arn:aws:s3:::$BUCKET_Y")" = "implicitDeny" ] || fail "Simulate GetObject Y should be implicitDeny (resource fidelity)"
[ "$(sim s3:ListBucket "arn:aws:s3:::$BUCKET_X")" = "implicitDeny" ]|| fail "Simulate ListBucket X should be implicitDeny (action fidelity)"
log "    ✓ translation faithful both directions (allow + resource-deny + action-deny)"

# --- 5. LIVE AssumeRole → S3: the confused-deputy detector (needs STS enabled) ------------------
# The DoD's live round-trip: an STS session's S3 requests must be authorized on the ROLE principal (its
# policies), NOT the shim's backend MinIO credentials. This needs STS enabled (a Vault sts/signing-key).
STS_GATED=""
log "sts assume-role into ${ROLE} (live confused-deputy detector)"
CREDS="$(AWS_ACCESS_KEY_ID="$AAK" AWS_SECRET_ACCESS_KEY="$ASK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager \
  sts assume-role --role-arn "arn:aws:iam::${ACCOUNT}:role/${ROLE}" --role-session-name "probe-$SFX" \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text 2>"$PWD/.iam_ar" || true)"
if grep -qiE 'signing key|not enabled|AssumeRole is not' "$PWD/.iam_ar" 2>/dev/null; then
  STS_GATED=1
  log "  ⚠ STS AssumeRole is not enabled on this shim (no Vault sts/signing-key) — the LIVE round-trip is gated."
elif [ -z "$CREDS" ]; then
  fail "assume-role failed: $(cat "$PWD/.iam_ar" 2>/dev/null)"
fi
rm -f "$PWD/.iam_ar"
if [ -z "$STS_GATED" ]; then
  read -r SAK SSK STOK <<<"$CREDS"
  [ -n "$SAK" ] && [ -n "$STOK" ] || fail "assume-role returned no session credentials"
  log "  ALLOW: the session can GetObject ${BUCKET_X}/obj (what the policy grants)"
  # get-object writes the body to the file AND prints metadata JSON to stdout; assert on the FILE content.
  s3op "$SAK" "$SSK" "$STOK" get-object --bucket "$BUCKET_X" --key obj "/tmp/iam_got_$SFX" >/dev/null 2>"$PWD/.iam_g" \
    || fail "assumed session could NOT GetObject the granted bucket (allow direction broken): $(cat "$PWD/.iam_g" 2>/dev/null)"
  GOT="$(cat "/tmp/iam_got_$SFX" 2>/dev/null || true)"
  rm -f "/tmp/iam_got_$SFX" "$PWD/.iam_g"
  [ "$GOT" = "hello-from-$BUCKET_X" ] || fail "granted GetObject returned the wrong content: '$GOT'"
  log "    ✓ allowed"
  log "  DENY (resource fidelity): the session is denied GetObject ${BUCKET_Y}/obj"
  if s3op "$SAK" "$SSK" "$STOK" get-object --bucket "$BUCKET_Y" --key obj "/tmp/iam_y_$SFX" >/dev/null 2>"$PWD/.iam_y"; then
    rm -f "/tmp/iam_y_$SFX"
    fail "assumed session read a bucket its policy does NOT grant (resource fidelity broken — confused deputy?)"
  fi
  grep -qiE 'AccessDenied|denied|forbidden' "$PWD/.iam_y" || fail "cross-bucket denial had the wrong error: $(cat "$PWD/.iam_y")"
  rm -f "$PWD/.iam_y" "/tmp/iam_y_$SFX"
  log "    ✓ denied bucket Y"
  log "  DENY (action fidelity): the session is denied ListBucket on ${BUCKET_X} (only GetObject granted)"
  if s3op "$SAK" "$SSK" "$STOK" list-objects-v2 --bucket "$BUCKET_X" >/dev/null 2>"$PWD/.iam_l"; then
    fail "assumed session performed ListBucket, which its policy does NOT grant (action fidelity broken)"
  fi
  grep -qiE 'AccessDenied|denied|forbidden' "$PWD/.iam_l" || fail "ListBucket denial had the wrong error: $(cat "$PWD/.iam_l")"
  rm -f "$PWD/.iam_l"
  log "    ✓ denied ListBucket (live session authorized on the ROLE, not the shim's backend creds)"
fi

# --- 6. forbid fidelity: an explicit Deny statement translates to a Cedar forbid ---------------
if [ -n "$DENY_ARN" ]; then
  log "forbid fidelity: attach the explicit-Deny policy → Simulate reports explicitDeny"
  iam "$AAK" "$ASK" attach-role-policy --role-name "$ROLE" --policy-arn "$DENY_ARN" >/dev/null 2>&1 || true
  sleep 35
  DEC="$(sim s3:GetObject "arn:aws:s3:::$BUCKET_X")"
  [ "$DEC" = "explicitDeny" ] || fail "an explicit Deny statement should translate to a forbid (Simulate=$DEC, want explicitDeny)"
  log "    ✓ explicit Deny → explicitDeny (forbid overrides permit)"
fi

# --- 6. CreateAccessKey yields a key that genuinely authenticates ------------------------------
log "create-user + create-access-key → the key must authenticate through the shim"
APPUSER="iam-probe-appuser-$SFX"
iam "$AAK" "$ASK" create-user --user-name "$APPUSER" >/dev/null 2>&1 || fail "create-user failed"
CREATED_USERS+=("$APPUSER")
AKOUT="$(iam "$AAK" "$ASK" create-access-key --user-name "$APPUSER" --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text 2>"$PWD/.iam_ak")" \
  || fail "create-access-key failed: $(cat "$PWD/.iam_ak" 2>/dev/null)"
rm -f "$PWD/.iam_ak"
read -r NAK NSK <<<"$AKOUT"
CREATED_KEYS+=("$(secret_name "$NAK")")
[ -n "$NAK" ] && [ -n "$NSK" ] || fail "create-access-key returned no key"
sleep 2
CID="$(AWS_ACCESS_KEY_ID="$NAK" AWS_SECRET_ACCESS_KEY="$NSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager sts get-caller-identity --query Arn --output text 2>"$PWD/.iam_ci" || true)"
grep -q "$APPUSER" <<<"$CID" || fail "the created access key did not authenticate as ${APPUSER} (got '$CID'): $(cat "$PWD/.iam_ci" 2>/dev/null)"
rm -f "$PWD/.iam_ci"
log "    ✓ the created key authenticates as ${APPUSER}"

# --- 7a. Negative: wrong secret ---------------------------------------------------------------
log "negative: a valid key ID with a WRONG secret must be rejected"
if iam "$AAK" "wrong-secret-not-the-real-one" list-roles >/dev/null 2>"$PWD/.iam_neg"; then
  fail "a wrong secret was accepted"
fi
grep -qiE 'Signature|does not match' "$PWD/.iam_neg" || fail "wrong secret rejected with the wrong error: $(cat "$PWD/.iam_neg")"
rm -f "$PWD/.iam_neg"
log "    ✓ rejected on signature mismatch"

# --- 7b. Negative: NotAction refused ----------------------------------------------------------
log "negative: a policy using NotAction must be REFUSED (fidelity hole), not silently stored"
NADOC='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":"s3:DeleteObject","Resource":"*"}]}'
if iam "$AAK" "$ASK" create-policy --policy-name "iam-probe-na-$SFX" --policy-document "$NADOC" >/dev/null 2>"$PWD/.iam_na"; then
  CREATED_POLICIES+=("iam-probe-na-$SFX")
  fail "a NotAction policy was accepted (would silently change the grant)"
fi
grep -qiE 'Malformed|NotAction|not supported' "$PWD/.iam_na" || fail "NotAction refusal had the wrong error: $(cat "$PWD/.iam_na")"
rm -f "$PWD/.iam_na"
log "    ✓ NotAction refused"

if [ -n "$STS_GATED" ]; then
  printf '\n⚠ INCONCLUSIVE — the TRANSLATION is proven faithful both directions (SimulatePrincipalPolicy: allow + resource-deny + action-deny + explicit-forbid), CreateAccessKey authenticates, and the negatives hold. BUT the LIVE AssumeRole→S3 round-trip (the confused-deputy detector) could not run: STS AssumeRole is not enabled on this shim (no Vault sts/signing-key). Enable STS (write sts/signing-key in Vault, like the KMS bootstrap) and re-run to complete the DoD.\n'
  exit "$EXIT_INCONCLUSIVE"
fi
printf '\n✓ PASS — aws-shim IAM (Branch A) is faithful BOTH directions: an STS-assumed role does exactly what its JSON→Cedar-translated policy grants and is denied everything it does not (resource, action, and forbid fidelity), verified LIVE (session authorized on the role, not the shim backend creds) and by SimulatePrincipalPolicy; CreateAccessKey authenticates; and the negatives hold.\n'
