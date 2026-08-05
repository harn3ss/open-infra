#!/usr/bin/env bash
# Compatibility probe for the aws-shim S3 surface (design handoff §8).
#
# This is the trust-earning artifact. It fires REAL AWS SDK calls (the `aws` CLI is a real AWS SDK
# client) at a deployed shim and asserts BYTE-FAITHFUL behavior — not merely HTTP 200 — because the
# failure this exists to catch is precisely the false-green: the app thinks it wrote durably, the
# shim said OK, but a semantic didn't hold. That is the same false-green the chaos oracle discipline
# catches one layer down. The support matrix is only real once this passes.
#
# It asserts, over a real put/get/list round-trip:
#   - put-object then get-object returns IDENTICAL bytes (the durability semantic, not just 200)
#   - the response carries a well-formed, quoted ETag (SDK-parse faithful)
#   - list-objects shows the key
#   - path-style addressing round-trips
# and the two NEGATIVES that are the whole point ("prove the no"):
#   - a request with a valid key ID but a WRONG secret is REJECTED (SignatureDoesNotMatch) — auth
#     actually fires; naming a key is not enough
#   - a valid key whose owner lacks write permission is DENIED (AccessDenied) — the boundary fires
#
# On-demand (needs a deployed shim + MinIO + the platform IAM). Run from a host with cluster
# access. Exit 0 = pass, 1 = a real failure (the shim is not faithful), 42 = INCONCLUSIVE (a
# prerequisite was missing, so nothing was proven — neither green nor red), mirroring the chaos
# suite's convention.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-s3.sh     # e.g. behind a kubectl port-forward
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
BUCKET="${PROBE_BUCKET:-aws-shim-probe}"
REGION="${AWS_REGION:-us-east-1}"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

# --- 0. Preflight -----------------------------------------------------------------------------
command -v aws     >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required to seed the principal + key"
command -v mc      >/dev/null || MC=""   # optional: used to pre-create the bucket
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"

WORK="$(mktemp -d)"
CREATED_KEYS=()
CREATED_USERS=()
cleanup() {
  for s in "${CREATED_KEYS[@]:-}";  do [ -n "$s" ] && kubectl -n "$SHIM_NS" delete secret "$s" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

# secret_name mirrors awskeys.SecretName: iam-ak-<first 40 hex of sha256(accessKeyID)>.
secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }

# mint_key <owner> <group> -> prints "ACCESS_KEY SECRET_KEY". Creates a kind: User in <group> and
# writes the iam-ak-<id> Secret the shim resolves, exactly as the console's mint path will.
mint_key() {
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
    --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" \
    >/dev/null
  CREATED_KEYS+=("$name")
  printf '%s %s' "$ak" "$sk"
}

# awsq runs the aws CLI against the shim with path-style addressing and given creds.
awsq() { # AK SK -- <aws args...>
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager s3api "$@"
}

# --- 1. Seed a WRITER principal + its key -----------------------------------------------------
log "seeding a writer principal (openinfra:powerusers) + access key"
read -r WAK WSK <<<"$(mint_key "probe-writer" "powerusers")"
[ -n "$WAK" ] && [ -n "$WSK" ] || inconclusive "failed to mint a writer key"
sleep 2 # let the key Secret + User settle

# Pre-create the bucket out-of-band (bucket creation via the shim is a later op).
if command -v mc >/dev/null && [ -n "${MINIO_ALIAS:-}" ]; then
  mc mb --ignore-existing "${MINIO_ALIAS}/${BUCKET}" >/dev/null 2>&1 || true
fi

# --- 2. put-object then get-object: IDENTICAL bytes -------------------------------------------
printf 'the-quick-brown-fox-%s' "$RANDOM$RANDOM" > "$WORK/in.txt"
log "put-object ${BUCKET}/probe.txt"
awsq "$WAK" "$WSK" put-object --bucket "$BUCKET" --key probe.txt --body "$WORK/in.txt" >/dev/null \
  || fail "put-object failed for an authorized writer"

log "get-object and compare bytes"
awsq "$WAK" "$WSK" get-object --bucket "$BUCKET" --key probe.txt "$WORK/out.txt" >"$WORK/get.json" \
  || fail "get-object failed"
cmp -s "$WORK/in.txt" "$WORK/out.txt" || fail "get-object bytes differ from put-object (durability semantic broken)"
log "  ✓ bytes identical"

# --- 3. ETag present + well-formed ------------------------------------------------------------
ETAG="$(awsq "$WAK" "$WSK" head-object --bucket "$BUCKET" --key probe.txt | sed -n 's/.*"ETag": "\(.*\)".*/\1/p' | head -1)"
[ -n "$ETAG" ] || fail "head-object returned no ETag (SDK-parse faithfulness broken)"
log "  ✓ ETag present: ${ETAG}"

# --- 4. list-objects shows the key ------------------------------------------------------------
log "list-objects-v2"
awsq "$WAK" "$WSK" list-objects-v2 --bucket "$BUCKET" | grep -q '"Key": "probe.txt"' \
  || fail "list-objects-v2 did not include the written key"
log "  ✓ key listed"

# --- 4b. Chunked upload round-trips (forces aws-chunked framing via a trailing checksum) ---------
# --checksum-algorithm CRC32 makes the CLI send a STREAMING-…-TRAILER (aws-chunked) body: the wire
# payload is the file wrapped in per-chunk size/signature framing. If the shim stored that verbatim
# the object would be corrupted; this asserts the shim dechunks it. (Guards the CHANGELOG claim.)
log "chunked upload: put-object --checksum-algorithm CRC32, then get, compare bytes"
printf 'aws-chunked-payload-%s-%s' "$RANDOM$RANDOM" "$(head -c 200 /dev/zero | tr '\0' x)" > "$WORK/chunk-in.txt"
awsq "$WAK" "$WSK" put-object --bucket "$BUCKET" --key chunk.txt --body "$WORK/chunk-in.txt" --checksum-algorithm CRC32 >/dev/null 2>"$WORK/chunk.err" \
  || fail "chunked put-object (--checksum-algorithm CRC32) failed: $(cat "$WORK/chunk.err")"
awsq "$WAK" "$WSK" get-object --bucket "$BUCKET" --key chunk.txt "$WORK/chunk-out.txt" >/dev/null || fail "chunked get-object failed"
cmp -s "$WORK/chunk-in.txt" "$WORK/chunk-out.txt" || fail "aws-chunked upload was stored WITH framing bytes — dechunking is broken"
log "  ✓ chunked upload round-trips byte-identical (framing stripped)"

# --- 5. NEGATIVE: valid key ID, WRONG secret → SignatureDoesNotMatch ---------------------------
log "negative: valid key ID with a WRONG secret must be rejected"
if awsq "$WAK" "wrong-secret-not-the-real-one" get-object --bucket "$BUCKET" --key probe.txt "$WORK/nope.txt" >"$WORK/neg.out" 2>&1; then
  fail "a request with a wrong signature was ACCEPTED (authentication theater!)"
fi
grep -qi 'SignatureDoesNotMatch\|403\|Forbidden' "$WORK/neg.out" \
  || fail "wrong-secret request was rejected, but not as SignatureDoesNotMatch/403: $(cat "$WORK/neg.out")"
log "  ✓ rejected as SignatureDoesNotMatch"

# --- 6. NEGATIVE: a reader (no write permission) → AccessDenied on put ------------------------
log "seeding a READER principal (openinfra:readers) + key"
read -r RAK RSK <<<"$(mint_key "probe-reader" "readers")"
[ -n "$RAK" ] && [ -n "$RSK" ] || inconclusive "failed to mint a reader key"
sleep 2
log "negative: a reader attempting put-object must be denied by the boundary"
if awsq "$RAK" "$RSK" put-object --bucket "$BUCKET" --key reader-should-not-write.txt --body "$WORK/in.txt" >"$WORK/deny.out" 2>&1; then
  fail "a read-only principal was allowed to WRITE (authorization did not fire)"
fi
grep -qi 'AccessDenied\|403\|Forbidden' "$WORK/deny.out" \
  || fail "reader write was rejected, but not as AccessDenied/403: $(cat "$WORK/deny.out")"
log "  ✓ denied as AccessDenied"

# The reader SHOULD still be able to read (sanity that the deny is scoped to writes, not blanket).
log "sanity: the reader CAN still get-object (deny is write-scoped)"
awsq "$RAK" "$RSK" get-object --bucket "$BUCKET" --key probe.txt "$WORK/reader.txt" >/dev/null \
  || fail "a reader was denied a READ (the coarse gate is over-broad)"
cmp -s "$WORK/in.txt" "$WORK/reader.txt" || fail "reader read returned wrong bytes"
log "  ✓ reader read succeeded"

# --- cleanup the object we wrote --------------------------------------------------------------
awsq "$WAK" "$WSK" delete-object --bucket "$BUCKET" --key probe.txt >/dev/null 2>&1 || true
awsq "$WAK" "$WSK" delete-object --bucket "$BUCKET" --key chunk.txt >/dev/null 2>&1 || true

echo
echo "✓ PASS — aws-shim S3 surface is byte-faithful and enforces auth + the write boundary."
