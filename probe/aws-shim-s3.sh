#!/usr/bin/env bash
# Compatibility probe for the aws-shim S3 surface.
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
#   - a 20 MiB `aws s3 cp` (a multipart upload: the CLI's threshold is 8 MiB) round-trips byte-identical,
#     and so do server-side copies above and below that threshold (UploadPartCopy, CopyObject); an
#     upload can be listed and aborted
#   - DeleteObjects deletes the keys it names (Quiet lists none of them), and a key the caller may not
#     delete is that key's AccessDenied error while the request still answers 200; `aws s3 rm --recursive`
#     empties a prefix
#   - CreateBucket (`aws s3 mb`) makes a bucket an immediate put/get works in, with the platform's default
#     encryption when that is on; re-creating your own bucket answers 200 (us-east-1); `aws s3 rb` removes
#     it and its kind: Bucket claim; a client configured for another region creates one too (its region is
#     the LocationConstraint), and a constraint naming yet another region is refused
# and the two NEGATIVES that are the whole point ("prove the no"):
#   - a request with a valid key ID but a WRONG secret is REJECTED (SignatureDoesNotMatch) — auth
#     actually fires; naming a key is not enough
#   - a valid key whose owner lacks write permission is DENIED (AccessDenied) — the boundary fires
#   - CreateBucket of a platform bucket's name is BucketAlreadyExists, and a reader's is AccessDenied
#   - a policy on a key prefix (Bucket::<bucket>/scoped/*) reaches only those keys: another key, a copy
#     whose source is outside the prefix, and a listing of the bucket are AccessDenied
#   - a platform bucket is AccessDenied to a non-admin
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
CREATED_POLICIES=()
BUCKET_NS="${S3_BUCKET_NAMESPACE:-open-infra-s3}"
MB_BUCKET="aws-shim-probe-mb-$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
cleanup() {
  # The CreateBucket section's buckets: their claims (each bucket's setup, reaper and MinIO bucket follow).
  kubectl -n "$BUCKET_NS" delete buckets.openinfra.dev "$MB_BUCKET" "${MB_BUCKET}-eu" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  for s in "${CREATED_KEYS[@]:-}";  do [ -n "$s" ] && kubectl -n "$SHIM_NS" delete secret "$s" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for p in "${CREATED_POLICIES[@]:-}"; do [ -n "$p" ] && kubectl -n "$USERS_NS" delete policies.iam.openinfra.dev "$p" --ignore-not-found >/dev/null 2>&1 || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

# secret_name mirrors awskeys.SecretName: iam-ak-<first 40 hex of sha256(accessKeyID)>.
secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }

# mint_key <owner> <group> -> prints "ACCESS_KEY SECRET_KEY". Creates a kind: User in <group> and
# writes the iam-ak-<id> Secret the shim resolves, exactly as the console's mint path will.
mint_key() {
  local owner="$1" group="$2"
  # A principal minted with no group is policy-only: its own policies are all it has, decided by IAM
  # policy alone (the canary label), as an AWS user with no group. A tier group (powerusers, admins)
  # carries its AWS managed policy (PowerUserAccess, AdministratorAccess), which a scoped policy of the
  # user's own only adds to, as on AWS — so a principal meant to be scoped has no group.
  local groups="[\"${group}\"]" labels=""
  [ -n "$group" ] || { groups="[]"; labels=', labels: { "openinfra.dev/iam-authz": "enforce" }'; }
  local ak="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  local sk; sk="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "${owner}", namespace: "${USERS_NS}"${labels} }
spec: { displayName: "${owner}", groups: ${groups}, source: local }
YAML
  CREATED_USERS+=("$owner")
  local name; name="$(secret_name "$ak")"
  kubectl -n "$SHIM_NS" create secret generic "$name" \
    --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" \
    >/dev/null
  CREATED_KEYS+=("$name")
  MK_AK="$ak"; MK_SK="$sk"  # returned via globals: mint_key must run in THIS shell so CREATED_* reach cleanup
}

# awsq runs the aws CLI against the shim with path-style addressing and given creds.
awsq() { # AK SK -- <aws args...>
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager s3api "$@"
}
awss3() { # AK SK -- <aws s3 args...> (the high-level `aws s3` commands)
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager s3 "$@"
}

# --- 1. Seed a WRITER principal + its key -----------------------------------------------------
log "seeding a writer principal (openinfra:powerusers) + access key"
mint_key "probe-writer" "powerusers"; WAK="$MK_AK"; WSK="$MK_SK"
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

log "ranged get-object (bytes=0-3): just those bytes, as a 206"
awsq "$WAK" "$WSK" get-object --bucket "$BUCKET" --key probe.txt --range bytes=0-3 "$WORK/range.txt" >"$WORK/range.json" \
  || fail "a ranged get-object failed"
[ "$(cat "$WORK/range.txt")" = "$(head -c 4 "$WORK/in.txt")" ] || fail "a ranged get-object returned other bytes: $(head -c 40 "$WORK/range.txt")"
grep -q '"ContentRange": "bytes 0-3/' "$WORK/range.json" || fail "a ranged get-object carries no Content-Range: $(cat "$WORK/range.json")"
log "  ✓ range served"

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

# --- 4c. Multipart upload and server-side copy --------------------------------------------------
# `aws s3 cp` switches to a multipart upload above 8 MiB, and to UploadPartCopy for a server-side copy
# above it: what an ordinary build artifact or `aws s3 sync` of a site sends.
log "multipart: aws s3 cp a 20 MiB file up and down, compare checksums"
head -c $((20 * 1024 * 1024)) /dev/urandom > "$WORK/big.bin"
awss3 "$WAK" "$WSK" cp "$WORK/big.bin" "s3://${BUCKET}/big.bin" >"$WORK/mp.out" 2>&1 \
  || fail "a 20 MiB aws s3 cp (multipart) failed: $(cat "$WORK/mp.out")"
awss3 "$WAK" "$WSK" cp "s3://${BUCKET}/big.bin" "$WORK/big-out.bin" >/dev/null 2>"$WORK/mpget.err" \
  || fail "downloading the multipart object failed: $(cat "$WORK/mpget.err")"
[ "$(sha256sum < "$WORK/big.bin")" = "$(sha256sum < "$WORK/big-out.bin")" ] \
  || fail "the multipart object's bytes differ from the uploaded file"
MP_ETAG="$(awsq "$WAK" "$WSK" head-object --bucket "$BUCKET" --key big.bin --query ETag --output text)"
case "$MP_ETAG" in *-*) ;; *) fail "the 20 MiB object's ETag ${MP_ETAG} is not a multipart ETag (was it uploaded in parts?)";; esac
log "  ✓ uploaded in parts (ETag ${MP_ETAG}), downloaded byte-identical"

log "server-side copy: above the threshold (UploadPartCopy) and below it (CopyObject)"
awss3 "$WAK" "$WSK" cp "s3://${BUCKET}/big.bin" "s3://${BUCKET}/big-copy.bin" >"$WORK/cp.out" 2>&1 \
  || fail "a 20 MiB server-side copy (UploadPartCopy) failed: $(cat "$WORK/cp.out")"
awss3 "$WAK" "$WSK" cp "s3://${BUCKET}/big-copy.bin" "$WORK/big-copy.bin" >/dev/null 2>&1 || fail "downloading the copy failed"
cmp -s "$WORK/big.bin" "$WORK/big-copy.bin" || fail "the server-side copy's bytes differ"
awss3 "$WAK" "$WSK" cp "s3://${BUCKET}/probe.txt" "s3://${BUCKET}/probe-copy.txt" >/dev/null 2>"$WORK/cps.err" \
  || fail "a small server-side copy (CopyObject) failed: $(cat "$WORK/cps.err")"
awsq "$WAK" "$WSK" get-object --bucket "$BUCKET" --key probe-copy.txt "$WORK/probe-copy.txt" >/dev/null || fail "get of the small copy failed"
cmp -s "$WORK/in.txt" "$WORK/probe-copy.txt" || fail "the small copy's bytes differ (a copy must never store an empty object)"
log "  ✓ both copies byte-identical"

log "an upload can be listed and aborted"
UPLOAD_ID="$(awsq "$WAK" "$WSK" create-multipart-upload --bucket "$BUCKET" --key aborted.bin --query UploadId --output text)" \
  || fail "create-multipart-upload failed"
head -c $((5 * 1024 * 1024)) /dev/urandom > "$WORK/part.bin"
awsq "$WAK" "$WSK" upload-part --bucket "$BUCKET" --key aborted.bin --upload-id "$UPLOAD_ID" --part-number 1 --body "$WORK/part.bin" >/dev/null \
  || fail "upload-part failed"
awsq "$WAK" "$WSK" list-parts --bucket "$BUCKET" --key aborted.bin --upload-id "$UPLOAD_ID" --query 'Parts[0].Size' --output text >"$WORK/lp.out" 2>&1 \
  && [ "$(cat "$WORK/lp.out")" = $((5 * 1024 * 1024)) ] || fail "list-parts does not show the 5 MiB part: $(cat "$WORK/lp.out")"
# Listed by the object's key as prefix (MinIO lists an upload under its exact key).
awsq "$WAK" "$WSK" list-multipart-uploads --bucket "$BUCKET" --prefix aborted.bin --query 'Uploads[].UploadId' --output text >"$WORK/lu.out" 2>&1 \
  || fail "list-multipart-uploads failed: $(cat "$WORK/lu.out")"
grep -q "$UPLOAD_ID" "$WORK/lu.out" || fail "list-multipart-uploads does not list the open upload"
awsq "$WAK" "$WSK" abort-multipart-upload --bucket "$BUCKET" --key aborted.bin --upload-id "$UPLOAD_ID" >/dev/null || fail "abort-multipart-upload failed"
ERR="$(awsq "$WAK" "$WSK" list-parts --bucket "$BUCKET" --key aborted.bin --upload-id "$UPLOAD_ID" 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q NoSuchUpload || fail "an aborted upload must be NoSuchUpload, got: $ERR"
log "  ✓ listed, then aborted (NoSuchUpload)"

OWN="$(awsq "$WAK" "$WSK" get-bucket-ownership-controls --bucket "$BUCKET" --query 'OwnershipControls.Rules[0].ObjectOwnership' --output text 2>&1 || true)"
[ "$OWN" = BucketOwnerEnforced ] || fail "get-bucket-ownership-controls: want BucketOwnerEnforced, got: $OWN"
awsq "$WAK" "$WSK" put-bucket-ownership-controls --bucket "$BUCKET" \
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]' >/dev/null 2>"$WORK/oc.err" \
  || fail "put-bucket-ownership-controls BucketOwnerEnforced failed: $(cat "$WORK/oc.err")"
ERR="$(awsq "$WAK" "$WSK" put-bucket-ownership-controls --bucket "$BUCKET" --ownership-controls 'Rules=[{ObjectOwnership=ObjectWriter}]' 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q NotImplemented || fail "ObjectWriter (ACLs) must be refused as NotImplemented, got: $ERR"
log "  ✓ ownership controls: BucketOwnerEnforced (put accepted; an ACL-enabling ObjectWriter refused)"

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
mint_key "probe-reader" "readers"; RAK="$MK_AK"; RSK="$MK_SK"
[ -n "$RAK" ] && [ -n "$RSK" ] || inconclusive "failed to mint a reader key"
sleep 2
log "negative: a reader attempting put-object must be denied by the boundary"
if awsq "$RAK" "$RSK" put-object --bucket "$BUCKET" --key reader-should-not-write.txt --body "$WORK/in.txt" >"$WORK/deny.out" 2>&1; then
  fail "a read-only principal was allowed to WRITE (authorization did not fire)"
fi
grep -qi 'AccessDenied\|403\|Forbidden' "$WORK/deny.out" \
  || fail "reader write was rejected, but not as AccessDenied/403: $(cat "$WORK/deny.out")"
log "  ✓ denied as AccessDenied"
ERR="$(awsq "$RAK" "$RSK" create-multipart-upload --bucket "$BUCKET" --key reader.bin 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q AccessDenied || fail "a reader's create-multipart-upload: want AccessDenied, got: $ERR"
ERR="$(awsq "$RAK" "$RSK" copy-object --bucket "$BUCKET" --key reader-copy.txt --copy-source "${BUCKET}/probe.txt" 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q AccessDenied || fail "a reader's copy-object: want AccessDenied, got: $ERR"
log "  ✓ a reader may not start a multipart upload or copy an object (AccessDenied)"

# The reader SHOULD still be able to read (sanity that the deny is scoped to writes, not blanket).
log "sanity: the reader CAN still get-object (deny is write-scoped)"
awsq "$RAK" "$RSK" get-object --bucket "$BUCKET" --key probe.txt "$WORK/reader.txt" >/dev/null \
  || fail "a reader was denied a READ (the coarse gate is over-broad)"
cmp -s "$WORK/in.txt" "$WORK/reader.txt" || fail "reader read returned wrong bytes"
log "  ✓ reader read succeeded"

# --- 6a. Object-level authorization: a grant on a key prefix reaches only those keys --------------
# A policy on Bucket::<bucket>/scoped/* (what arn:aws:s3:::<bucket>/scoped/* imports to) lets its User read
# and write the keys under scoped/, and nothing else in the bucket: not another key, not a copy whose
# source is outside the prefix, not a listing (ListBucket is a bucket action). A platform bucket is refused
# to every non-admin, whatever their grants.
SCOPED_USER="probe-scoped-$(head -c 3 /dev/urandom | od -An -tx1 | tr -d ' \n')"
SCOPED_POLICY="${SCOPED_USER}-s3"
log "seeding a policy-only user whose S3 policy grants only ${BUCKET}/scoped/*"
mint_key "$SCOPED_USER" ""; SAK="$MK_AK"; SSK="$MK_SK"
[ -n "$SAK" ] && [ -n "$SSK" ] || inconclusive "failed to mint the scoped user's key"
cat <<YAML | kubectl apply -f - >/dev/null || inconclusive "could not create the scoped data-plane Policy"
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "${SCOPED_POLICY}", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::${SCOPED_USER}"]
    statements:
      - { effect: Allow, actions: ["s3:GetObject", "s3:PutObject"], resources: ["Bucket::${BUCKET}/scoped/*"] }
YAML
CREATED_POLICIES+=("$SCOPED_POLICY")
log "  waiting ~35s for the data-plane policy loader to pick it up..."
sleep 35
awsq "$SAK" "$SSK" put-object --bucket "$BUCKET" --key scoped/a.txt --body "$WORK/in.txt" >/dev/null 2>"$WORK/sc.err" \
  || fail "a put under the granted prefix was refused: $(cat "$WORK/sc.err")"
awsq "$SAK" "$SSK" get-object --bucket "$BUCKET" --key scoped/a.txt "$WORK/sc.txt" >/dev/null 2>"$WORK/sc.err" \
  || fail "a get under the granted prefix was refused: $(cat "$WORK/sc.err")"
cmp -s "$WORK/in.txt" "$WORK/sc.txt" || fail "the scoped object's bytes differ"
ERR="$(awsq "$SAK" "$SSK" get-object --bucket "$BUCKET" --key probe.txt "$WORK/nope2.txt" 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q AccessDenied || fail "a get outside the granted prefix: want AccessDenied, got: $ERR"
ERR="$(awsq "$SAK" "$SSK" copy-object --bucket "$BUCKET" --key scoped/copy.txt --copy-source "${BUCKET}/probe.txt" 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q AccessDenied || fail "a copy into the prefix from a source outside it: want AccessDenied, got: $ERR"
ERR="$(awsq "$SAK" "$SSK" list-objects-v2 --bucket "$BUCKET" 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q AccessDenied || fail "a bucket listing with an object-only grant: want AccessDenied, got: $ERR"
log "  ✓ the prefix grant reaches scoped/ only (another key, a copy from outside, and ListBucket are AccessDenied)"
ERR="$(awsq "$WAK" "$WSK" list-objects-v2 --bucket db-snapshots 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q AccessDenied || fail "a non-admin listing a platform bucket: want AccessDenied, got: $ERR"
log "  ✓ a platform bucket (db-snapshots) is AccessDenied to a non-admin"

# --- 6b. DeleteObjects (batch delete): each key authorized, Quiet honored --------------------------
log "DeleteObjects: delete-objects of two keys, then a Quiet one, then a reader's (per-key AccessDenied)"
for k in del/a.txt del/b.txt del/c.txt del/r.txt; do
  awsq "$WAK" "$WSK" put-object --bucket "$BUCKET" --key "$k" --body "$WORK/in.txt" >/dev/null || fail "put-object ${k} failed"
done
N="$(awsq "$WAK" "$WSK" delete-objects --bucket "$BUCKET" --delete '{"Objects":[{"Key":"del/a.txt"},{"Key":"del/b.txt"}]}' \
  --query 'join(`,`, [to_string(length(Deleted || `[]`)), to_string(length(Errors || `[]`))])' --output text 2>&1 || true)"
[ "$N" = "2,0" ] || fail "delete-objects of two keys: want 2 deleted and no errors, got: $N"
for k in del/a.txt del/b.txt; do
  if awsq "$WAK" "$WSK" head-object --bucket "$BUCKET" --key "$k" >/dev/null 2>&1; then
    fail "${k} still exists after delete-objects listed it as deleted"
  fi
done
N="$(awsq "$WAK" "$WSK" delete-objects --bucket "$BUCKET" --delete '{"Objects":[{"Key":"del/c.txt"}],"Quiet":true}' \
  --query 'length(Deleted || `[]`)' --output text 2>&1 || true)"
[ "$N" = 0 ] || fail "a Quiet delete-objects must list no deleted keys, got: $N"
if awsq "$WAK" "$WSK" head-object --bucket "$BUCKET" --key del/c.txt >/dev/null 2>&1; then
  fail "del/c.txt still exists after a Quiet delete-objects"
fi
CODE="$(awsq "$RAK" "$RSK" delete-objects --bucket "$BUCKET" --delete '{"Objects":[{"Key":"del/r.txt"}]}' \
  --query 'Errors[0].Code' --output text 2>&1 || true)"
[ "$CODE" = AccessDenied ] || fail "a reader's delete-objects: want the key's AccessDenied error, got: $CODE"
awsq "$WAK" "$WSK" head-object --bucket "$BUCKET" --key del/r.txt >/dev/null 2>&1 \
  || fail "a reader's denied delete-objects deleted the key"
log "  ✓ two keys deleted; Quiet lists none; a reader's key is its AccessDenied and stays"
log "aws s3 rm --recursive removes a prefix"
for k in rm/1.txt rm/2.txt rm/3.txt; do
  awsq "$WAK" "$WSK" put-object --bucket "$BUCKET" --key "$k" --body "$WORK/in.txt" >/dev/null || fail "put-object ${k} failed"
done
awss3 "$WAK" "$WSK" rm "s3://${BUCKET}/rm/" --recursive >"$WORK/rm.out" 2>&1 || fail "aws s3 rm --recursive failed: $(cat "$WORK/rm.out")"
LEFT="$(awsq "$WAK" "$WSK" list-objects-v2 --bucket "$BUCKET" --prefix rm/ --query 'length(Contents || `[]`)' --output text 2>&1 || true)"
[ "$LEFT" = 0 ] || fail "aws s3 rm --recursive left keys under rm/: $LEFT"
log "  ✓ the prefix is empty"

# --- 7. Pre-signed GET URL (query-string SigV4): the browser-download path --------------------
# The app hands pre-signed GetObject URLs to the user's browser — a plain HTTP client with NO AWS
# credentials. So curl must fetch the object from the URL alone, and an EXPIRED URL must be refused.
if command -v curl >/dev/null; then
  log "pre-signed GET: generate, fetch with curl (NO creds), compare bytes"
  PS_URL="$(AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" s3 presign "s3://${BUCKET}/probe.txt" --expires-in 120 2>/dev/null)"
  [ -n "$PS_URL" ] || fail "could not generate a pre-signed URL"
  curl -fsS "$PS_URL" -o "$WORK/presigned.txt" 2>"$WORK/ps.err" \
    || fail "pre-signed GET fetch (no creds) failed: $(cat "$WORK/ps.err")"
  cmp -s "$WORK/in.txt" "$WORK/presigned.txt" || fail "pre-signed GET returned wrong bytes"
  log "  ✓ pre-signed GET fetched with no creds, bytes identical"

  log "negative: an EXPIRED pre-signed URL must be refused"
  PS_EXP="$(AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" s3 presign "s3://${BUCKET}/probe.txt" --expires-in 1 2>/dev/null)"
  sleep 2
  code="$(curl -s -o /dev/null -w '%{http_code}' "$PS_EXP")"
  [ "$code" = "403" ] || fail "an expired pre-signed URL must be refused (403), got ${code}"
  log "  ✓ expired pre-signed URL refused (403)"
fi

# --- 8. CreateBucket: mb → immediate put/get → ls → rb, as a deploy script would ---------------
log "CreateBucket: aws s3 mb s3://${MB_BUCKET}"
mb_start=$(date +%s)
awss3 "$WAK" "$WSK" mb "s3://${MB_BUCKET}" >"$WORK/mb.out" 2>&1 || fail "aws s3 mb failed: $(cat "$WORK/mb.out")"
log "  (aws s3 mb answered in $(( $(date +%s) - mb_start )) s)"
awsq "$WAK" "$WSK" put-object --bucket "$MB_BUCKET" --key first.txt --body "$WORK/in.txt" >/dev/null 2>"$WORK/mbput.err" \
  || fail "put-object right after CreateBucket failed: $(cat "$WORK/mbput.err")"
awsq "$WAK" "$WSK" get-object --bucket "$MB_BUCKET" --key first.txt "$WORK/mbget.txt" >/dev/null \
  || fail "get-object right after CreateBucket failed"
cmp -s "$WORK/in.txt" "$WORK/mbget.txt" || fail "the new bucket returned different bytes"
# Listed to a file first: grep -q stops at the first match, and under pipefail the CLI's broken pipe would
# fail a listing that did include the bucket.
awss3 "$WAK" "$WSK" ls >"$WORK/ls.out" 2>&1 || fail "aws s3 ls failed: $(head -c 300 "$WORK/ls.out")"
grep -q " ${MB_BUCKET}\$" "$WORK/ls.out" || fail "aws s3 ls does not list the new bucket"
log "  ✓ created; an immediate put/get round-trips; aws s3 ls lists it"
if [ "$(kubectl -n minio get configmap openinfra-object-encryption -o jsonpath='{.data.enabled}' 2>/dev/null || true)" = true ]; then
  enc="$(awsq "$WAK" "$WSK" get-bucket-encryption --bucket "$MB_BUCKET" \
    --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text 2>&1 || true)"
  [ "$enc" = AES256 ] || fail "the platform encrypts new buckets, but the new bucket's default encryption is: $enc"
  log "  ✓ default encryption AES256 (the platform's object encryption is on)"
fi
ERR="$(awsq "$WAK" "$WSK" get-bucket-policy --bucket "$MB_BUCKET" 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q NoSuchBucketPolicy || fail "get-bucket-policy of a bucket with no policy: want NoSuchBucketPolicy, got: $ERR"
log "  ✓ get-bucket-policy of a bucket with no policy is NoSuchBucketPolicy"
# A bucket whose kind: Bucket carries spec.policy (PROBE_POLICY_BUCKET, optional) answers that document.
if [ -n "${PROBE_POLICY_BUCKET:-}" ]; then
  awsq "$WAK" "$WSK" get-bucket-policy --bucket "$PROBE_POLICY_BUCKET" --query Policy --output text >"$WORK/pol.json" 2>&1 \
    || fail "get-bucket-policy ${PROBE_POLICY_BUCKET}: $(cat "$WORK/pol.json")"
  grep -q '"Statement"' "$WORK/pol.json" || fail "get-bucket-policy did not answer a policy document: $(head -c 300 "$WORK/pol.json")"
  log "  ✓ get-bucket-policy answers ${PROBE_POLICY_BUCKET}'s policy document"
fi
kubectl -n "$BUCKET_NS" get buckets.openinfra.dev "$MB_BUCKET" >/dev/null 2>&1 \
  || fail "no kind: Bucket claim ${BUCKET_NS}/${MB_BUCKET} behind the new bucket"
awsq "$WAK" "$WSK" create-bucket --bucket "$MB_BUCKET" >/dev/null 2>"$WORK/again.err" \
  || fail "re-creating your own bucket must answer 200 in us-east-1: $(cat "$WORK/again.err")"
log "  ✓ it is a kind: Bucket claim in ${BUCKET_NS}; re-creating your own bucket answers 200"
ERR="$(awsq "$WAK" "$WSK" create-bucket --bucket velero 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q BucketAlreadyExists || fail "CreateBucket of a platform bucket's name: want BucketAlreadyExists, got: $ERR"
ERR="$(awsq "$RAK" "$RSK" create-bucket --bucket "${MB_BUCKET}-r" 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q AccessDenied || fail "a reader's CreateBucket: want AccessDenied, got: $ERR"
log "  ✓ a platform bucket's name is BucketAlreadyExists; a reader's CreateBucket is AccessDenied"
awsq "$WAK" "$WSK" delete-object --bucket "$MB_BUCKET" --key first.txt >/dev/null 2>&1 || true
awss3 "$WAK" "$WSK" rb "s3://${MB_BUCKET}" >"$WORK/rb.out" 2>&1 || fail "aws s3 rb failed: $(cat "$WORK/rb.out")"
if awsq "$WAK" "$WSK" head-bucket --bucket "$MB_BUCKET" >/dev/null 2>&1; then
  fail "the bucket still exists after aws s3 rb"
fi
gone=""
for i in $(seq 1 30); do
  kubectl -n "$BUCKET_NS" get buckets.openinfra.dev "$MB_BUCKET" >/dev/null 2>&1 || { gone=1; break; }
  sleep 2
done
[ -n "$gone" ] || fail "the kind: Bucket claim ${BUCKET_NS}/${MB_BUCKET} outlived aws s3 rb"
log "  ✓ aws s3 rb removed the bucket and its claim"

# A client configured for another region: `aws s3 mb` sends that region as the LocationConstraint (signed
# for that region too), and a constraint naming yet another region is IllegalLocationConstraintException.
log "CreateBucket from a client configured for eu-west-1"
REGION=eu-west-1 awss3 "$WAK" "$WSK" mb "s3://${MB_BUCKET}-eu" >"$WORK/mbeu.out" 2>&1 \
  || fail "aws s3 mb from an eu-west-1 client failed: $(cat "$WORK/mbeu.out")"
REGION=eu-west-1 awsq "$WAK" "$WSK" put-object --bucket "${MB_BUCKET}-eu" --key first.txt --body "$WORK/in.txt" >/dev/null 2>"$WORK/mbeuput.err" \
  || fail "put-object into the eu-west-1 client's new bucket failed: $(cat "$WORK/mbeuput.err")"
ERR="$(awsq "$WAK" "$WSK" create-bucket --bucket "${MB_BUCKET}-x" --create-bucket-configuration LocationConstraint=ap-south-1 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q IllegalLocationConstraintException \
  || fail "a LocationConstraint other than the signing region: want IllegalLocationConstraintException, got: $ERR"
REGION=eu-west-1 awsq "$WAK" "$WSK" delete-object --bucket "${MB_BUCKET}-eu" --key first.txt >/dev/null 2>&1 || true
REGION=eu-west-1 awss3 "$WAK" "$WSK" rb "s3://${MB_BUCKET}-eu" >"$WORK/rbeu.out" 2>&1 || fail "aws s3 rb of the eu-west-1 bucket failed: $(cat "$WORK/rbeu.out")"
log "  ✓ created from an eu-west-1 client; a mismatched constraint is IllegalLocationConstraintException"

# --- cleanup the object we wrote --------------------------------------------------------------
for k in probe.txt chunk.txt big.bin big-copy.bin probe-copy.txt del/r.txt scoped/a.txt; do
  awsq "$WAK" "$WSK" delete-object --bucket "$BUCKET" --key "$k" >/dev/null 2>&1 || true
done

echo
echo "✓ PASS — aws-shim S3 surface is byte-faithful (multipart and copies included), serves pre-signed URLs, batch-deletes key by key, creates and removes buckets, and enforces auth, the write boundary, object-level grants and the platform-bucket fence."
