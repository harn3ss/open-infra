#!/usr/bin/env bash
# Credential-assertion probe for the MinIO root credential.
#
# This exists to catch ONE specific false-green that #151 fault 2 documented from a live
# cluster: the platform distributes a root credential (`secret/minio`, keys rootUser /
# rootPassword, that ~15 consumers read — the shim, backups, the console, every bucket job)
# that the RUNNING server does not accept. The secret had been rotated (or the pods were
# started from another source) and the server never picked it up — the MinIO StatefulSet sets
# MINIO_ROOT_USER_FILE / MINIO_ROOT_PASSWORD_FILE, whose values take precedence, so the
# process kept the old pair while the secret on disk showed a new one. Nothing reconciled the
# two and nothing checked them, so the first honest signal was an application failing at
# runtime with InvalidAccessKeyId — a long way from the cause.
#
# This probe MINTS NOTHING and WRITES NOTHING. It reads the credential the platform hands out
# and simply asserts the running server accepts it — the checkable condition that would have
# caught the drift the day it happened. It follows the same "prove the no" discipline as
# probe/aws-shim-s3.sh: a positive (the distributed pair IS accepted) AND a negative (a WRONG
# secret is REJECTED), so a pass means auth actually fired rather than a server that accepts
# anything.
#
# On-demand (needs a deployed MinIO + kubectl read access to secret/minio + the mc OR aws
# CLI). Read-only and side-effect-free: creates no users, buckets, or objects. Run from a host
# with cluster access, or behind a port-forward.
#
# Exit 0 = pass (the distributed credential is the one the server accepts).
#      1 = a real failure (the credential the platform distributes is REJECTED — drift).
#     42 = INCONCLUSIVE (a prerequisite was missing, so nothing was proven), mirroring the
#          chaos suite + the other probes.
#
#   ./probe/minio-root-cred.sh
#   MINIO_ENDPOINT=http://localhost:9000 ./probe/minio-root-cred.sh   # behind a port-forward
set -euo pipefail

EXIT_INCONCLUSIVE=42
MINIO_NS="${MINIO_NS:-minio}"
SECRET_NAME="${MINIO_SECRET:-minio}"
ENDPOINT="${MINIO_ENDPOINT:-http://minio.${MINIO_NS}.svc.cluster.local:9000}"

log()          { printf '▸ %s\n' "$*"; }
fail()         { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

# --- 0. Preflight -----------------------------------------------------------------------------
command -v kubectl >/dev/null || inconclusive "kubectl is required to read the distributed credential (secret/${SECRET_NAME} -n ${MINIO_NS})"
HAVE_MC=""; command -v mc  >/dev/null && HAVE_MC=1
HAVE_AWS=""; command -v aws >/dev/null && HAVE_AWS=1
[ -n "$HAVE_MC" ] || [ -n "$HAVE_AWS" ] || inconclusive "need the mc OR aws CLI to authenticate to the server"
curl -fsS -m 5 "${ENDPOINT}/minio/health/live" >/dev/null 2>&1 \
  || inconclusive "MinIO not reachable at ${ENDPOINT} (set MINIO_ENDPOINT / port-forward)"

# --- 1. Read the credential the PLATFORM distributes -----------------------------------------
log "reading the distributed credential from secret/${SECRET_NAME} -n ${MINIO_NS}"
RU="$(kubectl -n "$MINIO_NS" get secret "$SECRET_NAME" -o jsonpath='{.data.rootUser}' 2>/dev/null | base64 -d 2>/dev/null || true)"
RP="$(kubectl -n "$MINIO_NS" get secret "$SECRET_NAME" -o jsonpath='{.data.rootPassword}' 2>/dev/null | base64 -d 2>/dev/null || true)"
[ -n "$RU" ] && [ -n "$RP" ] \
  || inconclusive "secret/${SECRET_NAME} -n ${MINIO_NS} has no rootUser/rootPassword (nothing to assert)"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
[ -n "$HAVE_MC" ] && export MC_CONFIG_DIR="$WORK/mc"   # keep our alias out of the caller's ~/.mc

# assert_accepted <user> <pass>  -> exit 0 if the server ACCEPTS the pair, non-zero if it rejects.
# Read-only: mc admin info (needs valid admin auth — root has it) with an S3 ListBuckets fallback.
assert_accepted() {
  local u="$1" p="$2"
  if [ -n "$HAVE_MC" ]; then
    mc alias set probecheck "$ENDPOINT" "$u" "$p" >/dev/null 2>&1 || return 1
    # admin info requires authenticated admin; a rejected credential fails here.
    mc admin info probecheck >/dev/null 2>&1 && return 0
    # some deployments restrict admin over the API port; fall back to a signed S3 list.
    mc ls probecheck >/dev/null 2>&1 && return 0
    return 1
  fi
  AWS_ACCESS_KEY_ID="$u" AWS_SECRET_ACCESS_KEY="$p" AWS_REGION="${AWS_REGION:-us-east-1}" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager s3api list-buckets >/dev/null 2>&1
}

# --- 2. POSITIVE: the distributed credential IS accepted by the running server ----------------
log "asserting the distributed root credential is accepted by the server at ${ENDPOINT}"
assert_accepted "$RU" "$RP" \
  || fail "the running server REJECTS the credential the platform distributes (secret/${SECRET_NAME}). \
The distributed pair is not the one the server accepts — the #151 fault-2 drift. Every downstream \
consumer (shim, backups, console, bucket jobs) inherits this rejected credential. Reconcile the \
server's root credential with secret/${SECRET_NAME} and restart the MinIO pods."
log "  ✓ accepted"

# --- 3. NEGATIVE: a WRONG secret must be REJECTED (prove auth actually fires) -----------------
log "negative: the same user with a WRONG secret must be rejected"
if assert_accepted "$RU" "wrong-secret-not-the-real-one-$RANDOM"; then
  fail "the server ACCEPTED a wrong secret for the root user (authentication theater — a pass here \
would be meaningless)"
fi
log "  ✓ rejected"

echo
echo "✓ PASS — the credential the platform distributes (secret/${SECRET_NAME}) is the one the MinIO server accepts."
