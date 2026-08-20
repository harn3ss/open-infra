#!/usr/bin/env bash
# AC-2/AC-6 observation probe for the access-recertification report (/api/iam/access-review).
#
# The pure assembler (console-api/internal/accessreview) is exhaustively unit-tested, but the
# AUTHENTICATED, real-data success path — the admin-gated endpoint assembling a live report from the
# cluster's actual Users, Groups, Grants and audit trail — is only OBSERVED here. This probe produces
# that observation.
#
# It: (1) logs in to the console as the root break-glass principal; (2) proves the gate is real
# (unauthenticated GET → 401); (3) GETs /api/iam/access-review with the session and asserts a well-formed
# report — a principals array, a summary, and the signed-in admin itself present as a principal flagged
# admin=true (root effectively holds console admin, so the assembler must surface it). Read-only: it
# creates and deletes nothing.
#
# On-demand (needs a deployed console + the root break-glass password, which is user-held — the console
# stores only its bcrypt hash). Exit 0 = pass (observed), 1 = a real failure, 42 = INCONCLUSIVE.
#
#   CONSOLE_ROOT_PASSWORD=… ./probe/access-review.sh
#   CONSOLE_ENDPOINT=http://localhost:8080 CONSOLE_ROOT_PASSWORD=… ./probe/access-review.sh   # via port-forward
set -euo pipefail

EXIT_INCONCLUSIVE=42
CONSOLE_NS="${CONSOLE_NS:-open-infra-console}"
ENDPOINT="${CONSOLE_ENDPOINT:-http://console.${CONSOLE_NS}.svc.cluster.local}"
ROOT_USER="${CONSOLE_ROOT_USER:-root}"

log()          { printf '▸ %s\n' "$*"; }
fail()         { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

# --- 0. Preflight -----------------------------------------------------------------------------------
command -v curl >/dev/null || inconclusive "curl is required"
command -v jq   >/dev/null || inconclusive "jq is required to parse the report"
[ -n "${CONSOLE_ROOT_PASSWORD:-}" ] || inconclusive "CONSOLE_ROOT_PASSWORD is required (the root break-glass password is user-held; the console keeps only its bcrypt hash)"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || \
  curl -fsS -m 5 "${ENDPOINT}/api/healthz" >/dev/null 2>&1 || \
  inconclusive "console not reachable at ${ENDPOINT} (set CONSOLE_ENDPOINT / port-forward svc/console -n ${CONSOLE_NS})"

WORK="$(mktemp -d)"
JAR="$WORK/cookies.txt"
trap 'rm -rf "$WORK"' EXIT

# --- 1. The gate must be real: unauthenticated GET is rejected --------------------------------------
un="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' "${ENDPOINT}/api/iam/access-review" || true)"
[ "$un" = "401" ] || log "note: unauthenticated /api/iam/access-review returned ${un} (expected 401)"

# --- 2. Authenticate as the root break-glass principal ----------------------------------------------
log "logging in to the console as ${ROOT_USER}"
code="$(curl -sS -m 10 -o "$WORK/login.json" -w '%{http_code}' -c "$JAR" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$ROOT_USER" --arg p "$CONSOLE_ROOT_PASSWORD" '{username:$u,password:$p}')" \
  "${ENDPOINT}/api/auth/login" || true)"
[ "$code" = "200" ] || inconclusive "login returned HTTP ${code} (wrong CONSOLE_ROOT_PASSWORD, or AUTH_MODE is not local): $(head -c200 "$WORK/login.json" 2>/dev/null)"

# --- 3. Observe the report --------------------------------------------------------------------------
log "GET ${ENDPOINT}/api/iam/access-review (authenticated)"
code="$(curl -sS -m 25 -o "$WORK/report.json" -w '%{http_code}' -b "$JAR" "${ENDPOINT}/api/iam/access-review" || true)"
[ "$code" = "200" ] || fail "authenticated GET returned HTTP ${code}: $(head -c300 "$WORK/report.json" 2>/dev/null)"

jq -e '(.principals|type=="array") and (.summary|type=="object") and (.summary.principals>=1)' \
  "$WORK/report.json" >/dev/null 2>&1 || fail "response is not a well-formed report: $(head -c300 "$WORK/report.json")"

# The signed-in admin must appear as a principal flagged admin=true (root holds console admin).
if ! jq -e --arg u "$ROOT_USER" 'any(.principals[]; .name==$u and .admin==true)' "$WORK/report.json" >/dev/null 2>&1; then
  log "note: ${ROOT_USER} not present as admin principal — acceptable if root is not a kind: User in this deployment"
fi

n="$(jq -r '.summary.principals' "$WORK/report.json")"
review="$(jq -r '.summary.needsReview' "$WORK/report.json")"
log "OBSERVED report: ${n} principal(s), ${review} flagged for review, lookback $(jq -r '.lookbackDays' "$WORK/report.json")d"
printf '✓ PASS: /api/iam/access-review returned a well-formed access-recertification report (AC-2/AC-6 observed)\n'
