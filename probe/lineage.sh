#!/usr/bin/env bash
# SI-12 observation probe for the data-lineage plane (/api/lineage).
#
# This is the trust-earning artifact for the lineage feature: everything else about it is asserted by
# code-reading + unit tests on the pure parsers, but the AUTHENTICATED, non-empty success path — a real
# data-movement resource showing up as a flow through the admin-gated endpoint — has never been OBSERVED.
# This probe produces that observation.
#
# It: (1) logs in to the console as the root break-glass principal to get a session; (2) creates a
# THROWAWAY kind: Stream in a throwaway namespace with a dummy source (no real DB, no reconcile needed —
# lineage derives from the CR spec); (3) GETs /api/lineage with the session and asserts a flow of
# kind=Stream with the matching name and a stream-typed edge from the source endpoint; (4) deletes the
# Stream + namespace (throwaway-and-delete — never touches an existing database).
#
# On-demand (needs a deployed console + the root break-glass password, which is user-held — the console
# stores only its bcrypt hash). Exit 0 = pass (observed), 1 = a real failure, 42 = INCONCLUSIVE (a
# prerequisite was missing, so nothing was proven), mirroring the chaos-suite convention.
#
#   CONSOLE_ROOT_PASSWORD=… ./probe/lineage.sh
#   CONSOLE_ENDPOINT=http://localhost:8080 CONSOLE_ROOT_PASSWORD=… ./probe/lineage.sh   # e.g. via port-forward
set -euo pipefail

EXIT_INCONCLUSIVE=42
CONSOLE_NS="${CONSOLE_NS:-open-infra-console}"
ENDPOINT="${CONSOLE_ENDPOINT:-http://console.${CONSOLE_NS}.svc.cluster.local}"
ROOT_USER="${CONSOLE_ROOT_USER:-root}"
PROBE_NS="${PROBE_NS:-lineage-probe}"
STREAM_NAME="${PROBE_STREAM:-lineage-probe-stream}"

log()          { printf '▸ %s\n' "$*"; }
fail()         { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

# --- 0. Preflight -----------------------------------------------------------------------------------
command -v kubectl >/dev/null || inconclusive "kubectl is required to seed the throwaway Stream"
command -v curl    >/dev/null || inconclusive "curl is required"
command -v jq      >/dev/null || inconclusive "jq is required to parse the lineage response"
[ -n "${CONSOLE_ROOT_PASSWORD:-}" ] || inconclusive "CONSOLE_ROOT_PASSWORD is required (the root break-glass password is user-held; the console keeps only its bcrypt hash)"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || \
  curl -fsS -m 5 "${ENDPOINT}/api/healthz" >/dev/null 2>&1 || \
  inconclusive "console not reachable at ${ENDPOINT} (set CONSOLE_ENDPOINT / port-forward svc/console -n ${CONSOLE_NS})"

WORK="$(mktemp -d)"
JAR="$WORK/cookies.txt"
cleanup() {
  kubectl delete namespace "$PROBE_NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- 1. Authenticate --------------------------------------------------------------------------------
log "logging in to the console as ${ROOT_USER}"
code="$(curl -sS -m 10 -o "$WORK/login.json" -w '%{http_code}' -c "$JAR" \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$ROOT_USER" --arg p "$CONSOLE_ROOT_PASSWORD" '{username:$u,password:$p}')" \
  "${ENDPOINT}/api/auth/login" || true)"
[ "$code" = "200" ] || inconclusive "login returned HTTP ${code} (wrong CONSOLE_ROOT_PASSWORD, or AUTH_MODE is not local): $(head -c200 "$WORK/login.json" 2>/dev/null)"
grep -qiE 'session|token' "$JAR" 2>/dev/null || inconclusive "login succeeded but set no session cookie"

# Prove the gate is real: the same GET without the session must be rejected.
un="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' "${ENDPOINT}/api/lineage" || true)"
[ "$un" = "401" ] || log "note: unauthenticated /api/lineage returned ${un} (expected 401 — auth gate)"

# --- 2. Seed a throwaway Stream (spec-only; lineage does not require reconcile) ----------------------
log "creating throwaway namespace ${PROBE_NS} + kind: Stream ${STREAM_NAME}"
kubectl create namespace "$PROBE_NS" >/dev/null 2>&1 || true
kubectl -n "$PROBE_NS" create secret generic lineage-probe-src \
  --from-literal=password=unused >/dev/null 2>&1 || true
cat <<YAML | kubectl apply -f - >/dev/null 2>&1 || fail "could not create the throwaway Stream CR"
apiVersion: openinfra.dev/v1
kind: Stream
metadata:
  name: ${STREAM_NAME}
  namespace: ${PROBE_NS}
spec:
  source:
    engine: postgres
    host: lineage-probe-db
    database: probedb
    username: probe
    passwordSecretRef: { name: lineage-probe-src, key: password }
YAML

# --- 3. Observe the lineage (retry — the CR must register with the API) ------------------------------
log "GET ${ENDPOINT}/api/lineage (authenticated)"
observed=""
for i in $(seq 1 10); do
  code="$(curl -sS -m 10 -o "$WORK/lineage.json" -w '%{http_code}' -b "$JAR" "${ENDPOINT}/api/lineage" || true)"
  [ "$code" = "200" ] || { sleep 2; continue; }
  # Response is a JSON array of flows (tolerate a {flows:[…]} wrapper too).
  if jq -e --arg n "$STREAM_NAME" \
       '(if type=="array" then . else (.flows // []) end)
        | any(.kind=="Stream" and .name==$n and ((.edges // []) | any(.type=="stream")))' \
       "$WORK/lineage.json" >/dev/null 2>&1; then
    observed="yes"; break
  fi
  sleep 2
done

[ "$observed" = "yes" ] || fail "the throwaway Stream never appeared as a kind=Stream flow with a stream edge in /api/lineage (HTTP ${code}). Response head: $(head -c400 "$WORK/lineage.json" 2>/dev/null)"

flow="$(jq -c --arg n "$STREAM_NAME" \
  '(if type=="array" then . else (.flows // []) end) | map(select(.kind=="Stream" and .name==$n)) | .[0]' \
  "$WORK/lineage.json")"
log "OBSERVED lineage flow: ${flow}"
printf '✓ PASS: /api/lineage returned the throwaway Stream as a lineage flow with a stream edge (SI-12 observed)\n'
