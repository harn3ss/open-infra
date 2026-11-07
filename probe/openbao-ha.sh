#!/usr/bin/env bash
# Probe: OpenBao (platform/security/openbao.yaml) runs as three members on three different nodes, all
# unsealed by the unseal host, one active, all at the same Raft index. With --drill it also deletes the
# active member and asserts that another member takes over and the deleted one comes back unsealed.
#
# Asserted:
#   - three member pods, Ready, each on a different node;
#   - each member is initialized, unsealed, sealed by "transit" (the unseal host) and in HA mode;
#   - exactly one member is active, and the members' Raft committed indexes agree (within a small lag);
#   - --drill: after the active member is deleted, another member is active within DRILL_FAILOVER_S
#     seconds, and the deleted member is back, Ready and unsealed, within DRILL_REJOIN_S seconds.
#
# Uses only `bao status` (unauthenticated) inside the members: no token, no Secret is read. The drill
# deletes one pod and changes nothing else; run it when a short failover is acceptable.
# Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE (OpenBao not deployed or not yet initialized).
#
#   ./probe/openbao-ha.sh            # state only
#   ./probe/openbao-ha.sh --drill    # state, then lose the active member
set -euo pipefail

EXIT_INCONCLUSIVE=42
NS="${OPENBAO_NS:-openbao}"
MAX_LAG="${MAX_LAG:-5}"
DRILL_FAILOVER_S="${DRILL_FAILOVER_S:-30}"
DRILL_REJOIN_S="${DRILL_REJOIN_S:-180}"
DRILL=0
[ "${1:-}" = "--drill" ] && DRILL=1

log()  { printf '▸ %s\n' "$*"; }
ok()   { printf '  ✓ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for t in kubectl jq; do command -v "$t" >/dev/null || inconclusive "$t is required"; done
kubectl -n "$NS" get statefulset openbao >/dev/null 2>&1 || inconclusive "no OpenBao in namespace $NS (components.openbao is off?)"

# status <member> -> one line of JSON: the member's `bao status`, or {} when it does not answer.
status() { kubectl -n "$NS" exec "$1" -c openbao -- bao status -format=json 2>/dev/null || echo '{}'; }

check_members() {
  local pods nodes
  pods="$(kubectl -n "$NS" get pods -l app.kubernetes.io/name=openbao,component=server -o json)"
  [ "$(jq '.items | length' <<<"$pods")" = 3 ] || fail "expected 3 member pods, found $(jq '.items | length' <<<"$pods")"
  nodes="$(jq -r '[.items[].spec.nodeName] | unique | length' <<<"$pods")"
  [ "$nodes" = 3 ] || fail "the members share a node: $(jq -r '[.items[] | .metadata.name + "@" + (.spec.nodeName // "-")] | join(" ")' <<<"$pods")"
  ok "three members on three nodes: $(jq -r '[.items[] | .metadata.name + "@" + .spec.nodeName] | join(", ")' <<<"$pods")"
  jq -e '[.items[] | .status.conditions[]? | select(.type == "Ready") | .status] | all(. == "True")' <<<"$pods" >/dev/null \
    || fail "not every member is Ready: $(jq -r '[.items[] | .metadata.name + "=" + ([.status.conditions[]? | select(.type == "Ready") | .status] | first // "?")] | join(" ")' <<<"$pods")"
  ok "all three are Ready"

  local active=0 min="" max="" m s
  for m in openbao-0 openbao-1 openbao-2; do
    s="$(status "$m")"
    [ "$(jq -r '.initialized // false' <<<"$s")" = true ] || {
      [ "$m" = openbao-0 ] && inconclusive "OpenBao is not initialized yet (docs/openbao.md, 'Turning it on')"
      fail "$m is not initialized"; }
    [ "$(jq -r '.sealed' <<<"$s")" = false ] || fail "$m is sealed"
    [ "$(jq -r '.type' <<<"$s")" = transit ] || fail "$m is sealed by '$(jq -r '.type' <<<"$s")', not by the unseal host (transit)"
    [ "$(jq -r '.ha_enabled' <<<"$s")" = true ] || fail "$m is not in HA mode"
    [ "$(jq -r '.is_self' <<<"$s")" = true ] && active=$((active + 1))
    local idx; idx="$(jq -r '.raft_committed_index' <<<"$s")"
    { [ -z "$min" ] || [ "$idx" -lt "$min" ]; } && min="$idx"
    { [ -z "$max" ] || [ "$idx" -gt "$max" ]; } && max="$idx"
  done
  [ "$active" = 1 ] || fail "expected exactly one active member, found $active"
  [ $((max - min)) -le "$MAX_LAG" ] || fail "the members' Raft indexes disagree: $min..$max (more than $MAX_LAG apart)"
  ok "each member initialized, unsealed by the unseal host, one active, Raft index $max (lag $((max - min)))"
}

active_member() {
  local m
  for m in openbao-0 openbao-1 openbao-2; do
    [ "$(status "$m" | jq -r '.is_self // false')" = true ] && { echo "$m"; return; }
  done
}

log "OpenBao members in namespace $NS"
check_members

[ "$DRILL" = 1 ] || exit 0

log "drill: lose the active member"
victim="$(active_member)"
[ -n "$victim" ] || fail "no active member to delete"
kubectl -n "$NS" delete pod "$victim" --wait=false >/dev/null
start=$(date +%s)
ok "deleted $victim (the active member)"

new=""
while [ $(( $(date +%s) - start )) -le "$DRILL_FAILOVER_S" ]; do
  for m in openbao-0 openbao-1 openbao-2; do
    [ "$m" = "$victim" ] && continue
    [ "$(status "$m" | jq -r '.is_self // false')" = true ] && { new="$m"; break 2; }
  done
  sleep 1
done
[ -n "$new" ] || fail "no other member became active within ${DRILL_FAILOVER_S}s"
ok "$new is active after $(( $(date +%s) - start ))s"

ready=""
while [ $(( $(date +%s) - start )) -le "$DRILL_REJOIN_S" ]; do
  ready="$(kubectl -n "$NS" get pod "$victim" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
  [ "$ready" = True ] && [ "$(status "$victim" | jq -r '.sealed')" = false ] && break
  sleep 3
done
[ "$ready" = True ] || fail "$victim did not come back Ready and unsealed within ${DRILL_REJOIN_S}s"
ok "$victim is back, unsealed by the unseal host, after $(( $(date +%s) - start ))s"
sleep 5
check_members
