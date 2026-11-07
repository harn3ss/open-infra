#!/usr/bin/env bash
# Revoke Vault's root tokens once the setup Job runs as vault-config (docs/encryption.md, step 4).
#
# Runs one throwaway pod in the vault namespace that holds the bootstrap token from the Secret
# vault-bootstrap (never on this machine, never printed). The pod:
#   1. revokes every OTHER token that carries the root policy (found by accessor), so no root token
#      outlives this run — not even one copied from an earlier bootstrap;
#   2. revokes the bootstrap token itself, and shows a call made with it is refused.
# It prints counts only: no token, no accessor. Then delete the Secret:
#   kubectl -n vault delete secret vault-bootstrap
# A root token can be generated again from the unseal or recovery keys (`vault operator generate-root`)
# should one be needed for recovery.
#
#   ./hack/vault-revoke-root.sh            # VAULT_IMAGE and VAULT_ADDR may be overridden
set -euo pipefail
NS="${VAULT_NS:-vault}"
IMAGE="${VAULT_IMAGE:-hashicorp/vault:1.17.2}"
ADDR="${VAULT_ADDR_IN_CLUSTER:-http://vault.vault.svc.cluster.local:8200}"

kubectl -n "$NS" get secret vault-bootstrap >/dev/null 2>&1 \
  || { echo "no Secret $NS/vault-bootstrap: nothing to revoke with (create it once from the root token)"; exit 1; }

read -r -d '' SCRIPT <<'SH' || true
set -eu
self="$(vault token lookup -field=accessor)"
case " $(vault token lookup -field=policies | tr -d '[]') " in
  *" root "*) ;;
  *) echo "the bootstrap token is not a root token: nothing revoked"; exit 1 ;;
esac
others=0
for a in $(vault list auth/token/accessors | tail -n +3); do
  [ "$a" = "$self" ] && continue
  case " $(vault write -field=policies auth/token/lookup-accessor accessor="$a" 2>/dev/null | tr -d '[]') " in
    *" root "*) vault token revoke -accessor "$a" >/dev/null && others=$((others + 1)) ;;
  esac
done
echo "revoked $others other root token(s)"
vault token revoke -self >/dev/null
if vault token lookup >/dev/null 2>&1; then
  echo "FAIL: the bootstrap token still answers"; exit 1
fi
echo "the bootstrap token is revoked: a call made with it is refused"
SH

OVERRIDES="$(jq -cn --arg image "$IMAGE" --arg addr "$ADDR" --arg script "$SCRIPT" '{spec: {
  restartPolicy: "Never",
  containers: [{name: "vault-root-revoke", image: $image, command: ["sh", "-c", $script],
    env: [{name: "VAULT_ADDR", value: $addr},
          {name: "VAULT_TOKEN", valueFrom: {secretKeyRef: {name: "vault-bootstrap", key: "token"}}}]}]}}')"
kubectl -n "$NS" run vault-root-revoke --rm -i --restart=Never --image="$IMAGE" --overrides="$OVERRIDES"
