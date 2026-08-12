#!/usr/bin/env bash
# Live verification of the customer-owned encryption stack (Vault Transit KMS + kind: EncryptionKey +
# kind: Destruction crypto-erase). GovStack / NIST SC-12/13/28(1). This is the trust-earning artifact
# that lets vault.yaml drop its EXPERIMENTAL flag: it proves, on the RUNNING cluster, that
#   1. a kind: EncryptionKey provisions a real Transit key,
#   2. a value encrypted through that key decrypts back BYTE-IDENTICAL (the KEK actually wraps/unwraps),
#   3. crypto-erase (kind: Destruction) destroys the key so the wrapped data is UNRECOVERABLE.
#
# HUMAN-GATED PREREQUISITES (this script cannot do them — custody of unseal keys is an operator duty):
#   - components.encryption: true, and audit off-siting enabled (the destroyer requires it).
#   - Vault initialized + unsealed:  kubectl -n vault exec vault-0 -- vault operator init ; unseal x3.
#   - A short-lived token with transit encrypt+decrypt on enc-verify + read transit/keys, exported as
#     VAULT_TOKEN (issue a throwaway policy for the probe, then revoke it).
# Run:  VAULT_TOKEN=<token> probe/encryption-vault.sh
set -uo pipefail

NS_VAULT="${VAULT_NS:-vault}"
POD="${VAULT_POD:-vault-0}"
KEY="enc-verify"
PLAIN="govstack-encryption-roundtrip-OK"

fail() { echo "▸ FAIL — $*" >&2; exit 1; }
vault_() { kubectl -n "$NS_VAULT" exec "$POD" -- env VAULT_TOKEN="${VAULT_TOKEN:?export VAULT_TOKEN (see header)}" vault "$@"; }

echo "▸ pre-flight: Vault reachable + UNSEALED?"
sealed="$(kubectl -n "$NS_VAULT" exec "$POD" -- vault status -format=json 2>/dev/null | grep -o '"sealed": *[a-z]*' | grep -o '[a-z]*$')"
[ "$sealed" = "false" ] || fail "Vault is sealed or unreachable — an operator must init + unseal it first (see header). Not a product failure."

echo "▸ provisioning kind: EncryptionKey/$KEY and waiting for the reconciler to create the Transit key"
kubectl apply -f - >/dev/null <<YAML || fail "could not apply EncryptionKey"
apiVersion: openinfra.dev/v1
kind: EncryptionKey
metadata: { name: $KEY, namespace: default }
spec: { description: "govstack live-verify", keyType: aes256-gcm96, rotationDays: 90 }
YAML
for _ in $(seq 1 60); do vault_ read "transit/keys/$KEY" >/dev/null 2>&1 && break; sleep 5; done
vault_ read "transit/keys/$KEY" >/dev/null 2>&1 || fail "Transit key transit/keys/$KEY was not created within the budget (reconciler not running / not authorized)."
echo "  key present."

echo "▸ round-trip: encrypt then decrypt must return byte-identical plaintext"
b64="$(printf '%s' "$PLAIN" | base64 | tr -d '\n')"
ct="$(vault_ write -field=ciphertext "transit/encrypt/$KEY" plaintext="$b64")"
[ -n "$ct" ] || fail "encrypt returned no ciphertext"
got="$(vault_ write -field=plaintext "transit/decrypt/$KEY" ciphertext="$ct" | base64 -d 2>/dev/null)"
[ "$got" = "$PLAIN" ] || fail "decrypt did NOT return the original plaintext (got '$got') — the KEK does not round-trip."
echo "  PASS — customer KEK wraps + unwraps byte-identical."

echo "▸ crypto-erase: kind: Destruction must make transit/keys/$KEY unrecoverable"
kubectl apply -f - >/dev/null <<YAML || fail "could not apply Destruction"
apiVersion: openinfra.dev/v1
kind: Destruction
metadata: { name: $KEY, namespace: default }
spec: { encryptionKey: $KEY, confirm: $KEY, reason: "govstack live-verify crypto-erase" }
YAML
for _ in $(seq 1 60); do vault_ read "transit/keys/$KEY" >/dev/null 2>&1 || break; sleep 5; done
if vault_ read "transit/keys/$KEY" >/dev/null 2>&1; then fail "key still present after Destruction — crypto-erase did not complete."; fi
# the wrapped data is now unrecoverable — decrypt must fail
if vault_ write "transit/decrypt/$KEY" ciphertext="$ct" >/dev/null 2>&1; then fail "decrypt STILL works after crypto-erase — data is not actually unrecoverable."; fi
echo "  PASS — key destroyed; the previously-encrypted value is now unrecoverable."

echo "▸ cleanup"
kubectl delete encryptionkey "$KEY" destruction "$KEY" -n default --ignore-not-found >/dev/null 2>&1 || true
echo "▸ PASS — encryption stack live-verified: provision -> round-trip -> crypto-erase. Safe to drop the EXPERIMENTAL flag on vault.yaml (see docs/encryption.md)."
