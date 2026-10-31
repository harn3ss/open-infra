#!/usr/bin/env bash
# Compatibility probe for the aws-shim VM workload-credentials surface (#344) — the AWS
# container-credentials provider (ECS/EKS Pod Identity shape) that gives a kind: VirtualMachine
# rotating role credentials with NO static keys.
#
# This is the trust-earning artifact for "a VM assumes a role": it drives the REAL endpoint the AWS
# SDK's container-credentials provider calls (GET $AWS_CONTAINER_CREDENTIALS_FULL_URI with the
# identity token in Authorization) and asserts the WHOLE chain, not just HTTP 200:
#   - a VM's per-VM ServiceAccount token (what KubeVirt projects into the guest) is exchanged for
#     TEMPORARY credentials (AccessKeyId begins "ASIA", carries a SessionToken + Expiration), and
#   - those credentials actually AUTHENTICATE: sts:GetCallerIdentity returns
#     assumed-role/<role>/<session> (the role the SA's openinfra.dev/instance-role annotation names).
# and the NEGATIVES that are the point ("prove the no"):
#   - no token            -> 401 (the endpoint never serves credentials unauthenticated)
#   - a token whose role does NOT trust the "vm" principal -> 403 (opt-in; a role must allow it)
#
# On-demand (needs a deployed shim with IMDS_ENABLED=true, the platform IAM, and the control-plane
# grant letting the shim read ServiceAccounts). Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-vm-credentials.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ROLES_NS="${ROLES_NS:-default}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
SFX="$(date +%s)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required to seed the role + ServiceAccount"
command -v curl    >/dev/null || inconclusive "curl is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"

ROLE="vmcredprobe-${SFX}"
ROLE_UNTRUSTED="vmcredprobe-untrusted-${SFX}"
SA="vm-vmcredprobe-${SFX}"
SA_UNTRUSTED="vm-vmcredprobe-untrusted-${SFX}"
VMCREDS_URL="${ENDPOINT}/v1/vm-credentials"

cleanup() {
  kubectl delete role.iam.openinfra.dev "$ROLE" "$ROLE_UNTRUSTED" -n "$ROLES_NS" --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete sa "$SA" "$SA_UNTRUSTED" -n "$ROLES_NS" --ignore-not-found >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- 1. Seed a vm-trusted Role + its per-VM ServiceAccount (what the composition creates) ---------
log "seeding a vm-trusted Role + a per-VM ServiceAccount annotated with it"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Role
metadata: { name: "${ROLE}", namespace: "${ROLES_NS}" }
spec: { description: "vm-credentials probe", trust: ["vm"] }
---
apiVersion: iam.openinfra.dev/v1
kind: Role
metadata: { name: "${ROLE_UNTRUSTED}", namespace: "${ROLES_NS}" }
spec: { description: "vm-credentials probe (not vm-trusted)", trust: ["someuser"] }
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: "${SA}"
  namespace: "${ROLES_NS}"
  annotations: { openinfra.dev/instance-role: "${ROLE}", openinfra.dev/vm: "vmcredprobe" }
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: "${SA_UNTRUSTED}"
  namespace: "${ROLES_NS}"
  annotations: { openinfra.dev/instance-role: "${ROLE_UNTRUSTED}", openinfra.dev/vm: "vmcredprobe-u" }
YAML
sleep 2

TOKEN="$(kubectl create token "$SA" -n "$ROLES_NS" --duration=1h 2>/dev/null || true)"
[ -n "$TOKEN" ] || inconclusive "could not mint a ServiceAccount token (TokenRequest denied?)"
TOKEN_U="$(kubectl create token "$SA_UNTRUSTED" -n "$ROLES_NS" --duration=1h 2>/dev/null || true)"

# --- 2. POSITIVE: the SA token yields temporary credentials --------------------------------------
log "exchanging the ServiceAccount token for role credentials at ${VMCREDS_URL}"
CREDS="$(curl -s -H "Authorization: ${TOKEN}" "$VMCREDS_URL")"
AK="$(printf '%s' "$CREDS" | sed -n 's/.*"AccessKeyId":"\([^"]*\)".*/\1/p')"
SK="$(printf '%s' "$CREDS" | sed -n 's/.*"SecretAccessKey":"\([^"]*\)".*/\1/p')"
TK="$(printf '%s' "$CREDS" | sed -n 's/.*"Token":"\([^"]*\)".*/\1/p')"
[ -n "$AK" ] && [ -n "$SK" ] && [ -n "$TK" ] || fail "no credentials returned for a valid VM token (got: ${CREDS:0:200})"
case "$AK" in ASIA*) : ;; *) fail "AccessKeyId must be a TEMPORARY credential (ASIA…), got ${AK}" ;; esac
log "got temporary credentials ${AK} (session token + expiry present)"

# --- 3. POSITIVE: those credentials AUTHENTICATE as the assumed role -----------------------------
log "calling sts:GetCallerIdentity with the VM's credentials"
ARN="$(AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="$TK" AWS_REGION=openinfra \
  aws --endpoint-url "$ENDPOINT" --no-cli-pager sts get-caller-identity --query Arn --output text 2>/dev/null || true)"
case "$ARN" in
  *":assumed-role/${ROLE}/"*) log "identity confirmed: ${ARN}" ;;
  *) fail "credentials did not authenticate as assumed-role/${ROLE}/… (got: ${ARN:-<none>})" ;;
esac

# --- 4. NEGATIVE: no token is refused (never serves credentials unauthenticated) -----------------
log "NEGATIVE: an unauthenticated request must be refused"
CODE="$(curl -s -o /dev/null -w '%{http_code}' "$VMCREDS_URL")"
[ "$CODE" = "401" ] || fail "unauthenticated vm-credentials must be 401, got ${CODE}"

# --- 5. NEGATIVE: a role that does not trust "vm" is denied (opt-in) ------------------------------
if [ -n "$TOKEN_U" ]; then
  log "NEGATIVE: a role whose trust omits \"vm\" must be denied"
  CODE_U="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: ${TOKEN_U}" "$VMCREDS_URL")"
  [ "$CODE_U" = "403" ] || fail "a non-vm-trusted role must be 403 (role not assumable by an instance), got ${CODE_U}"
fi

printf '✓ PASS: VM workload credentials are faithful — a ServiceAccount token yields temporary\n'
printf '        assumed-role credentials (no static keys); unauthenticated=401, non-vm-trusted=403.\n'
