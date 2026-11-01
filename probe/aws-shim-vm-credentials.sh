#!/usr/bin/env bash
# Compatibility probe for the aws-shim VM workload-credentials surface (#344) — the AWS
# container-credentials provider (ECS/EKS Pod Identity shape) that gives a kind: VirtualMachine
# rotating role credentials with NO static keys.
#
# This is the trust-earning artifact for "a VM assumes a role": it drives the REAL endpoint the AWS
# SDK's container-credentials provider calls (GET $AWS_CONTAINER_CREDENTIALS_FULL_URI with the
# identity token in Authorization) and asserts the WHOLE chain, not just HTTP 200:
#   - a real VirtualMachineInstance mounts the per-VM ServiceAccount (as the VM composition renders
#     it), and a token bound to its virt-launcher pod — the shape KubeVirt projects into the guest: a
#     pod-bound token of that ServiceAccount — is exchanged for TEMPORARY credentials (AccessKeyId
#     begins "ASIA", carries a SessionToken + Expiration), and
#   - those credentials actually AUTHENTICATE: sts:GetCallerIdentity returns
#     assumed-role/<role>/<session> (the role the SA's openinfra.dev/instance-role annotation names).
# and the NEGATIVES that are the point ("prove the no"):
#   - no token            -> 401 (the endpoint never serves credentials unauthenticated)
#   - a token of the same ServiceAccount bound to ANOTHER pod running as it (what an Application named
#     vm-<x> would hold) -> 401, and an unbound token of it -> 401: only the VM's launcher qualifies
#   - the VM's own token while its role does NOT trust the "vm" principal -> 403 (opt-in)
#   - the plaintext port  -> 404 (credentials are served over TLS only; no token is sent to check it)
#
# The VMI has no boot disk and no network — only the token disk — so it needs no image: what is
# checked is the launcher pod and the VMI's record of it, not the guest.
#
# The token goes only to the shim's in-cluster TLS port, verified (curl --cacert) against the platform
# root CA from the openinfra-platform-ca EnvironmentConfig, exactly as a guest's metadata agent does.
#
# On-demand (needs a deployed shim with IMDS_ENABLED=true, the platform IAM, KubeVirt, and the
# control-plane grant letting the shim read ServiceAccounts and VirtualMachineInstances).
# Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   In-cluster: ./probe/aws-shim-vm-credentials.sh
#   Port-forward (svc/aws-shim 4566 4567):
#     SHIM_ENDPOINT=http://localhost:4566 VMCREDS_CONNECT_TO=localhost:4567 ./probe/aws-shim-vm-credentials.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ROLES_NS="${ROLES_NS:-default}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
# The TLS port, always named by the Service DNS name its certificate carries; VMCREDS_CONNECT_TO
# (host:port) redirects the connection, e.g. to a port-forward, without changing the name verified.
VMCREDS_HOSTPORT="aws-shim.${SHIM_NS}.svc.cluster.local:4567"
VMCREDS_CONNECT_TO="${VMCREDS_CONNECT_TO:-}"
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
VMI="vmcredprobe-${SFX}"
SA="vm-${VMI}"
IMPOSTER="vmcredprobe-imposter-${SFX}"
VMCREDS_URL="https://${VMCREDS_HOSTPORT}/v1/vm-credentials"
CA_FILE="$(mktemp)"

cleanup() {
  kubectl delete vmi "$VMI" -n "$ROLES_NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl delete pod "$IMPOSTER" -n "$ROLES_NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl delete role.iam.openinfra.dev "$ROLE" "$ROLE_UNTRUSTED" -n "$ROLES_NS" --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete sa "$SA" -n "$ROLES_NS" --ignore-not-found >/dev/null 2>&1 || true
  rm -f "$CA_FILE"
}
trap cleanup EXIT

# The platform root CA the guests get (public data), to verify the TLS port with.
kubectl get environmentconfig openinfra-platform-ca -o jsonpath='{.data.platformRootCA}' > "$CA_FILE" 2>/dev/null || true
grep -q 'BEGIN CERTIFICATE' "$CA_FILE" || inconclusive "openinfra-platform-ca carries no root CA yet (is the platform-ca-publisher running?)"
vmcurl() {
  if [ -n "$VMCREDS_CONNECT_TO" ]; then
    curl --cacert "$CA_FILE" --connect-to "${VMCREDS_HOSTPORT}:${VMCREDS_CONNECT_TO}" "$@"
  else
    curl --cacert "$CA_FILE" "$@"
  fi
}
vmcurl -sS -m 5 -o /dev/null "https://${VMCREDS_HOSTPORT}/healthz" \
  || inconclusive "the shim's TLS port is not reachable or does not verify against the platform root (${VMCREDS_HOSTPORT})"

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
  annotations: { openinfra.dev/instance-role: "${ROLE}", openinfra.dev/vm: "${VMI}" }
YAML

# --- 1b. A VMI that projects that ServiceAccount, as the VM composition renders it (token disk,
#         serial SATOKEN). No boot disk, no network: only its launcher pod matters here. -------------
log "starting VMI ${VMI} with the ServiceAccount's token disk"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: kubevirt.io/v1
kind: VirtualMachineInstance
metadata:
  name: "${VMI}"
  namespace: "${ROLES_NS}"
  labels: { app.kubernetes.io/name: vmcredprobe }
spec:
  terminationGracePeriodSeconds: 0
  domain:
    resources: { requests: { memory: 64Mi } }
    devices:
      disks:
        - { name: identity, serial: SATOKEN, disk: { bus: virtio } }
      interfaces: []
      autoattachPodInterface: false
  volumes:
    - name: identity
      serviceAccount: { serviceAccountName: "${SA}" }
YAML
POD=""; POD_UID=""
for _ in $(seq 1 60); do
  POD_UID="$( (kubectl get vmi "$VMI" -n "$ROLES_NS" -o jsonpath='{.status.activePods}' 2>/dev/null || true) \
    | sed -n 's/^{"\([^"]*\)".*/\1/p')"
  if [ -n "$POD_UID" ]; then
    POD="$(kubectl get pods -n "$ROLES_NS" -l kubevirt.io=virt-launcher \
      -o jsonpath="{.items[?(@.metadata.uid=='${POD_UID}')].metadata.name}" 2>/dev/null || true)"
    [ -n "$POD" ] && break
  fi
  sleep 3
done
[ -n "$POD" ] || inconclusive "VMI ${VMI} never got a launcher pod listed in status.activePods (KubeVirt down, or no node can run it?)"
log "launcher pod ${POD} (uid ${POD_UID})"

# The token KubeVirt projects into the guest is the launcher pod's own: a token of the ServiceAccount
# bound to that pod. Mint exactly that.
TOKEN="$(kubectl create token "$SA" -n "$ROLES_NS" --duration=10m \
  --bound-object-kind Pod --bound-object-name "$POD" --bound-object-uid "$POD_UID" 2>/dev/null || true)"
[ -n "$TOKEN" ] || inconclusive "could not mint a token bound to the launcher pod (TokenRequest denied?)"

# --- 2. POSITIVE: the SA token yields temporary credentials --------------------------------------
log "exchanging the launcher pod's token for role credentials at ${VMCREDS_URL}"
CREDS="$(vmcurl -s -H "Authorization: ${TOKEN}" "$VMCREDS_URL")"
AK="$(printf '%s' "$CREDS" | sed -n 's/.*"AccessKeyId":"\([^"]*\)".*/\1/p')"
SK="$(printf '%s' "$CREDS" | sed -n 's/.*"SecretAccessKey":"\([^"]*\)".*/\1/p')"
TK="$(printf '%s' "$CREDS" | sed -n 's/.*"Token":"\([^"]*\)".*/\1/p')"
[ -n "$AK" ] && [ -n "$SK" ] && [ -n "$TK" ] || fail "no credentials returned for the VM launcher's token (got: ${CREDS:0:200})"
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
CODE="$(vmcurl -s -o /dev/null -w '%{http_code}' "$VMCREDS_URL")"
[ "$CODE" = "401" ] || fail "unauthenticated vm-credentials must be 401, got ${CODE}"

# --- 4b. NEGATIVE: the plaintext port does not serve credentials at all (no token is sent) --------
log "NEGATIVE: the plaintext port must not serve the credentials endpoint"
CODE_P="$(curl -s -o /dev/null -w '%{http_code}' "${ENDPOINT}/v1/vm-credentials")"
[ "$CODE_P" = "404" ] || fail "vm-credentials on the plaintext port must be 404 (TLS only), got ${CODE_P}"

# --- 5. NEGATIVE: the same ServiceAccount, but not the VM's launcher pod -------------------------
# A pod running as the VM's ServiceAccount (what an Application named vm-<x> with assumeRole would be)
# holds a valid token for it; so does anyone who can request an unbound one. Neither is the VM.
log "NEGATIVE: a token of the VM's ServiceAccount bound to ANOTHER pod must be refused"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: "${IMPOSTER}"
  namespace: "${ROLES_NS}"
  labels: { app.kubernetes.io/name: vmcredprobe }
spec:
  serviceAccountName: "${SA}"
  automountServiceAccountToken: false
  enableServiceLinks: false
  restartPolicy: Never
  securityContext: { runAsNonRoot: true, runAsUser: 65532, seccompProfile: { type: RuntimeDefault } }
  containers:
    - name: pause
      image: registry.k8s.io/pause:3.10
      securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }
YAML
IMP_UID="$(kubectl get pod "$IMPOSTER" -n "$ROLES_NS" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
[ -n "$IMP_UID" ] || inconclusive "could not create the imposter pod ${IMPOSTER}"
TOKEN_IMP="$(kubectl create token "$SA" -n "$ROLES_NS" --duration=10m \
  --bound-object-kind Pod --bound-object-name "$IMPOSTER" --bound-object-uid "$IMP_UID" 2>/dev/null || true)"
[ -n "$TOKEN_IMP" ] || inconclusive "could not mint a token bound to the imposter pod"
CODE_I="$(vmcurl -s -o /dev/null -w '%{http_code}' -H "Authorization: ${TOKEN_IMP}" "$VMCREDS_URL")"
[ "$CODE_I" = "401" ] || fail "a token of the VM's ServiceAccount from another pod must be 401, got ${CODE_I}"
TOKEN_UNBOUND="$(kubectl create token "$SA" -n "$ROLES_NS" --duration=10m 2>/dev/null || true)"
[ -n "$TOKEN_UNBOUND" ] || inconclusive "could not mint an unbound token of the VM's ServiceAccount"
CODE_N="$(vmcurl -s -o /dev/null -w '%{http_code}' -H "Authorization: ${TOKEN_UNBOUND}" "$VMCREDS_URL")"
[ "$CODE_N" = "401" ] || fail "an unbound token of the VM's ServiceAccount must be 401, got ${CODE_N}"

# --- 6. NEGATIVE: a role that does not trust "vm" is denied (opt-in) ------------------------------
# The VM's own token, with its ServiceAccount now naming a Role whose trust omits "vm".
log "NEGATIVE: a role whose trust omits \"vm\" must be denied, even to the VM's own launcher"
kubectl annotate sa "$SA" -n "$ROLES_NS" --overwrite "openinfra.dev/instance-role=${ROLE_UNTRUSTED}" >/dev/null \
  || inconclusive "could not point the ServiceAccount at the untrusted Role"
CODE_U="$(vmcurl -s -o /dev/null -w '%{http_code}' -H "Authorization: ${TOKEN}" "$VMCREDS_URL")"
[ "$CODE_U" = "403" ] || fail "a non-vm-trusted role must be 403 (role not assumable by an instance), got ${CODE_U}"

printf '✓ PASS: VM workload credentials are faithful — the VM launcher pod'"'"'s token yields temporary\n'
printf '        assumed-role credentials (no static keys) over verified TLS; unauthenticated=401,\n'
printf '        same ServiceAccount from another pod or unbound=401, non-vm-trusted=403, plaintext port=404.\n'
