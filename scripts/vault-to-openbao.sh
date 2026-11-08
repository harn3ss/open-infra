#!/usr/bin/env bash
# Move the platform's keys from Vault (the encryption component) to OpenBao (security/openbao.yaml), by
# storage copy. docs/openbao.md, "Moving the keys from Vault", is the runbook; the work itself is
# scripts/vault-to-openbao/move.py, which runs in a temporary pod this script creates.
#
#   scripts/vault-to-openbao.sh prepare   create the openbao-move pod and its permissions, then check
#                                         (no credentials, nothing changed) that the move can run
#   scripts/vault-to-openbao.sh kes       after the clients use OpenBao: point KES's live config at it
#   scripts/vault-to-openbao.sh cleanup   delete the pod, its permissions and its config
#
# The move pod may: exec into vault-0 (to copy Vault's encrypted storage), read and delete OpenBao's member
# pods (to restart them after the restore), and nothing else in the cluster. It reads the unseal host's
# token for the cluster (secret openbao-seal) to open the copy, and nothing else that is secret.
set -euo pipefail
KUBECTL="${KUBECTL:-kubectl}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/vault-to-openbao"
NS=openbao
VAULT_IMG="hashicorp/vault:1.17.2"
BAO_IMG="quay.io/openbao/openbao:2.7.2@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f"
K8S_IMG="alpine/k8s:1.30.0@sha256:bd01dae02676ce4cab62fc744e43443eee5bf660054e94d3496d23bfc35d384e"
PY_IMG="python:3.12-alpine@sha256:e064671ca452259bab50e8e2c7bd896e39e9a343bb06ca25234adf6fe18d0fc7"

prepare() {
  $KUBECTL -n vault get pod vault-0 >/dev/null || { echo "no vault-0 in namespace vault: nothing to move" >&2; exit 1; }
  $KUBECTL -n "$NS" get secret openbao-seal -o name >/dev/null || { echo "no secret $NS/openbao-seal" >&2; exit 1; }
  $KUBECTL -n "$NS" delete pod openbao-move --ignore-not-found --wait=true >/dev/null   # a pod is replaced, not updated
  $KUBECTL -n "$NS" create configmap openbao-move --from-file=move.py="$DIR/move.py" \
    --from-file=migrate.hcl="$DIR/migrate.hcl" --from-file=temp-node.hcl="$DIR/temp-node.hcl" \
    --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null
  cat <<EOF | $KUBECTL apply -f - >/dev/null
apiVersion: v1
kind: ServiceAccount
metadata: { name: openbao-move, namespace: $NS }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: openbao-move, namespace: vault }
rules:
  - { apiGroups: [""], resources: [pods], resourceNames: [vault-0], verbs: [get] }
  - { apiGroups: [""], resources: [pods/exec], resourceNames: [vault-0], verbs: [create, get] }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: openbao-move, namespace: vault }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: openbao-move }
subjects: [{ kind: ServiceAccount, name: openbao-move, namespace: $NS }]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: openbao-move, namespace: $NS }
rules:
  - { apiGroups: [""], resources: [pods], verbs: [list] }
  - { apiGroups: [""], resources: [pods], resourceNames: [openbao-0, openbao-1, openbao-2], verbs: [get, delete] }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: openbao-move, namespace: $NS }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: openbao-move }
subjects: [{ kind: ServiceAccount, name: openbao-move, namespace: $NS }]
---
apiVersion: v1
kind: Pod
metadata:
  name: openbao-move
  namespace: $NS
  labels: { app: openbao-move, openinfra.dev/openbao-client: "true" }
spec:
  serviceAccountName: openbao-move
  restartPolicy: Never
  securityContext: { runAsNonRoot: true, runAsUser: 100, runAsGroup: 1000, fsGroup: 1000, seccompProfile: { type: RuntimeDefault } }
  initContainers:
    - name: tool-vault
      image: $VAULT_IMG
      command: [sh, -c, "cp \"\$(command -v vault)\" /tools/vault"]
      securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }
      volumeMounts: [{ name: tools, mountPath: /tools }]
    - name: tool-bao
      image: $BAO_IMG
      command: [sh, -c, "cp \"\$(command -v bao)\" /tools/bao"]
      securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }
      volumeMounts: [{ name: tools, mountPath: /tools }]
    - name: tool-kubectl
      image: $K8S_IMG
      command: [sh, -c, "cp \"\$(command -v kubectl)\" /tools/kubectl"]
      securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }
      volumeMounts: [{ name: tools, mountPath: /tools }]
  containers:
    - name: move
      image: $PY_IMG
      command: [sleep, "86400"]
      env:
        - { name: HOME, value: /work/home }
        - { name: PATH, value: "/tools:/usr/local/bin:/usr/bin:/bin" }
        - { name: GOMEMLIMIT, value: 900MiB }
        - name: MOVE_SEAL_TOKEN   # the unseal host's token for the cluster, to open the copy
          valueFrom: { secretKeyRef: { name: openbao-seal, key: token } }
      securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }
      resources: { requests: { cpu: 100m, memory: 256Mi }, limits: { cpu: "2", memory: 1536Mi } }
      volumeMounts:
        - { name: tools, mountPath: /tools }
        - { name: work, mountPath: /work }
        - { name: tmp, mountPath: /tmp }
        - { name: stash, mountPath: /run/move }
        - { name: cfg, mountPath: /cfg, readOnly: true }
        - { name: unseal-host, mountPath: /etc/unseal-host, readOnly: true }
        - { name: openbao-ca, mountPath: /etc/openbao-ca, readOnly: true }
  volumes:
    - { name: tools, emptyDir: {} }
    - { name: work, emptyDir: {} }
    - { name: tmp, emptyDir: {} }
    - { name: stash, emptyDir: { medium: Memory, sizeLimit: 16Mi } }   # the temporary token and new recovery keys, in memory only
    - { name: cfg, configMap: { name: openbao-move } }
    - { name: unseal-host, configMap: { name: openbao-unseal-host } }
    - { name: openbao-ca, configMap: { name: openbao-ca } }
EOF
  $KUBECTL -n "$NS" wait --for=condition=Ready pod/openbao-move --timeout=180s >/dev/null
  echo "openbao-move is ready; checking that the move can run (no credentials, nothing changed):"
  $KUBECTL -n "$NS" exec openbao-move -c move -- python3 /cfg/move.py preflight
}

kes() {
  # The KES keystore address lives in configmap/kes-config, which the certgen Job writes once: point it at
  # OpenBao (the template in security/minio-kes.yaml already does, for new installs) and restart KES.
  cfg="$($KUBECTL -n minio get configmap kes-config -o jsonpath='{.data.config\.yaml}')"
  new="$(printf '%s\n' "$cfg" | python3 -I -c '
import sys
s = sys.stdin.read()
old = "endpoint: \"http://vault.vault.svc.cluster.local:8200\""
if "openbao-active.openbao.svc" in s:
    print(s, end=""); sys.exit(0)
if old not in s:
    sys.exit("kes-config has no Vault endpoint to replace")
i = s.index(old); indent = s[s.rindex("\n", 0, i) + 1:i]
s = s.replace(old, "endpoint: \"https://openbao-active.openbao.svc:8200\"\n" + indent + "tls:\n" + indent + "  ca: /etc/openbao-ca/ca.crt", 1)
print(s, end="")')"
  printf '%s\n' "$new" > /tmp/kes-config.yaml
  $KUBECTL -n minio create configmap kes-config --from-file=config.yaml=/tmp/kes-config.yaml --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null
  rm -f /tmp/kes-config.yaml
  $KUBECTL -n minio rollout restart deployment kes >/dev/null && $KUBECTL -n minio rollout status deployment kes --timeout=180s
}

cleanup() {
  $KUBECTL -n "$NS" delete pod openbao-move --ignore-not-found --wait=true >/dev/null
  $KUBECTL -n "$NS" delete configmap openbao-move --ignore-not-found >/dev/null
  $KUBECTL -n "$NS" delete rolebinding,role openbao-move --ignore-not-found >/dev/null
  $KUBECTL -n vault delete rolebinding,role openbao-move --ignore-not-found >/dev/null
  $KUBECTL -n "$NS" delete serviceaccount openbao-move --ignore-not-found >/dev/null
  echo "the move pod, its permissions and its config are gone"
}

case "${1:-}" in
  prepare) prepare ;;
  kes) kes ;;
  cleanup) cleanup ;;
  *) echo "usage: $0 prepare|kes|cleanup" >&2; exit 2 ;;
esac
