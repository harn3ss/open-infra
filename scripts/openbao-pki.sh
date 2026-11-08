#!/usr/bin/env bash
# The platform's CAs into OpenBao, once (#359; docs/openbao.md, "The platform's CAs"). Runs
# scripts/openbao-pki/pki.py in a temporary pod, with a root token from Secret openbao/openbao-bootstrap
# (scripts/openbao-root-access.sh mint).
#
#   scripts/openbao-pki.sh prepare       create the openbao-pki pod and its permissions
#   scripts/openbao-pki.sh run           the intermediates in OpenBao, the ACM CA imported, throwaway checks
#   scripts/openbao-pki.sh rotate NAME [ROOT_SECRET]   a new intermediate for platform or aws-endpoints
#   scripts/openbao-pki.sh status        what was done (public data only)
#   scripts/openbao-pki.sh cleanup       delete the pod and its permissions
#
# The pod may read the ClusterIssuers, the published roots and, of all Secrets, only the ACM CA's (the one
# key that moves); it may create CertificateRequests and a temporary Issuer in cert-manager (whose roots
# sign the intermediates there, so no root key is read), and write ConfigMap cert-manager/openinfra-roots.
set -euo pipefail
KUBECTL="${KUBECTL:-kubectl}"
NS=openbao
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/openbao-pki"
K8S_IMG="alpine/k8s:1.30.0@sha256:bd01dae02676ce4cab62fc744e43443eee5bf660054e94d3496d23bfc35d384e"
PY_IMG="python:3.12-alpine@sha256:e064671ca452259bab50e8e2c7bd896e39e9a343bb06ca25234adf6fe18d0fc7"

prepare() {
  $KUBECTL -n "$NS" get secret openbao-bootstrap >/dev/null 2>&1 \
    || { echo "no secret $NS/openbao-bootstrap: mint a root token first (scripts/openbao-root-access.sh mint)" >&2; exit 1; }
  acm="$($KUBECTL get clusterissuer openinfra-acm -o jsonpath='{.spec.ca.secretName}' 2>/dev/null || true)"
  $KUBECTL -n "$NS" delete pod openbao-pki --ignore-not-found --wait=true >/dev/null
  $KUBECTL -n "$NS" create configmap openbao-pki --from-file=pki.py="$DIR/pki.py" --dry-run=client -o yaml | $KUBECTL apply -f - >/dev/null
  cat <<EOF | $KUBECTL apply -f - >/dev/null
apiVersion: v1
kind: ServiceAccount
metadata: { name: openbao-pki, namespace: $NS }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: openinfra-openbao-pki }
rules:
  - { apiGroups: [cert-manager.io], resources: [clusterissuers], verbs: [get] }
  - { apiGroups: [apiextensions.crossplane.io], resources: [environmentconfigs], resourceNames: [openinfra-platform-ca], verbs: [get] }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: openinfra-openbao-pki }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: openinfra-openbao-pki }
subjects: [{ kind: ServiceAccount, name: openbao-pki, namespace: $NS }]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: openbao-pki, namespace: cert-manager }
rules:
  - { apiGroups: [cert-manager.io], resources: [issuers, certificaterequests], verbs: [create, get, patch, delete] }
  - { apiGroups: [cert-manager.io], resources: [certificates], verbs: [list, get] }
  - { apiGroups: [""], resources: [configmaps], verbs: [create] }
  - { apiGroups: [""], resources: [configmaps], resourceNames: [openinfra-roots], verbs: [get, patch] }
$( [ -n "$acm" ] && printf '  - { apiGroups: [""], resources: [secrets], resourceNames: [%s], verbs: [get] }' "$acm" )
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: openbao-pki, namespace: cert-manager }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: openbao-pki }
subjects: [{ kind: ServiceAccount, name: openbao-pki, namespace: $NS }]
---
apiVersion: v1
kind: Pod
metadata:
  name: openbao-pki
  namespace: $NS
  labels: { app: openbao-pki, openinfra.dev/openbao-client: "true" }
spec:
  serviceAccountName: openbao-pki
  restartPolicy: Never
  securityContext: { runAsNonRoot: true, runAsUser: 100, runAsGroup: 1000, seccompProfile: { type: RuntimeDefault } }
  initContainers:
    - name: tool-kubectl
      image: $K8S_IMG
      command: [sh, -c, "cp \"\$(command -v kubectl)\" /tools/kubectl"]
      securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }
      volumeMounts: [{ name: tools, mountPath: /tools }]
  containers:
    - name: pki
      image: $PY_IMG
      command: [sleep, "86400"]
      env:
        - { name: HOME, value: /tmp }
        - { name: PATH, value: "/tools:/usr/local/bin:/usr/bin:/bin" }
        - { name: BAO_ADDR, value: "https://openbao-active.openbao.svc:8200" }
        - { name: BAO_CACERT, value: /etc/openbao-ca/ca.crt }
        - name: BAO_TOKEN   # a root token, once (scripts/openbao-root-access.sh)
          valueFrom: { secretKeyRef: { name: openbao-bootstrap, key: token } }
      securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }
      resources: { requests: { cpu: 50m, memory: 64Mi }, limits: { cpu: "1", memory: 256Mi } }
      volumeMounts:
        - { name: tools, mountPath: /tools }
        - { name: tmp, mountPath: /tmp }
        - { name: status, mountPath: /run/pki }
        - { name: cfg, mountPath: /cfg, readOnly: true }
        - { name: openbao-ca, mountPath: /etc/openbao-ca, readOnly: true }
  volumes:
    - { name: tools, emptyDir: {} }
    - { name: tmp, emptyDir: {} }
    - { name: status, emptyDir: {} }
    - { name: cfg, configMap: { name: openbao-pki } }
    - { name: openbao-ca, configMap: { name: openbao-ca } }
EOF
  $KUBECTL -n "$NS" wait --for=condition=Ready pod/openbao-pki --timeout=180s >/dev/null && echo "openbao-pki is ready"
}

status() {
  $KUBECTL -n "$NS" exec openbao-pki -c pki -- cat /run/pki/status.json \
    | python3 -I -c 'import json,sys; [print(" ", s["msg"]) for s in json.load(sys.stdin)["steps"]]'
}

case "${1:-}" in
  prepare) prepare ;;
  run) $KUBECTL -n "$NS" exec openbao-pki -c pki -- python3 /cfg/pki.py setup ;;
  rotate) $KUBECTL -n "$NS" exec openbao-pki -c pki -- python3 /cfg/pki.py rotate "${2:?platform or aws-endpoints}" ${3:+"$3"} ;;
  status) status ;;
  cleanup)
    $KUBECTL -n "$NS" delete pod openbao-pki --ignore-not-found --wait=true >/dev/null
    $KUBECTL -n "$NS" delete configmap openbao-pki --ignore-not-found >/dev/null
    $KUBECTL -n "$NS" delete serviceaccount openbao-pki --ignore-not-found >/dev/null
    $KUBECTL -n cert-manager delete rolebinding,role openbao-pki --ignore-not-found >/dev/null
    $KUBECTL delete clusterrolebinding,clusterrole openinfra-openbao-pki --ignore-not-found >/dev/null
    echo "the openbao-pki pod and its permissions are gone" ;;
  *) echo "usage: $0 prepare|run|rotate NAME|status|cleanup" >&2; exit 2 ;;
esac
