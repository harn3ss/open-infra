#!/usr/bin/env bash
# A tenant gets no Kubernetes access: an IAM principal reaches the platform through its AWS APIs and the
# console, never the Kubernetes API.
#
# Two throwaway Users, each with one inline policy:
#   reader — eks:DescribeCluster + eks:ListClusters + s3:ListAllMyBuckets on "*";
#   other  — s3:ListAllMyBuckets only.
# Through the real AWS CLI, kubectl and the console:
#   - EKS decides by IAM policy: the reader describes the cluster; the other User is refused with
#     AccessDeniedException;
#   - the kubeconfig `aws eks update-kubeconfig` writes for the reader authenticates with `aws eks get-token`
#     (the reader's own IAM credentials), and the API server refuses it: no IAM credential is a Kubernetes
#     identity. The kubeconfig is pointed at this probe's own API server, so it runs from anywhere;
#   - the reader's console session reaches its resources through the console's resource API (its bucket
#     list, as its policy allows) and is refused, by the IAM gate naming an openinfra-operator action, every
#     raw Kubernetes object: Secrets, Pods, a pod's exec, Nodes, Namespaces, RoleBindings, ServiceAccount
#     tokens.
#
# Needs IAM policy to decide for the principals (IAM_AUTHZ=enforce, or shadow with PRINCIPAL_MODE=canary),
# and kubectl access to the cluster (to make the throwaway Users, and for the API server's address).
# Exit 0 = pass, 1 = fail, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-eks-tenant-refused.sh
set -uo pipefail
# shellcheck source=probe/iam-lib.sh
. "$(dirname "$0")/iam-lib.sh"
trap iamp_cleanup EXIT
iamp_require

READER="eks-tenant-reader-$SFX"
OTHER="eks-tenant-other-$SFX"
iamp_user "$READER" "" '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["eks:DescribeCluster","eks:ListClusters","s3:ListAllMyBuckets"],"Resource":"*"}]}'
R_AK="$U_AK"; R_SK="$U_SK"; JAR="$PROBE_TMP/jar"
iamp_login "$READER" "$U_PW" "$JAR"
iamp_user "$OTHER" "" '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}'
O_AK="$U_AK"; O_SK="$U_SK"
iamp_settle

as() { # <ak> <sk> <cmd…>: run a command with a principal's credentials
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_SESSION_TOKEN="" AWS_REGION="$REGION" "$@"
}

# --- EKS decides by IAM policy --------------------------------------------------------------------------
as "$R_AK" "$R_SK" aws --endpoint-url "$ENDPOINT" --no-cli-pager eks list-clusters --query 'clusters[0]' --output text \
  > "$PROBE_TMP/cluster" 2>"$PROBE_TMP/err" || fail "the reader could not list clusters: $(head -c 300 "$PROBE_TMP/err")"
CLUSTER="$(cat "$PROBE_TMP/cluster")"
[ -n "$CLUSTER" ] && [ "$CLUSTER" != None ] || fail "ListClusters named no cluster"
d="$(shim_decision "$O_AK" "$O_SK" eks describe-cluster --name "$CLUSTER")"; decided "$d"
[ "$d" = deny ] || fail "a User without eks:DescribeCluster described the cluster"
grep -q AccessDeniedException "$PROBE_TMP/s.err" || fail "DescribeCluster was refused, but not with AccessDeniedException: $(head -c 300 "$PROBE_TMP/s.err")"
log "  ✓ DescribeCluster without eks:DescribeCluster: AccessDeniedException"

# --- the kubeconfig EKS writes is no Kubernetes identity -----------------------------------------------
KC="$PROBE_TMP/kubeconfig"
as "$R_AK" "$R_SK" aws --endpoint-url "$ENDPOINT" --no-cli-pager eks update-kubeconfig --name "$CLUSTER" --kubeconfig "$KC" \
  >/dev/null 2>"$PROBE_TMP/err" || fail "update-kubeconfig for the reader: $(head -c 300 "$PROBE_TMP/err")"
ENTRY="$(kubectl --kubeconfig "$KC" config view -o jsonpath='{.clusters[0].name}')"
SRV="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
CA="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"
[ -n "$ENTRY" ] && [ -n "$SRV" ] || inconclusive "could not read the API server's address from this probe's kubeconfig"
kubectl --kubeconfig "$KC" config set-cluster "$ENTRY" --server "$SRV" >/dev/null
[ -n "$CA" ] && kubectl --kubeconfig "$KC" config set "clusters.$ENTRY.certificate-authority-data" "$CA" >/dev/null
for what in "get pods -A" "get secrets -n default" "get namespaces" "auth can-i --list"; do
  # shellcheck disable=SC2086
  if as "$R_AK" "$R_SK" kubectl --kubeconfig "$KC" --request-timeout=20s $what >"$PROBE_TMP/k.out" 2>&1; then
    fail "kubectl $what with the reader's IAM credentials reached the Kubernetes API: $(head -c 300 "$PROBE_TMP/k.out")"
  fi
  if grep -qiE 'Unable to connect|connection refused|no such host|i/o timeout|executable aws not found' "$PROBE_TMP/k.out"; then
    inconclusive "kubectl $what never reached the API server at $SRV: $(head -c 300 "$PROBE_TMP/k.out")"
  fi
  grep -qiE 'Unauthorized|forbidden|You must be logged in' "$PROBE_TMP/k.out" \
    || fail "kubectl $what failed, but not as the API server refusing the credential: $(head -c 300 "$PROBE_TMP/k.out")"
  log "  ✓ kubectl $what with an IAM principal's token: refused by the API server"
done

# --- the console's resource API: the principal's resources, never raw Kubernetes objects -----------------
K8S="/api/k8s"
d="$(console_decision "$JAR" GET "$K8S/apis/openinfra.dev/v1/namespaces/default/buckets" s3:ListAllMyBuckets)"; decided "$d"
[ "$d" = allow ] || fail "the reader's console session was refused its own bucket list"
log "  ✓ console: the bucket list its policy allows"
NOPE="eks-tenant-nope-$SFX"
while read -r method path action; do
  [ -n "$method" ] || continue
  d="$(CONSOLE_BODY='{}' console_decision "$JAR" "$method" "$path" "$action")"; decided "$d"
  [ "$d" = deny ] || fail "console $method $path ($action) was not denied to a tenant"
  log "  ✓ console $method $path: denied ($action)"
done <<EOF
GET $K8S/api/v1/namespaces/default/secrets openinfra-operator:ListSecrets
GET $K8S/api/v1/namespaces/default/secrets/$NOPE openinfra-operator:GetSecret
GET $K8S/api/v1/pods openinfra-operator:ListPods
POST $K8S/api/v1/namespaces/default/pods/$NOPE/exec openinfra-operator:CreatePodExec
GET $K8S/api/v1/nodes openinfra-operator:ListNodes
GET $K8S/api/v1/namespaces openinfra-operator:ListNamespaces
GET $K8S/apis/rbac.authorization.k8s.io/v1/namespaces/default/rolebindings openinfra-operator:ListRoleBindings
POST $K8S/api/v1/namespaces/default/serviceaccounts/default/token openinfra-operator:CreateServiceAccountToken
EOF
log "PASS: an IAM principal reaches its resources through AWS's APIs and the console, and no Kubernetes API"
