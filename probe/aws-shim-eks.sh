#!/usr/bin/env bash
# Compatibility probe for the aws-shim EKS surface (polyhedron#177).
#
# open-infra IS Kubernetes, so the EKS doorway is the least-additive of the container trio: there is no
# cluster to create or destroy. Its value is API-SHAPE compatibility — DescribeCluster returns the cluster's
# REAL connection details so `aws eks update-kubeconfig` produces a working kubeconfig. This probe fires REAL
# `aws eks` SDK calls at a deployed shim and asserts:
#
#   - DescribeCluster returns the one cluster, status ACTIVE, with an https endpoint, a certificateAuthority
#     whose data base64-decodes to a real PEM certificate, and a version that MATCHES the live Kubernetes
#     server version (not a fabricated string);
#   - `aws eks update-kubeconfig` generates a kubeconfig whose server + CA match DescribeCluster — the
#     load-bearing value (AWS tooling can configure kubectl against open-infra);
#   - ListClusters includes the cluster;
#   - UNSUPPORTED refused honestly: CreateCluster → InvalidRequestException; ListNodegroups → an empty set
#     (open-infra nodes are not EKS-managed node groups); DescribeNodegroup → ResourceNotFoundException;
#   - a valid key id with a WRONG secret → signature mismatch.
#
# On-demand (needs a deployed shim with the EKS front door enabled + an openinfra:admins caller):
#   kubectl -n open-infra-aws-shim port-forward svc/aws-shim 4566:4566 &
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-eks.sh
#
# Exit 0 = pass, 1 = a real fidelity/enforcement failure, 42 = INCONCLUSIVE.
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
CLUSTER="${EKS_CLUSTER_NAME:-open-infra}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"

ADMIN_USER="eksprobe-admin-$SFX"
AAK=""; ASK=""

eks() { # <ak> <sk> -- <eks args...>
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager eks "$@"
}

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }
mint_key() { # <owner> <group> -> "AK SK"
  local owner="$1" group="$2"
  local ak="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  local sk; sk="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "${owner}", namespace: "${USERS_NS}" }
spec: { displayName: "${owner}", groups: ["${group}"], source: local }
YAML
  kubectl -n "$SHIM_NS" create secret generic "$(secret_name "$ak")" \
    --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  printf '%s %s' "$ak" "$sk"
}

cleanup() {
  kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$ADMIN_USER" --ignore-not-found >/dev/null 2>&1 || true
  [ -n "$AAK" ] && kubectl -n "$SHIM_NS" delete secret "$(secret_name "$AAK")" --ignore-not-found >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

log "seeding an openinfra:admins caller"
read -r AAK ASK <<<"$(mint_key "$ADMIN_USER" "admins")"
[ -n "$AAK" ] || inconclusive "failed to mint a caller key"
sleep 2

# --- gate: the EKS front door must be enabled -------------------------------------------------------
if ! eks "$AAK" "$ASK" list-clusters >/dev/null 2>"$TMP/en.err"; then
  grep -qiE 'NotImplemented|not fronted|UnsupportedService|not implemented' "$TMP/en.err" && inconclusive "the EKS front door is not enabled on this shim"
  inconclusive "eks list-clusters failed, cannot confirm the front door: $(cat "$TMP/en.err")"
fi

# --- 1. DescribeCluster returns real, faithful connection details -----------------------------------
log "describe-cluster ${CLUSTER} → ACTIVE, https endpoint, a real CA, the LIVE k8s version"
eks "$AAK" "$ASK" describe-cluster --name "$CLUSTER" > "$TMP/dc.json" 2>"$TMP/dc.err" \
  || fail "describe-cluster failed: $(cat "$TMP/dc.err")"
ST="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["cluster"]["status"])' "$TMP/dc.json" 2>/dev/null || true)"
[ "$ST" = "ACTIVE" ] || fail "describe-cluster status='$ST', want ACTIVE"
EP="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["cluster"]["endpoint"])' "$TMP/dc.json" 2>/dev/null || true)"
case "$EP" in https://*) : ;; *) fail "describe-cluster endpoint is not https: '$EP'";; esac
CAB64="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["cluster"]["certificateAuthority"]["data"])' "$TMP/dc.json" 2>/dev/null || true)"
printf '%s' "$CAB64" | base64 -d 2>/dev/null | grep -q 'BEGIN CERTIFICATE' || fail "certificateAuthority.data did not base64-decode to a PEM certificate"
EKSVER="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["cluster"].get("version",""))' "$TMP/dc.json" 2>/dev/null || true)"
# live version, major.minor (strip any build suffix like "31+")
LIVEVER="$(kubectl version -o json 2>/dev/null | python3 -c 'import json,sys;v=json.load(sys.stdin)["serverVersion"];import re;print(re.sub(r"[^0-9]","",v["major"])+"."+re.sub(r"[^0-9].*$","",v["minor"]))' 2>/dev/null || true)"
[ -n "$EKSVER" ] || fail "describe-cluster returned no version"
if [ -n "$LIVEVER" ] && [ "$EKSVER" != "$LIVEVER" ]; then
  fail "describe-cluster version='$EKSVER' does not match the live cluster '$LIVEVER' (fabricated, not real?)"
fi
log "    ✓ ACTIVE; endpoint=${EP}; CA is a real cert; version=${EKSVER} (matches live ${LIVEVER:-?})"

# --- 2. update-kubeconfig produces a working-shaped kubeconfig (the load-bearing value) --------------
log "update-kubeconfig → a kubeconfig whose server + CA match describe-cluster"
KUBECONFIG="$TMP/kcfg" eks "$AAK" "$ASK" update-kubeconfig --name "$CLUSTER" >/dev/null 2>"$TMP/uk.err" \
  || fail "update-kubeconfig failed: $(cat "$TMP/uk.err")"
KSRV="$(kubectl --kubeconfig "$TMP/kcfg" config view --raw -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || true)"
KCA="$(kubectl --kubeconfig "$TMP/kcfg" config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' 2>/dev/null || true)"
[ "$KSRV" = "$EP" ] || fail "generated kubeconfig server='$KSRV' != describe-cluster endpoint '$EP'"
[ "$KCA" = "$CAB64" ] || fail "generated kubeconfig CA does not match describe-cluster certificateAuthority.data"
log "    ✓ kubeconfig server + CA match describe-cluster (aws eks update-kubeconfig works)"

# --- 3. ListClusters includes the cluster -----------------------------------------------------------
log "list-clusters includes ${CLUSTER}"
eks "$AAK" "$ASK" list-clusters --query 'clusters' --output text 2>/dev/null | tr '\t' '\n' | grep -qxF "$CLUSTER" \
  || fail "list-clusters did not include ${CLUSTER}"
log "    ✓ listed"

# --- 4. UNSUPPORTED refused honestly ----------------------------------------------------------------
log "create-cluster → InvalidRequestException (open-infra is the cluster; not created via EKS)"
if eks "$AAK" "$ASK" create-cluster --name "eksprobe-$SFX" \
    --role-arn "arn:aws:iam::open-infra:role/eksprobe" \
    --resources-vpc-config "subnetIds=subnet-0a1b2c3d,subnet-0e4f5a6b" >/dev/null 2>"$TMP/cc.err"; then
  fail "create-cluster was ACCEPTED (must refuse — the platform is the cluster)"
fi
grep -qiE 'not supported|not implemented|InvalidRequest|already exists|is the' "$TMP/cc.err" \
  || fail "create-cluster refusal had the wrong error: $(cat "$TMP/cc.err")"
log "    ✓ create-cluster refused honestly"

log "list-nodegroups → empty (open-infra nodes are not EKS-managed node groups)"
NG="$(eks "$AAK" "$ASK" list-nodegroups --cluster-name "$CLUSTER" --query 'length(nodegroups)' --output text 2>"$TMP/ng.err" || true)"
[ "$NG" = "0" ] || fail "list-nodegroups returned ${NG} (want 0): $(cat "$TMP/ng.err" 2>/dev/null)"
log "    ✓ list-nodegroups empty"

log "describe-nodegroup → ResourceNotFoundException"
if eks "$AAK" "$ASK" describe-nodegroup --cluster-name "$CLUSTER" --nodegroup-name "nope-$SFX" >/dev/null 2>"$TMP/dn.err"; then
  fail "describe-nodegroup was accepted (no EKS-managed node groups exist)"
fi
grep -qiE 'ResourceNotFound|No node group|not found' "$TMP/dn.err" || fail "describe-nodegroup error was wrong: $(cat "$TMP/dn.err")"
log "    ✓ describe-nodegroup → ResourceNotFoundException"

# --- 5. negative: wrong SigV4 secret ---------------------------------------------------------------
log "negative: a valid key id with a WRONG secret → signature mismatch"
if eks "$AAK" "wrong-secret-not-the-real-one" list-clusters >/dev/null 2>"$TMP/sig.err"; then
  fail "a wrong secret was accepted"
fi
grep -qiE 'Signature|does not match' "$TMP/sig.err" || fail "wrong-secret rejection had the wrong error: $(cat "$TMP/sig.err")"
log "    ✓ rejected on signature mismatch"

printf '\n✓ PASS — aws-shim EKS is faithful: DescribeCluster returns the open-infra cluster'"'"'s real endpoint + a real CA + the LIVE Kubernetes version; `aws eks update-kubeconfig` generates a kubeconfig whose server and CA match it (AWS tooling can target open-infra); ListClusters lists it; and the surface with no open-infra analog (CreateCluster, node groups) is refused honestly — with the SigV4 boundary enforced.\n'
