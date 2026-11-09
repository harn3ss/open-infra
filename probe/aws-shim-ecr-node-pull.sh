#!/usr/bin/env bash
# Probe: every armed node pulls an image from the in-cluster registry with a credential its own identity
# obtained (#411), as a node's instance role gets its ECR credential on AWS.
#
# Through the real AWS CLI and the registry's /v2 API:
#   1. the management account's administrator creates a repository (CreateRepository) and pushes a tiny
#      image to it with the GetAuthorizationToken credential;
#   2. on EVERY schedulable node labelled openinfra.dev/ecr-pull=enabled, a pod pinned to that node with
#      imagePullPolicy Always pulls the image from the registry (the kubelet event "Pulled"), so the node's
#      runtime authenticated with the node pull credential its agent holds;
#   3. DENIAL: another ServiceAccount's token is refused the node pull credential (403) and a request with
#      no token is refused (401); the node pull credential itself is granted pull alone on the repository,
#      never push.
# Everything the probe made is removed on exit: the pods, its namespace, the repository and the
# administrator's key.
#
# Needs: aws (v2), kubectl (a cluster operator), curl, python3, sha256sum; the shim and the registry
# reachable (port-forwards are fine). Exit 0 = pass, 1 = fail, 42 = inconclusive.
#
#   kubectl -n open-infra-aws-shim port-forward svc/aws-shim 4566:4566 &
#   kubectl -n open-infra-ecr port-forward svc/ecr-registry 5000:5000 &
#   SHIM_ENDPOINT=http://localhost:4566 ECR_REGISTRY_ENDPOINT=http://localhost:5000 ./probe/aws-shim-ecr-node-pull.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGISTRY="${ECR_REGISTRY_ENDPOINT:-http://ecr-registry.open-infra-ecr.svc.cluster.local:5000}"
# The registry as the nodes name it (their runtime's registries.yaml mirror).
NODE_REGISTRY="${NODE_REGISTRY:-ecr-registry.open-infra-ecr.svc.cluster.local:5000}"
REGION="${AWS_REGION:-us-east-1}"
SETTLE="${IAM_SETTLE_SECONDS:-35}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
NS="ecrnp-$SFX"
REPO="ecrnp-$SFX/probe"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
ok()   { printf '▸   ✓ %s\n' "$*"; }
die()  { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for t in aws kubectl curl python3 sha256sum; do command -v "$t" >/dev/null || inconclusive "$t is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
curl -sS -m 5 -o /dev/null "${REGISTRY}/v2/" 2>/dev/null || inconclusive "registry not reachable at ${REGISTRY}"

OWNER="ecrnp-admin-$SFX"; AK=""; SK=""; KS=""
cleanup() {
  [ -n "$AK" ] && M ecr delete-repository --repository-name "$REPO" --force >/dev/null 2>&1
  kubectl delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1
  [ -n "$KS" ] && kubectl -n "$SHIM_NS" delete secret "$KS" --ignore-not-found >/dev/null 2>&1
  kubectl -n "$USERS_NS" delete users.iam.openinfra.dev "$OWNER" --ignore-not-found >/dev/null 2>&1
  rm -rf "$TMP"
  return 0
}
trap cleanup EXIT

# reg_bearer <b64 "AWS:pw"> <service> <repo> <actions>: the registry realm dance at the shim's /ecr/token.
reg_bearer() {
  curl -s -H "Authorization: Basic $1" "$ENDPOINT/ecr/token?service=$2&scope=repository:$3:$4" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))' 2>/dev/null
}

# oci_push <b64 "AWS:pw"> <repo> <tag>: push a tiny config-only image over /v2, as docker push does; echoes
# the manifest PUT's status (201 = created).
oci_push() {
  local b64="$1" repo="$2" tag="$3" cfg cd cs loc u man bearer svc chal
  cfg='{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}'
  cd="sha256:$(printf '%s' "$cfg" | sha256sum | cut -d' ' -f1)"
  cs=$(printf '%s' "$cfg" | wc -c)
  chal=$(curl -s -D - -o /dev/null "$REGISTRY/v2/" | tr -d '\r' | awk 'tolower($1)=="www-authenticate:"{print; exit}')
  svc=$(printf '%s' "$chal" | sed -n 's/.*service="\([^"]*\)".*/\1/p'); svc="${svc:-ecr-registry}"
  bearer=$(reg_bearer "$b64" "$svc" "$repo" "push,pull")
  [ -n "$bearer" ] || { echo "000"; return; }
  loc=$(curl -s -H "Authorization: Bearer $bearer" -X POST "$REGISTRY/v2/$repo/blobs/uploads/" -D - -o /dev/null | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
  [ -n "$loc" ] || { echo "000"; return; }
  case "$loc" in http*) u="$loc";; *) u="$REGISTRY$loc";; esac
  case "$u" in *\?*) u="$u&digest=$cd";; *) u="$u?digest=$cd";; esac
  curl -s -o /dev/null -H "Authorization: Bearer $bearer" -X PUT "$u" -H 'Content-Type: application/octet-stream' --data-binary "$cfg" || { echo "000"; return; }
  man='{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"'"$cd"'","size":'"$cs"'},"layers":[]}'
  curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $bearer" -X PUT "$REGISTRY/v2/$repo/manifests/$tag" \
    -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' --data-binary "$man"
}

# --- 1. a repository and an image in it ---------------------------------------------------------------
AK="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
SK="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
KS="iam-ak-$(printf '%s' "$AK" | sha256sum | cut -c1-40)"
printf 'apiVersion: iam.openinfra.dev/v1\nkind: User\nmetadata: { name: "%s", namespace: "%s" }\nspec: { displayName: "%s", groups: ["admins"], source: local }\n' \
  "$OWNER" "$USERS_NS" "$OWNER" | kubectl apply -f - >/dev/null || inconclusive "could not create the administrator"
kubectl -n "$SHIM_NS" create secret generic "$KS" --from-literal=accessKeyId="$AK" --from-literal=secretKey="$SK" \
  --from-literal=owner="$OWNER" >/dev/null || inconclusive "could not create the administrator's key"
M() { AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" "$@"; }
for _ in $(seq 1 20); do M sts get-caller-identity >/dev/null 2>&1 && break; sleep 3; done
sleep "$SETTLE"

log "1. a repository, and an image pushed to it"
M ecr create-repository --repository-name "$REPO" >/dev/null 2>"$TMP/err" || die "create-repository: $(tr '\n' ' ' < "$TMP/err")"
B64="$(M ecr get-authorization-token --query 'authorizationData[0].authorizationToken' --output text 2>"$TMP/err")" \
  || die "get-authorization-token: $(tr '\n' ' ' < "$TMP/err")"
code="$(oci_push "$B64" "$REPO" v1)"
[ "$code" = 201 ] || die "the push to $REPO:v1 answered $code"
ok "$REPO:v1 pushed"

# --- 2. every armed node pulls it ---------------------------------------------------------------------
log "2. every armed node pulls it with its own credential"
kubectl create ns "$NS" >/dev/null || inconclusive "could not create namespace $NS"
NODES="$(kubectl get nodes -l openinfra.dev/ecr-pull=enabled -o json | python3 -c '
import json,sys
for n in json.load(sys.stdin)["items"]:
    if n["spec"].get("unschedulable"): continue
    if not any(c["type"]=="Ready" and c["status"]=="True" for c in n["status"]["conditions"]): continue
    print(n["metadata"]["name"])')"
[ -n "$NODES" ] || inconclusive "no schedulable node is labelled openinfra.dev/ecr-pull=enabled"
i=0
for node in $NODES; do
  i=$((i+1))
  cat <<EOF | kubectl apply -f - >/dev/null || die "could not create the pull pod on $node"
apiVersion: v1
kind: Pod
metadata: { name: pull-$i, namespace: $NS, labels: { app: ecr-node-pull-probe } }
spec:
  nodeName: $node
  restartPolicy: Never
  automountServiceAccountToken: false
  tolerations: [ { operator: Exists } ]
  securityContext: { runAsNonRoot: true, runAsUser: 65532, seccompProfile: { type: RuntimeDefault } }
  containers:
    - name: image
      image: $NODE_REGISTRY/$REPO:v1
      imagePullPolicy: Always
      securityContext: { allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
      resources: { requests: { cpu: 1m, memory: 4Mi }, limits: { cpu: 10m, memory: 8Mi } }
EOF
done
for _ in $(seq 1 36); do
  kubectl -n "$NS" get events -o json >"$TMP/events.json" 2>/dev/null
  state="$(python3 - "$TMP/events.json" "$i" <<'PY'
import json, sys
ev = json.load(open(sys.argv[1]))["items"]
n = int(sys.argv[2])
pulled, refused = set(), {}
for e in ev:
    pod = e.get("involvedObject", {}).get("name", "")
    if e.get("reason") == "Pulled":
        pulled.add(pod)
    elif e.get("reason") == "Failed" and "pull" in e.get("message", "").lower():
        refused[pod] = e.get("message", "")[:300]
done = all(f"pull-{k}" in pulled for k in range(1, n + 1))
bad = {p: m for p, m in refused.items() if p not in pulled}
print("done" if done else ("refused " + json.dumps(bad) if bad and len(bad) + len(pulled) >= n else "waiting"))
PY
)"
  case "$state" in done|refused*) break ;; esac
  sleep 5
done
case "$state" in
  done) ;;
  refused*) die "a node's runtime was refused the image: ${state#refused }" ;;
  *) die "not every node pulled the image within 3 minutes" ;;
esac
ok "pulled on every armed node: $(echo $NODES | wc -w) nodes"

# --- 3. DENIAL ----------------------------------------------------------------------------------------
log "3. DENIAL: the node pull credential is the node agent's alone, and it pulls only"
kubectl -n "$NS" create serviceaccount not-an-agent >/dev/null || inconclusive "could not create a ServiceAccount"
OTHER="$(kubectl -n "$NS" create token not-an-agent --audience openinfra-ecr-node-pull --duration 10m 2>/dev/null)" \
  || inconclusive "could not mint a token for the other ServiceAccount"
code="$(curl -s -o "$TMP/other" -w '%{http_code}' -H "Authorization: Bearer $OTHER" "$ENDPOINT/ecr/node-credential")"
[ "$code" = 403 ] || die "another ServiceAccount was answered $code, not 403"
grep -q '"password"' "$TMP/other" && die "another ServiceAccount was given a credential"
code="$(curl -s -o /dev/null -w '%{http_code}' "$ENDPOINT/ecr/node-credential")"
[ "$code" = 401 ] || die "a request with no token was answered $code, not 401"
AGENT="$(kubectl -n kube-system create token ecr-node-pull-agent --audience openinfra-ecr-node-pull --duration 10m 2>/dev/null)" \
  || inconclusive "could not mint the node agent's token"
NODE_PW="$(curl -s -H "Authorization: Bearer $AGENT" "$ENDPOINT/ecr/node-credential" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("password",""))' 2>/dev/null)"
[ -n "$NODE_PW" ] || die "the node agent was not given the node pull credential"
NODE_B64="$(printf 'AWS:%s' "$NODE_PW" | base64 | tr -d '\n')"
GRANT="$(reg_bearer "$NODE_B64" ecr-registry "$REPO" "push,pull")"
[ -n "$GRANT" ] || die "the node pull credential got no registry token"
python3 - "$GRANT" "$REPO" <<'PY' || die "the node pull credential was granted more than pull"
import base64, json, sys
p = sys.argv[1].split(".")[1]
claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
acts = sorted(a for x in claims.get("access", []) if x.get("name") == sys.argv[2] for a in x.get("actions", []))
assert acts == ["pull"], acts
PY
ok "another ServiceAccount: 403; no token: 401; the node pull credential asked for push,pull is granted pull alone"

log "PASS — every armed node pulls from the in-cluster registry with the credential its own identity obtained, and that credential pulls only"
