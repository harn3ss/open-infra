#!/usr/bin/env bash
# Compatibility probe for the aws-shim ECR surface (polyhedron#177).
#
# ECR has two planes. The CONTROL plane is the `ecr.*` SDK/CLI API (GetAuthorizationToken, repositories,
# image listing/description/deletion) spoken to the shim over SigV4; the DATA plane is the standard OCI
# Distribution protocol (docker login/push/pull) spoken DIRECTLY to the backing registry at the
# proxyEndpoint — the shim never proxies image bytes. This probe fires REAL `aws ecr` SDK calls at a
# deployed shim and drives the data plane against the registry, asserting end to end:
#
#   - the token bridge: GetAuthorizationToken hands back a credential whose base64 decodes to "AWS:<pw>"
#     and a proxyEndpoint — the exact input `aws ecr get-login-password | docker login` consumes;
#   - the lifecycle: CreateRepository returns a faithful repositoryUri/Arn/registryId; an image PUSHED to
#     the registry with that credential (the same Basic-auth path docker uses, exercised here over /v2)
#     then appears in ListImages (tag + digest) and DescribeImages (a real, non-zero imageSizeInBytes);
#     DeleteRepository refuses a non-empty repo without force (RepositoryNotEmptyException) and succeeds
#     with force, removing the record;
#   - AUTHORITY: a READER caller's CreateRepository is refused at the control-plane gate (the coarse
#     impersonated SubjectAccessReview — a reader cannot create) and leaves NO repository record behind;
#   - UNSUPPORTED refused honestly: PutLifecyclePolicy is refused (InvalidParameterException naming the op),
#     never faked;
#   - a valid key id with a WRONG secret on a management call → signature mismatch.
#
# On-demand (needs a deployed shim with the ECR front door enabled + the MinIO-backed registry of
# platform/aws-shim/ecr-registry.yaml, plus openinfra:admins + openinfra:readers callers). Because the
# registry is in-cluster-only in v1, run from a workstation behind TWO port-forwards and point the envs at
# them:
#
#   kubectl -n open-infra-aws-shim port-forward svc/aws-shim 4566:4566 &
#   kubectl -n open-infra-ecr      port-forward svc/ecr-registry 5000:5000 &
#   SHIM_ENDPOINT=http://localhost:4566 ECR_REGISTRY_ENDPOINT=http://localhost:5000 ./probe/aws-shim-ecr.sh
#
# Exit 0 = pass, 1 = a real fidelity/enforcement failure, 42 = INCONCLUSIVE (a prerequisite was missing,
# so nothing was proven). Per polyhedron#157 a probe failure is presumed a shim defect.
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ECR_NS="${ECR_NAMESPACE:-open-infra-ecr}"            # where the ecr-repo-* bookkeeping records live
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGISTRY="${ECR_REGISTRY_ENDPOINT:-http://ecr-registry.${ECR_NS}.svc.cluster.local:5000}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws       >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl   >/dev/null || inconclusive "kubectl is required"
command -v curl      >/dev/null || inconclusive "curl is required (data-plane push over /v2)"
command -v sha256sum >/dev/null || inconclusive "sha256sum is required (data-plane push over /v2)"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"
curl -fsS -m 5 "${REGISTRY}/v2/" >/dev/null 2>&1 || true   # /v2/ is 401 without auth; reachability only:
curl -sS -m 5 -o /dev/null "${REGISTRY}/v2/" 2>/dev/null   || inconclusive "registry not reachable at ${REGISTRY} (set ECR_REGISTRY_ENDPOINT / port-forward)"

REPO="ecrprobe-$SFX/app"
READER_REPO="ecrprobe-reader-$SFX/app"
ADMIN_USER="ecrprobe-admin-$SFX"
READER_USER="ecrprobe-reader-$SFX"
AAK=""; ASK=""; RAK=""; RSK=""

ecr() { # <ak> <sk> -- <ecr args...>
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager ecr "$@"
}

# ecr_record_exists <repo-name>: true iff a bookkeeping record with that EXACT repositoryName exists.
ecr_record_exists() {
  kubectl -n "$ECR_NS" get configmap -l app.kubernetes.io/managed-by=ecr \
    -o jsonpath='{range .items[*]}{.data.repositoryName}{"\n"}{end}' 2>/dev/null | grep -qxF "$1"
}

# oci_push <registry> <cred "AWS:pw"> <repo> <tag>: push a tiny config-only image over /v2 (the same
# Basic-auth path `docker push` uses). Echoes the manifest PUT status code (201 = created).
oci_push() {
  local reg="$1" cred="$2" repo="$3" tag="$4" cfg cd cs loc u man
  cfg='{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}'
  cd="sha256:$(printf '%s' "$cfg" | sha256sum | cut -d' ' -f1)"
  cs=$(printf '%s' "$cfg" | wc -c)
  loc=$(curl -s -u "$cred" -X POST "$reg/v2/$repo/blobs/uploads/" -D - -o /dev/null | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
  [ -n "$loc" ] || { echo "000"; return; }
  case "$loc" in http*) u="$loc";; *) u="$reg$loc";; esac
  case "$u" in *\?*) u="$u&digest=$cd";; *) u="$u?digest=$cd";; esac
  curl -s -o /dev/null -u "$cred" -X PUT "$u" -H 'Content-Type: application/octet-stream' --data-binary "$cfg" || { echo "000"; return; }
  man='{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"'"$cd"'","size":'"$cs"'},"layers":[]}'
  curl -s -o /dev/null -w '%{http_code}' -u "$cred" -X PUT "$reg/v2/$repo/manifests/$tag" \
    -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' --data-binary "$man"
}

cleanup() {
  if [ -n "$AAK" ]; then
    ecr "$AAK" "$ASK" delete-repository --repository-name "$REPO" --force >/dev/null 2>&1 || true
    ecr "$AAK" "$ASK" delete-repository --repository-name "$READER_REPO" --force >/dev/null 2>&1 || true
  fi
  # belt-and-suspenders: drop any bookkeeping records this probe could have left behind
  for rn in "$REPO" "$READER_REPO"; do
    cm="$(kubectl -n "$ECR_NS" get configmap -l app.kubernetes.io/managed-by=ecr \
      -o jsonpath="{range .items[?(@.data.repositoryName=='$rn')]}{.metadata.name}{'\n'}{end}" 2>/dev/null || true)"
    [ -n "$cm" ] && kubectl -n "$ECR_NS" delete configmap $cm --ignore-not-found >/dev/null 2>&1 || true
  done
  # Users + key secrets are named deterministically / derived from the captured access keys — mint_key runs
  # in a command-substitution subshell, so an array it appended to would not survive to here.
  for u in "$ADMIN_USER" "$READER_USER"; do kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for ak in "$AAK" "$RAK"; do [ -n "$ak" ] && kubectl -n "$SHIM_NS" delete secret "$(secret_name "$ak")" --ignore-not-found >/dev/null 2>&1 || true; done
  rm -rf "$TMP"
}
trap cleanup EXIT

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
  local name; name="$(secret_name "$ak")"
  kubectl -n "$SHIM_NS" create secret generic "$name" \
    --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  printf '%s %s' "$ak" "$sk"
}

# --- seed callers -----------------------------------------------------------------------------------
log "seeding an openinfra:admins caller and an openinfra:readers caller"
read -r AAK ASK <<<"$(mint_key "$ADMIN_USER"  "admins")"
read -r RAK RSK <<<"$(mint_key "$READER_USER" "readers")"
[ -n "$AAK" ] && [ -n "$RAK" ] || inconclusive "failed to mint caller keys"
sleep 2

# --- gate: the ECR front door must be enabled -------------------------------------------------------
if ! ecr "$AAK" "$ASK" get-authorization-token >/dev/null 2>"$TMP/en.err"; then
  grep -qiE 'NotImplemented|not fronted|UnsupportedService' "$TMP/en.err" && inconclusive "the ECR front door is not enabled on this shim"
  inconclusive "ECR get-authorization-token failed, cannot confirm the front door: $(cat "$TMP/en.err")"
fi

# --- 1. token bridge --------------------------------------------------------------------------------
log "get-authorization-token → a base64 'AWS:<pw>' credential + a proxyEndpoint"
TOKEN="$(ecr "$AAK" "$ASK" get-authorization-token --query 'authorizationData[0].authorizationToken' --output text 2>"$TMP/tok.err")" \
  || fail "get-authorization-token failed: $(cat "$TMP/tok.err")"
PROXY="$(ecr "$AAK" "$ASK" get-authorization-token --query 'authorizationData[0].proxyEndpoint' --output text 2>/dev/null)"
CRED="$(printf '%s' "$TOKEN" | base64 -d 2>/dev/null || true)"
case "$CRED" in
  AWS:*) : ;;
  *) fail "authorization token did not decode to 'AWS:<pw>' (got a ${#CRED}-char value)";;
esac
[ -n "$PROXY" ] && [ "$PROXY" != "None" ] || fail "get-authorization-token returned no proxyEndpoint"
log "    ✓ credential decodes to AWS:…  proxyEndpoint=${PROXY}"

# --- 2. lifecycle: create → push → list → describe → delete -----------------------------------------
log "create-repository ${REPO}"
URI="$(ecr "$AAK" "$ASK" create-repository --repository-name "$REPO" \
  --query 'repository.repositoryUri' --output text 2>"$TMP/cr.err")" \
  || fail "create-repository failed: $(cat "$TMP/cr.err")"
case "$URI" in
  */"$REPO") : ;;
  *) fail "create-repository returned an unexpected repositoryUri: '$URI' (want …/${REPO})";;
esac
ecr_record_exists "$REPO" || fail "no bookkeeping record after create-repository ${REPO}"
log "    ✓ repositoryUri=${URI}"

log "push an image to ${REGISTRY}/${REPO}:v1 with the token credential (the /v2 Basic-auth path docker uses)"
CODE="$(oci_push "$REGISTRY" "$CRED" "$REPO" "v1")"
[ "$CODE" = "201" ] || fail "image push to the registry failed (manifest PUT HTTP $CODE; is ECR_REGISTRY_ENDPOINT the registry?)"
log "    ✓ pushed (manifest 201)"

log "list-images → the pushed tag v1 with a digest"
i=0; LTAG=""; LDIG=""
while [ "$i" -lt 30 ]; do
  LTAG="$(ecr "$AAK" "$ASK" list-images --repository-name "$REPO" --query 'imageIds[0].imageTag' --output text 2>/dev/null || true)"
  LDIG="$(ecr "$AAK" "$ASK" list-images --repository-name "$REPO" --query 'imageIds[0].imageDigest' --output text 2>/dev/null || true)"
  [ "$LTAG" = "v1" ] && [ -n "$LDIG" ] && [ "$LDIG" != "None" ] && break
  sleep 2; i=$((i+2))
done
[ "$LTAG" = "v1" ] || fail "list-images did not return the pushed tag (imageTag='$LTAG')"
case "$LDIG" in sha256:*) : ;; *) fail "list-images returned a non-digest imageDigest='$LDIG'";; esac
log "    ✓ list-images: v1 → ${LDIG}"

log "describe-images → a real, non-zero imageSizeInBytes (read from the registry, never fabricated)"
SZ="$(ecr "$AAK" "$ASK" describe-images --repository-name "$REPO" --query 'imageDetails[0].imageSizeInBytes' --output text 2>/dev/null || true)"
case "$SZ" in
  ''|None|0) fail "describe-images reported no/zero imageSizeInBytes ('$SZ')";;
  *[!0-9]*)  fail "describe-images imageSizeInBytes is not numeric ('$SZ')";;
esac
log "    ✓ describe-images imageSizeInBytes=${SZ}"

log "delete-repository (no force) on a NON-empty repo → RepositoryNotEmptyException"
if ecr "$AAK" "$ASK" delete-repository --repository-name "$REPO" >/dev/null 2>"$TMP/dne.err"; then
  fail "delete-repository without force deleted a non-empty repository (must refuse)"
fi
grep -qiE 'RepositoryNotEmpty|still contains images' "$TMP/dne.err" || fail "non-empty delete refusal had the wrong error: $(cat "$TMP/dne.err")"
log "    ✓ refused (RepositoryNotEmptyException)"

log "delete-repository --force → the record is removed"
ecr "$AAK" "$ASK" delete-repository --repository-name "$REPO" --force >/dev/null 2>"$TMP/del.err" \
  || fail "forced delete-repository failed: $(cat "$TMP/del.err")"
ecr_record_exists "$REPO" && fail "a bookkeeping record remains after a forced delete-repository"
log "    ✓ repository + images deleted, record gone"

# --- 3. AUTHORITY — a reader's create provisions nothing --------------------------------------------
log "authority: a READER caller's create-repository is refused at the control-plane gate, nothing created"
if ecr "$RAK" "$RSK" create-repository --repository-name "$READER_REPO" >/dev/null 2>"$TMP/auth.err"; then
  fail "a reader created a repository it lacks authority for (the create gate did not enforce)"
fi
grep -qiE 'AccessDenied|denied|forbidden' "$TMP/auth.err" || fail "reader create-repository refused with the wrong error: $(cat "$TMP/auth.err")"
ecr_record_exists "$READER_REPO" && fail "a repository record exists for the denied reader (nothing should be created)"
log "    ✓ reader refused — no repository record created"

# --- 4. UNSUPPORTED refused honestly ----------------------------------------------------------------
log "unsupported refused: put-lifecycle-policy → InvalidParameterException naming the op"
# A real, ≥100-char lifecycle policy so the aws CLI's client-side length validation passes and the
# request actually reaches the shim (which then refuses it) — the point is the SHIM's refusal, not the CLI's.
LIFECYCLE_POLICY='{"rules":[{"rulePriority":1,"description":"expire untagged images","selection":{"tagStatus":"untagged","countType":"imageCountMoreThan","countNumber":10},"action":{"type":"expire"}}]}'
if ecr "$AAK" "$ASK" put-lifecycle-policy --repository-name "$REPO" \
    --lifecycle-policy-text "$LIFECYCLE_POLICY" >/dev/null 2>"$TMP/life.err"; then
  fail "put-lifecycle-policy was ACCEPTED (lifecycle policies are not implemented; must refuse)"
fi
grep -qiE 'PutLifecyclePolicy|not implemented|InvalidParameter' "$TMP/life.err" \
  || fail "put-lifecycle-policy refusal had the wrong error: $(cat "$TMP/life.err")"
log "    ✓ put-lifecycle-policy refused honestly"

# --- 5. negative: wrong SigV4 secret ---------------------------------------------------------------
log "negative: a valid key id with a WRONG secret on a management call → signature mismatch"
if ecr "$AAK" "wrong-secret-not-the-real-one" describe-repositories >/dev/null 2>"$TMP/sig.err"; then
  fail "a wrong secret was accepted on a management call"
fi
grep -qiE 'Signature|does not match' "$TMP/sig.err" || fail "wrong-secret rejection had the wrong error: $(cat "$TMP/sig.err")"
log "    ✓ rejected on signature mismatch"

printf '\n✓ PASS — aws-shim ECR is faithful: GetAuthorizationToken bridges to a docker-login credential + proxyEndpoint; a repository created through the control plane takes a real image push (ListImages shows the tag+digest, DescribeImages a real size); DeleteRepository refuses a non-empty repo without force and succeeds with it; a reader is refused at the create gate (no record created); unsupported surface (lifecycle policies) is refused honestly; and the SigV4 boundary holds.\n'
