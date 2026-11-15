#!/usr/bin/env bash
# Live probe: the ECR registry decides each request as the ECR action AWS authorizes it as.
#
# ECR's documented push policy (https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-push-iam.html)
# allows ecr:BatchCheckLayerAvailability, the three layer-upload actions, ecr:PutImage and ecr:BatchGetImage
# on the repository, and not ecr:GetDownloadUrlForLayer. A role holding exactly that:
#   - pushes an image over the registry API, as `docker push` does: checks for each layer (HEAD), uploads
#     it (POST, PUT), writes the manifest (PUT);
#   - reads the manifest back (ecr:BatchGetImage);
#   - is refused downloading a layer, with ECR's DENIED naming ecr:GetDownloadUrlForLayer.
# A role with the same policy less ecr:PutImage uploads layers and is refused the manifest, DENIED naming
# ecr:PutImage. Before the fix the registry asked for its pull scope (both read actions) on every request,
# so the push-policy role was refused at its first layer check with insufficient_scope.
#
# Exit 0 pass, 1 fail, 42 inconclusive. Needs the aws CLI, kubectl (KUBECONFIG), curl and sha256sum;
# reaches the shim at SHIM_ENDPOINT (port-forward svc/aws-shim 4566) and the registry at REG_ENDPOINT
# (port-forward -n open-infra-ecr svc/ecr-registry 5000).
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REG="${REG_ENDPOINT:-http://ecr-registry.open-infra-ecr.svc.cluster.local:5000}"
REGION="${AWS_REGION:-us-east-1}"
ACCOUNT="${ACCOUNT_ID:-000000000000}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for c in aws kubectl curl sha256sum; do command -v "$c" >/dev/null || inconclusive "$c is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
curl -s -m 5 -o /dev/null "${REG}/v2/" || inconclusive "registry not reachable at ${REG}"

ADMIN="ecrpp-admin-$SFX"; REPO="ecrpp-probe-$SFX"
ROLE_PUSH="ecrpp-push-$SFX"; ROLE_NOPUT="ecrpp-noput-$SFX"
CREATED_KEYS=(); CREATED_USERS=(); ROLES=(); MADE_REPO=""
as() { local ak="$1" sk="$2" tok="$3"; shift 3
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_SESSION_TOKEN="$tok" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$@"; }
cleanup() {
  [ -n "$MADE_REPO" ] && as "$AAK" "$ASK" "" ecr delete-repository --repository-name "$REPO" --force >/dev/null 2>&1
  for r in "${ROLES[@]:-}"; do
    [ -n "$r" ] || continue
    as "$AAK" "$ASK" "" iam delete-role-policy --role-name "$r" --policy-name p >/dev/null 2>&1
    as "$AAK" "$ASK" "" iam delete-role --role-name "$r" >/dev/null 2>&1
  done
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1; done
  for k in "${CREATED_KEYS[@]:-}"; do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1; done
  rm -rf "$TMP"
}
trap cleanup EXIT

# mint_key <owner> <group>: a kind: User and an access key the shim authenticates; sets MK_AK MK_SK.
mint_key() {
  local owner="$1" group="$2" ak sk name
  ak="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  sk="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  cat <<YAML | kubectl apply -f - >/dev/null || inconclusive "could not create User $owner"
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "${owner}", namespace: "${USERS_NS}" }
spec: { displayName: "${owner}", groups: ["${group}"], source: local }
YAML
  CREATED_USERS+=("$owner")
  name="iam-ak-$(printf '%s' "$ak" | sha256sum | cut -c1-40)"
  kubectl -n "$SHIM_NS" create secret generic "$name" --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" \
    --from-literal=owner="$owner" >/dev/null || inconclusive "could not create the access key"
  CREATED_KEYS+=("$name")
  MK_AK="$ak"; MK_SK="$sk"
}

# --- 1. an administrator, a repository and two roles ---------------------------------------------------
log "seeding an administrator, repository $REPO and two roles"
mint_key "$ADMIN" "admins"; AAK="$MK_AK"; ASK="$MK_SK"
ok=""
for _ in $(seq 1 10); do
  as "$AAK" "$ASK" "" ecr create-repository --repository-name "$REPO" >/dev/null 2>"$TMP/repo" && { ok=1; break; }
  sleep 3   # the new key reaches the shim's key cache
done
[ -n "$ok" ] || inconclusive "create-repository failed: $(head -c 300 "$TMP/repo")"
MADE_REPO=1

REPO_ARN="arn:aws:ecr:${REGION}:${ACCOUNT}:repository/${REPO}"
TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::'"$ACCOUNT"':user/'"$ADMIN"'"},"Action":"sts:AssumeRole"}]}'
policy() { # <actions JSON list>: ECR's push-policy shape, on this repository
  printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":%s,"Resource":"%s"},{"Effect":"Allow","Action":"ecr:GetAuthorizationToken","Resource":"*"}]}' "$1" "$REPO_ARN"
}
PUSH='["ecr:CompleteLayerUpload","ecr:UploadLayerPart","ecr:InitiateLayerUpload","ecr:BatchCheckLayerAvailability","ecr:PutImage","ecr:BatchGetImage"]'
NOPUT='["ecr:CompleteLayerUpload","ecr:UploadLayerPart","ecr:InitiateLayerUpload","ecr:BatchCheckLayerAvailability","ecr:BatchGetImage"]'
mkrole() { # <name> <policy>
  as "$AAK" "$ASK" "" iam create-role --role-name "$1" --assume-role-policy-document "$TRUST" >/dev/null 2>"$TMP/cr" \
    || inconclusive "create-role $1 failed: $(head -c 300 "$TMP/cr")"
  ROLES+=("$1")
  as "$AAK" "$ASK" "" iam put-role-policy --role-name "$1" --policy-name p --policy-document "$2" >/dev/null || fail "put-role-policy $1 failed"
}
mkrole "$ROLE_PUSH" "$(policy "$PUSH")"
mkrole "$ROLE_NOPUT" "$(policy "$NOPUT")"
log "waiting 35s for the IAM policy world to load the roles' policies"
sleep 35

# registry_token <role>: as the role, GetAuthorizationToken, then the registry token for pull,push on the
# repository (as docker asks for it); sets RTOK. Credentials stay in this shell, never printed.
registry_token() {
  local s_ak s_sk s_tok cred
  read -r s_ak s_sk s_tok <<<"$(as "$AAK" "$ASK" "" sts assume-role --role-arn "arn:aws:iam::${ACCOUNT}:role/$1" \
    --role-session-name "ecrpp-$SFX" --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' 2>"$TMP/ar")"
  [ -n "${s_tok:-}" ] || inconclusive "assume-role $1 returned no credentials: $(head -c 300 "$TMP/ar")"
  cred="$(as "$s_ak" "$s_sk" "$s_tok" ecr get-authorization-token --query 'authorizationData[0].authorizationToken' 2>"$TMP/gat" | base64 -d)"
  case "$cred" in AWS:*) ;; *) fail "$1: GetAuthorizationToken gave no AWS:<token> credential: $(head -c 300 "$TMP/gat")" ;; esac
  RTOK="$(curl -s -u "$cred" "${ENDPOINT}/ecr/token?service=ecr-registry&scope=repository:${REPO}:pull,push" \
    | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
  [ -n "$RTOK" ] || fail "$1: the token endpoint returned no registry token"
}

# req <method> <path-or-url> [curl args…]: the HTTP status; the body in $TMP/body, headers in $TMP/hdr.
req() {
  local m="$1" u="$2"; shift 2
  case "$u" in http*) ;; *) u="${REG}${u}" ;; esac
  local mflag=(-X "$m"); [ "$m" = HEAD ] && mflag=(-I)   # -X HEAD would wait for a body
  curl -s -m 30 -o "$TMP/body" -D "$TMP/hdr" -w '%{http_code}' "${mflag[@]}" -H "Authorization: Bearer $RTOK" "$@" "$u"
}

# push_blob <file>: the layer check, then a monolithic upload, as docker does; sets DIGEST.
push_blob() {
  local f="$1" code loc
  DIGEST="sha256:$(sha256sum "$f" | cut -d' ' -f1)"
  code="$(req HEAD "/v2/${REPO}/blobs/${DIGEST}")"
  case "$code" in 404|200) ;; *) fail "the layer check (ecr:BatchCheckLayerAvailability) answered HTTP $code: $(head -c 300 "$TMP/body")" ;; esac
  code="$(req POST "/v2/${REPO}/blobs/uploads/")"
  [ "$code" = 202 ] || fail "starting an upload (ecr:InitiateLayerUpload) answered HTTP $code: $(head -c 300 "$TMP/body")"
  loc="$(sed -n 's/^[Ll]ocation: *\([^[:space:]]*\).*/\1/p' "$TMP/hdr" | tr -d '\r')"
  [ -n "$loc" ] || fail "the upload has no Location"
  case "$loc" in http*) ;; *) loc="${REG}${loc}" ;; esac
  case "$loc" in *\?*) loc="${loc}&digest=${DIGEST}" ;; *) loc="${loc}?digest=${DIGEST}" ;; esac
  code="$(req PUT "$loc" -H 'Content-Type: application/octet-stream' --data-binary "@$f")"
  [ "$code" = 201 ] || fail "completing the upload (ecr:UploadLayerPart, ecr:CompleteLayerUpload) answered HTTP $code: $(head -c 300 "$TMP/body")"
}

# manifest <layer digest> <layer size> <config digest> <config size>
manifest() {
  printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"%s","size":%s},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"%s","size":%s}]}' "$3" "$4" "$1" "$2"
}

# denied <action>: the last answer was ECR's 403 DENIED naming the action on the repository.
denied() {
  grep -q '"DENIED"' "$TMP/body" && grep -q "is not authorized to perform: $1 on resource: ${REPO_ARN}" "$TMP/body"
}

head -c 512 /dev/urandom >"$TMP/layer"
printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"config":{}}' >"$TMP/config"

# --- 2. ECR's push policy pushes, and cannot download a layer ------------------------------------------
log "$ROLE_PUSH (ECR's documented push policy) pushes an image"
registry_token "$ROLE_PUSH"
push_blob "$TMP/layer"; LDIG="$DIGEST"; LSZ="$(wc -c <"$TMP/layer" | tr -d ' ')"
push_blob "$TMP/config"; CDIG="$DIGEST"; CSZ="$(wc -c <"$TMP/config" | tr -d ' ')"
manifest "$LDIG" "$LSZ" "$CDIG" "$CSZ" >"$TMP/manifest"
code="$(req PUT "/v2/${REPO}/manifests/v1" -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' --data-binary "@$TMP/manifest")"
[ "$code" = 201 ] || fail "writing the manifest (ecr:PutImage) answered HTTP $code: $(head -c 300 "$TMP/body")"
log "  ✓ layers checked and uploaded, manifest written"

code="$(req GET "/v2/${REPO}/manifests/v1" -H 'Accept: application/vnd.oci.image.manifest.v1+json')"
[ "$code" = 200 ] || fail "reading the manifest back (ecr:BatchGetImage) answered HTTP $code: $(head -c 300 "$TMP/body")"
log "  ✓ manifest read back"

code="$(req GET "/v2/${REPO}/blobs/${LDIG}")"
case "$code" in
  403) denied "ecr:GetDownloadUrlForLayer" || fail "the refused download is not ECR's DENIED naming ecr:GetDownloadUrlForLayer: $(head -c 300 "$TMP/body")" ;;
  200) fail "WIDER THAN AWS: a role without ecr:GetDownloadUrlForLayer downloaded a layer" ;;
  *) fail "downloading a layer answered HTTP $code: $(head -c 300 "$TMP/body")" ;;
esac
log "  ✓ downloading a layer is refused: DENIED, ecr:GetDownloadUrlForLayer"

# --- 3. no ecr:PutImage: layers upload, the manifest is refused ----------------------------------------
log "$ROLE_NOPUT (the push policy less ecr:PutImage) uploads a layer and is refused the manifest"
registry_token "$ROLE_NOPUT"
head -c 256 /dev/urandom >"$TMP/layer2"
push_blob "$TMP/layer2"; L2="$DIGEST"; L2SZ="$(wc -c <"$TMP/layer2" | tr -d ' ')"
manifest "$L2" "$L2SZ" "$CDIG" "$CSZ" >"$TMP/manifest2"
code="$(req PUT "/v2/${REPO}/manifests/v2" -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' --data-binary "@$TMP/manifest2")"
case "$code" in
  403) denied "ecr:PutImage" || fail "the refused manifest is not ECR's DENIED naming ecr:PutImage: $(head -c 300 "$TMP/body")" ;;
  201) fail "WIDER THAN AWS: a role without ecr:PutImage wrote a manifest" ;;
  *) fail "writing the manifest answered HTTP $code: $(head -c 300 "$TMP/body")" ;;
esac
log "  ✓ the manifest is refused: DENIED, ecr:PutImage"

printf '\n✓ PASS: the registry decides each request as its ECR action: ECR'"'"'s push policy pushes and cannot download a layer, and a manifest write needs ecr:PutImage\n'
