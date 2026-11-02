#!/usr/bin/env bash
# End-to-end probe for the lift-and-shift goal: an UNMODIFIED CloudFormation template set deploys to
# open-infra through the aws-shim CloudFormation front door, from a LAN workstation, and behaves.
#
# It deploys cfn/testdata/lift-and-shift/template.yaml with `aws cloudformation deploy` (only an
# open-infra parameter file differs from AWS; the template carries no endpoint of any kind: the instance's
# aws CLIs and its container reach open-infra through the guest's own environment) and asserts, from this
# LAN host:
#   1. the stack reaches CREATE_COMPLETE and returns its Outputs (the instance's address, the site URL);
#   2. the EC2 instance boots unmodified and its own checks pass (served by the instance at
#      http://<Elastic IP>/results.json): #!/bin/bash UserData runs, the encrypted data disk mounts by its
#      Nitro name, IMDSv2 requires a token and serves the role's credentials, `aws s3 cp` works with the
#      distro CLI and aws-cli v2, a call outside the role's policy is denied, an image pulls from the
#      registry, and a container in the guest gets the role's credentials through the default chain;
#   3. the Elastic IP is a reachable LAN address; the CloudFront site serves its origin (SPA fallback +
#      the response-headers policy); the deploy flow's last step works — after the site upload,
#      `aws cloudfront create-invalidation` on the distribution in the Outputs and `aws cloudfront wait
#      invalidation-completed` — and on a re-deploy the next request after the wait serves the new content;
#      a pre-signed S3 link opens;
#   4. delete-stack removes everything (DELETE_COMPLETE; with KUBECONFIG set, no claim of the stack is
#      left in the cluster).
# Before deploying it runs `cfn plan` (when CFN_BIN is set) and prints the fidelity summary: every
# property the template relies on that open-infra accepts without emulating.
#
# Env (no site addresses are built in):
#   SHIM_ENDPOINT   (required) the aws-shim's LAN URL, e.g. https://s3.<your domain>. Exported as
#                   AWS_ENDPOINT_URL, so EVERY call this host makes (CloudFormation, S3, ECR) goes to the shim:
#                   --endpoint-url would redirect only the one service a command names, and e.g.
#                   `cloudformation deploy --s3-bucket` would then upload the template to AWS's own S3.
#   SITE_DOMAIN     (required) the static site's hostname (a CloudFront alias; must resolve to the ingress)
#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY  a deployer identity (admin), or MINT=1 with KUBECONFIG
#   AWS_CA_BUNDLE   (optional) the cluster root CA, so TLS is verified
#   APP_IMAGE       (optional) the image the instance pulls (default: the aws-cli image, copied into ECR)
#   CFN_BIN         (optional) path to the cfn CLI, for the fidelity summary
#   EVIDENCE_OUT    (optional) write {name, exit_code, reason, when} here
#   KEEP=1          (optional) leave the stack up for inspection
# Needs: aws (v2), curl, python3, and crane or docker to push the app image.
# Exit 0 = pass, 1 = a real failure, 42 = inconclusive.
#
#   SHIM_ENDPOINT=https://s3.example SITE_DOMAIN=site.example AWS_CA_BUNDLE=ca.crt ./probe/aws-shim-cfn-lift-and-shift.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
NAME=aws-shim-cfn-lift-and-shift
HERE="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="${TEMPLATE:-$HERE/../cfn/testdata/lift-and-shift/template.yaml}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
STACK="${STACK:-lsfix-$SFX}"
REPO="${REPO:-lsfix-app-$SFX}"
CFN_NS="${CFN_NS:-open-infra-cfn}"
CREDS_NS="${CREDS_NS:-openinfra-bucket-creds}"
APP_IMAGE="${APP_IMAGE:-docker.io/amazon/aws-cli:2.27.50}"
RESULTS_TIMEOUT="${RESULTS_TIMEOUT:-1800}"
TMP="$(mktemp -d)"
STATE=""; MINTED_USER=""; MINTED_KEY=""

evidence() { # <exit> <reason>
  [ -n "${EVIDENCE_OUT:-}" ] || return 0
  python3 - "$EVIDENCE_OUT" "$1" "$2" <<'PY'
import json, sys, datetime
out, code, reason = sys.argv[1], int(sys.argv[2]), sys.argv[3]
json.dump({"name": "aws-shim-cfn-lift-and-shift", "exit_code": code, "reason": reason,
           "when": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
          open(out, "w"), indent=2)
PY
}
log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; evidence 1 "$*"; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; evidence "$EXIT_INCONCLUSIVE" "$*"; exit "$EXIT_INCONCLUSIVE"; }

command -v aws >/dev/null || inconclusive "the aws CLI (v2) is required"
command -v curl >/dev/null || inconclusive "curl is required"
[ -n "${SHIM_ENDPOINT:-}" ] || inconclusive "set SHIM_ENDPOINT to the aws-shim's LAN URL"
[ -n "${SITE_DOMAIN:-}" ] || inconclusive "set SITE_DOMAIN to the static site's hostname"
[ -f "$TEMPLATE" ] || inconclusive "template not found: $TEMPLATE"
CURL_TLS=(); [ -n "${AWS_CA_BUNDLE:-}" ] && CURL_TLS=(--cacert "$AWS_CA_BUNDLE")

# --- optional: mint a throwaway admin deployer (cluster access) -------------------------------------
mint_key() { # <owner> <group>  -> sets MK_AK / MK_SK (called directly, never in $(...))
  local owner="$1" group="$2"
  MK_AK="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  MK_SK="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  printf 'apiVersion: iam.openinfra.dev/v1\nkind: User\nmetadata: { name: "%s", namespace: open-infra-console }\nspec: { displayName: "%s", groups: ["%s"], source: local }\n' \
    "$owner" "$owner" "$group" | kubectl apply -f - >/dev/null || return 1
  MINTED_USER="$owner"
  MINTED_KEY="iam-ak-$(printf '%s' "$MK_AK" | sha256sum | cut -c1-40)"
  kubectl -n open-infra-aws-shim create secret generic "$MINTED_KEY" --from-literal=accessKeyId="$MK_AK" \
    --from-literal=secretKey="$MK_SK" --from-literal=owner="$owner" >/dev/null
}
if [ "${MINT:-0}" = 1 ]; then
  command -v kubectl >/dev/null || inconclusive "MINT=1 needs kubectl"
  mint_key "lsfix-admin-$SFX" admins || inconclusive "could not mint a deployer key"
  export AWS_ACCESS_KEY_ID="$MK_AK" AWS_SECRET_ACCESS_KEY="$MK_SK"
  sleep 3
fi
[ -n "${AWS_ACCESS_KEY_ID:-}" ] || inconclusive "set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY (or MINT=1)"
export AWS_REGION="$REGION" AWS_ENDPOINT_URL="$SHIM_ENDPOINT"
A=(aws --region "$REGION" --no-cli-pager)

cleanup() {
  local appb="" siteb=""
  if [ "${KEEP:-0}" != 1 ] && [ -n "$STATE" ]; then
    appb="$("${A[@]}" cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='AppBucketName'].OutputValue" --output text 2>/dev/null)"
    siteb="$("${A[@]}" cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='SiteBucketName'].OutputValue" --output text 2>/dev/null)"
    for b in $appb $siteb; do
      [ -n "$b" ] && [ "$b" != None ] && "${A[@]}" s3 rm "s3://$b" --recursive >/dev/null 2>&1 || true
    done
    "${A[@]}" cloudformation delete-stack --stack-name "$STACK" >/dev/null 2>&1 || true
    "${A[@]}" ecr delete-repository --repository-name "$REPO" --force >/dev/null 2>&1 || true
  fi
  if [ -n "$MINTED_USER" ]; then
    kubectl -n open-infra-console delete user.iam.openinfra.dev "$MINTED_USER" --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n open-infra-aws-shim delete secret "$MINTED_KEY" --ignore-not-found >/dev/null 2>&1 || true
  fi
  if [ "${KEEP:-0}" != 1 ]; then
    # Teardown leftovers (#347/#348): the claim creds Secrets are now composed (GC'd with the stack);
    # sweep any that linger, the cert-manager TLS Secrets, and this stack's platform-side scoped-cred
    # Secrets + owner records. Then assert none remain. Matched by this stack's name / bucket names.
    local pat_cfn pat_creds
    pat_cfn="/(${STACK}[-a-z0-9]*-(minio|db-backup-creds)|staticsite-${STACK}[-a-z0-9]*-tls)$"
    pat_creds="/(app-open-infra-cfn-${STACK}|bkp-open-infra-cfn-${STACK}"
    { [ -n "$appb" ] && [ "$appb" != None ] && pat_creds="$pat_creds|bucket-owner-${appb}"; } || true
    { [ -n "$siteb" ] && [ "$siteb" != None ] && pat_creds="$pat_creds|bucket-owner-${siteb}"; } || true
    pat_creds="$pat_creds)"
    for s in $(kubectl -n "$CFN_NS" get secret -o name 2>/dev/null | grep -E "$pat_cfn"); do kubectl -n "$CFN_NS" delete "$s" --ignore-not-found >/dev/null 2>&1; done
    for s in $(kubectl -n "$CREDS_NS" get secret -o name 2>/dev/null | grep -E "$pat_creds"); do kubectl -n "$CREDS_NS" delete "$s" --ignore-not-found >/dev/null 2>&1; done
    local left
    left="$(kubectl -n "$CFN_NS" get secret -o name 2>/dev/null | grep -E "$pat_cfn"; kubectl -n "$CREDS_NS" get secret -o name 2>/dev/null | grep -E "$pat_creds"; true)"  # an absent Secret is the expected answer, not a set -e exit
    [ -z "$left" ] || log "WARNING: leftover Secrets remain after teardown: $(echo $left)"
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

# --- 0. the fidelity summary (what a pass here does NOT prove) ---------------------------------------
if [ -n "${CFN_BIN:-}" ] && [ -x "$CFN_BIN" ]; then
  log "cfn plan: verdict + fidelity summary"
  # -object-encryption: the fixture's buckets ask for BucketEncryption, which the target (the shim, with
  # the platform's object encryption on) vouches for; offline the CLI cannot check it.
  "$CFN_BIN" plan -stack-name "$STACK" -object-encryption -param SiteDomain="$SITE_DOMAIN" \
    -param AppRepositoryName="$REPO" "$TEMPLATE" > "$TMP/plan.txt" 2>&1
  grep -E "^Verdict" "$TMP/plan.txt"
  sed -n '/^Fidelity summary/,/^$/p' "$TMP/plan.txt" | cut -c1-200
  grep -q "^Verdict: PROVISIONABLE" "$TMP/plan.txt" || fail "cfn plan did not report the fixture provisionable: $(grep -A3 Blockers "$TMP/plan.txt" | head -4 | tr '\n' ' ')"
  FIDELITY_N="$(sed -n 's/^Fidelity summary .*(\([0-9]*\)):$/\1/p' "$TMP/plan.txt")"
fi

# --- 1. the app image, in an existing repository (as CI would have pushed it) -----------------------
log "creating ECR repository $REPO and pushing the app image"
"${A[@]}" ecr create-repository --repository-name "$REPO" >/dev/null || fail "ecr create-repository failed"
URI="$("${A[@]}" ecr describe-repositories --repository-names "$REPO" --query 'repositories[0].repositoryUri' --output text)"
REG="${URI%%/*}"
if command -v crane >/dev/null; then
  export DOCKER_CONFIG="$TMP/docker"; mkdir -p "$DOCKER_CONFIG"
  [ -n "${AWS_CA_BUNDLE:-}" ] && export SSL_CERT_FILE="$AWS_CA_BUNDLE"
  "${A[@]}" ecr get-login-password | crane auth login "$REG" -u AWS --password-stdin >/dev/null 2>&1 || fail "registry login to $REG failed"
  crane copy "$APP_IMAGE" "$URI:app" >/dev/null 2>&1 || fail "pushing $APP_IMAGE to $URI:app failed"
elif command -v docker >/dev/null; then
  "${A[@]}" ecr get-login-password | docker login -u AWS --password-stdin "$REG" >/dev/null || fail "docker login $REG failed"
  docker pull -q "$APP_IMAGE" >/dev/null && docker tag "$APP_IMAGE" "$URI:app" && docker push -q "$URI:app" >/dev/null || fail "docker push $URI:app failed"
else
  inconclusive "crane or docker is required to push the app image"
fi
log "  ✓ $URI:app"

# --- 2. deploy, unmodified ----------------------------------------------------------------------------
log "aws cloudformation deploy --stack-name $STACK (parameter overrides only)"
STATE=deploying
"${A[@]}" cloudformation deploy --template-file "$TEMPLATE" --stack-name "$STACK" --capabilities CAPABILITY_IAM \
  --parameter-overrides "SiteDomain=$SITE_DOMAIN" "AppRepositoryName=$REPO" \
  > "$TMP/deploy.txt" 2>&1 || fail "aws cloudformation deploy failed: $(tail -3 "$TMP/deploy.txt" | tr '\n' ' ')"
ST="$("${A[@]}" cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' --output text)"
[ "$ST" = CREATE_COMPLETE ] || fail "stack status $ST, want CREATE_COMPLETE"
out() { "${A[@]}" cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }
ADDR="$(out InstanceAddress)"; SITE_URL="$(out SiteUrl)"; APPB="$(out AppBucketName)"; SITEB="$(out SiteBucketName)"
DIST="$(out SiteDistributionId)"
log "  ✓ CREATE_COMPLETE; Outputs: InstanceAddress=$ADDR SiteUrl=$SITE_URL AppBucketName=$APPB SiteBucketName=$SITEB SiteDistributionId=$DIST"
[ -n "$ADDR" ] && [ "$ADDR" != None ] || fail "the stack returned no InstanceAddress output (the Elastic IP)"
[ -n "$APPB" ] && [ "$APPB" != None ] || fail "the stack returned no AppBucketName output"
[ -n "$DIST" ] && [ "$DIST" != None ] || fail "the stack returned no SiteDistributionId output"

# --- 3. the app's inputs: its config object, and the site's content ----------------------------------
echo "hello from $STACK" > "$TMP/hello.txt"
"${A[@]}" s3 cp "$TMP/hello.txt" "s3://$APPB/hello.txt" >/dev/null || fail "uploading the app's object to $APPB failed"
printf '<!doctype html><title>fixture</title><p id="m">LSFIX_SITE_%s</p>\n' "$SFX" > "$TMP/index.html"
"${A[@]}" s3 cp "$TMP/index.html" "s3://$SITEB/index.html" >/dev/null || fail "uploading the site to $SITEB failed"
log "  ✓ uploaded the app's object and the site's index.html"
# invalidate <distribution>: the standard deploy's last step — create-invalidation, then wait for it.
invalidate() {
  local id
  id="$("${A[@]}" cloudfront create-invalidation --distribution-id "$1" --paths '/*' --query Invalidation.Id --output text 2>"$TMP/inv.err")" \
    || fail "aws cloudfront create-invalidation --distribution-id $1 failed: $(tr '\n' ' ' < "$TMP/inv.err")"
  "${A[@]}" cloudfront wait invalidation-completed --distribution-id "$1" --id "$id" 2>"$TMP/inv.err" \
    || fail "aws cloudfront wait invalidation-completed did not see $id complete: $(tr '\n' ' ' < "$TMP/inv.err")"
  INV_ID="$id"
}
invalidate "$DIST"
log "  ✓ create-invalidation $INV_ID on $DIST, then wait invalidation-completed"

# --- 4. the instance's own checks, over the Elastic IP --------------------------------------------------
log "waiting for http://$ADDR/results.json (the instance's checks; up to ${RESULTS_TIMEOUT}s)"
deadline=$(( $(date +%s) + RESULTS_TIMEOUT )); R=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  R="$(curl -s -m 5 "http://$ADDR/results.json" 2>/dev/null)"
  printf '%s' "$R" | grep -q '"done": "yes"' && break
  sleep 15
done
printf '%s' "$R" | grep -q '"done": "yes"' || fail "the instance did not finish its checks over the Elastic IP $ADDR (last: $(printf '%s' "$R" | tr '\n' ' ' | head -c 400))"
printf '%s\n' "$R" | sed 's/^/    /'
FAILED="$(printf '%s' "$R" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(k for k,v in d.items() if v=="fail"))')"
# All 9 pass, s3_cp_distro_cli (the distro aws CLI v1) included: v1 predates AWS_ENDPOINT_URL, so the
# guest's endpoint plugin applies it (docs/virtual-machines.md#aws-endpoints-inside-the-guest).
[ -z "$FAILED" ] || fail "instance checks failed: $FAILED"
log "  ✓ every instance check passed (served over the Elastic IP $ADDR)"

# --- 5. the static site (CloudFront subset) and a pre-signed link --------------------------------------
log "the static site at $SITE_URL"
SITE_OK=""
for i in $(seq 1 12); do
  B="$(curl -s -k -m 8 "$SITE_URL/" 2>/dev/null)"
  printf '%s' "$B" | grep -q "LSFIX_SITE_$SFX" && { SITE_OK=1; break; }
  sleep 10
done
[ -n "$SITE_OK" ] || fail "$SITE_URL/ did not serve the uploaded index.html"
H="$(curl -s -k -m 8 -D - -o "$TMP/deep.html" "$SITE_URL/some/client/route" | tr -d '\r')"
printf '%s' "$H" | head -1 | grep -q " 200" && grep -q "LSFIX_SITE_$SFX" "$TMP/deep.html" || fail "SPA fallback: a deep route did not serve index.html with 200"
printf '%s' "$H" | grep -qi '^x-fixture: lift-and-shift' || fail "the response-headers policy's X-Fixture header is missing"
log "  ✓ site serves its origin, SPA fallback + response headers (TLS from the cluster issuer; see the fidelity summary)"
# A re-deploy of the site: new content, the invalidation, the wait — and the very next request serves it.
printf '<!doctype html><title>fixture</title><p id="m">LSFIX_REDEPLOY_%s</p>\n' "$SFX" > "$TMP/index.html"
"${A[@]}" s3 cp "$TMP/index.html" "s3://$SITEB/index.html" >/dev/null || fail "re-uploading the site to $SITEB failed"
invalidate "$DIST"
B="$(curl -s -k -m 8 "$SITE_URL/" 2>/dev/null)"
printf '%s' "$B" | grep -q "LSFIX_REDEPLOY_$SFX" || fail "invalidation $INV_ID completed, but $SITE_URL/ still served the earlier content"
log "  ✓ re-deploy: upload, create-invalidation $INV_ID, wait → the next request serves the new content"
U="$("${A[@]}" s3 presign "s3://$APPB/hello.txt" --expires-in 600)"
PS_BODY="$(curl -s "${CURL_TLS[@]}" -m 10 -o - -w '\n%{http_code} connect=%{time_connect}s tls=%{time_appconnect}s first-byte=%{time_starttransfer}s' "$U"; echo " curl-exit=$?")"
if [ "$(printf '%s' "$PS_BODY" | head -n -1)" != "hello from $STACK" ]; then
  # Say what happened (status, where it stalled), and whether an immediate retry opens it.
  RETRY="$(curl -s "${CURL_TLS[@]}" -m 10 -o /dev/null -w '%{http_code} first-byte=%{time_starttransfer}s' "$U"; echo " curl-exit=$?")"
  fail "the pre-signed link did not open (first try: $(printf '%s' "$PS_BODY" | tail -n 1); retry: $RETRY): ${U%%\?*}"
fi
log "  ✓ a pre-signed S3 link opens"

# --- 6. teardown: AWS's bucket rules, and nothing left behind ------------------------------------------
# empty_bucket <bucket>: remove every object version and delete marker (what DeleteBucket requires).
empty_bucket() {
  local b="$1" v
  "${A[@]}" s3 rm "s3://$b" --recursive >/dev/null 2>&1 || true
  "${A[@]}" s3api list-object-versions --bucket "$b" --query '[Versions,DeleteMarkers][][].[Key,VersionId]' --output text 2>/dev/null \
    | while read -r k v; do
        [ -n "$k" ] && [ "$k" != None ] && "${A[@]}" s3api delete-object --bucket "$b" --key "$k" --version-id "$v" >/dev/null 2>&1
      done
  return 0
}
stack_state() { "${A[@]}" cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].[StackStatus,StackStatusReason]' --output text 2>&1; }
if [ "${KEEP:-0}" = 1 ]; then
  log "KEEP=1: leaving stack $STACK up"; STATE=""
else
  # AWS refuses to delete a stack while one of its buckets still holds data: DELETE_FAILED, BucketNotEmpty,
  # the bucket and its data kept. $APPB still holds the app's object.
  log "delete-stack $STACK while $APPB still holds data (AWS: DELETE_FAILED with BucketNotEmpty)"
  "${A[@]}" cloudformation delete-stack --stack-name "$STACK" || fail "delete-stack failed"
  "${A[@]}" cloudformation wait stack-delete-complete --stack-name "$STACK" 2>/dev/null \
    && fail "the stack was deleted although bucket $APPB still held data (AWS refuses: BucketNotEmpty)"
  st="$(stack_state)"
  printf '%s' "$st" | grep -q DELETE_FAILED && printf '%s' "$st" | grep -q BucketNotEmpty \
    || fail "a delete with a non-empty bucket ended as '$st', want DELETE_FAILED naming BucketNotEmpty"
  "${A[@]}" s3api head-bucket --bucket "$APPB" >/dev/null 2>&1 || fail "the non-empty bucket $APPB was removed by the refused delete"
  log "  ✓ refused as AWS refuses it: DELETE_FAILED (BucketNotEmpty); $APPB and its data kept"

  log "empty both buckets, delete-stack $STACK again"
  empty_bucket "$APPB"; empty_bucket "$SITEB"
  "${A[@]}" cloudformation delete-stack --stack-name "$STACK" || fail "delete-stack (retry) failed"
  "${A[@]}" cloudformation wait stack-delete-complete --stack-name "$STACK" 2>/dev/null \
    || { st="$(stack_state)"; printf '%s' "$st" | grep -q -E "does not exist|DELETE_COMPLETE" || fail "stack did not delete cleanly: $st"; }
  STATE=""
  # Nothing is swept here before checking: what the delete itself left is what is asserted.
  for b in "$APPB" "$SITEB"; do
    if "${A[@]}" s3api head-bucket --bucket "$b" >/dev/null 2>&1; then fail "bucket $b still exists after the stack was deleted"; fi
  done
  log "  ✓ stack deleted; its buckets are gone (HeadBucket → 404 through the S3 API)"
  if command -v kubectl >/dev/null && [ -n "${KUBECONFIG:-}" ]; then
    left="$(kubectl get virtualmachines.openinfra.dev,buckets.openinfra.dev,staticsites.openinfra.dev,roles.iam.openinfra.dev,policies.iam.openinfra.dev,securitygroups.openinfra.dev,volumes.openinfra.dev -A -l "cfn.openinfra.dev/stack=$STACK" --no-headers 2>/dev/null | wc -l)"
    [ "$left" -eq 0 ] || fail "teardown left $left claim(s) of $STACK in the cluster"
    # The claim Secrets are composed (deleted with their claims); the scoped MinIO users' credentials and
    # owner records are removed by the bucket reaper within a minute or two of the claims going.
    pat_cfn="/(${STACK}[-a-z0-9]*-(minio|db-backup-creds)|staticsite-${STACK}[-a-z0-9]*-tls)$"
    pat_creds="/(app-open-infra-cfn-${STACK}|bucket-owner-${APPB}$|bucket-owner-${SITEB}$)"
    leftover=""
    for _ in $(seq 1 24); do
      leftover="$(kubectl -n "$CFN_NS" get secret -o name 2>/dev/null | grep -E "$pat_cfn"; kubectl -n "$CREDS_NS" get secret -o name 2>/dev/null | grep -E "$pat_creds")"
      [ -z "$leftover" ] && break
      sleep 5
    done
    [ -z "$leftover" ] || fail "teardown left Secrets behind: $(echo $leftover)"
    log "  ✓ no claim, credentials Secret, owner record or TLS Secret of $STACK left in the cluster"
  else
    log "  (set KUBECONFIG to also check the cluster for leftover claims and Secrets)"
  fi
  "${A[@]}" ecr delete-repository --repository-name "$REPO" --force >/dev/null 2>&1 || true
fi

MSG="unmodified lift-and-shift template deployed through the CloudFormation front door from a LAN client: CREATE_COMPLETE with Outputs; instance checks all passed over the Elastic IP (bash UserData, encrypted Nitro data disk, IMDSv2 token + role creds, s3 cp distro+v2, out-of-policy call denied, ECR pull, container default-chain creds); CloudFront site served with SPA fallback + headers; create-invalidation + wait invalidation-completed after each upload, the re-deployed content served on completion; pre-signed link opened; teardown clean${FIDELITY_N:+; fidelity summary lists $FIDELITY_N not-emulated properties}"
printf '\n✓ PASS — %s\n' "$MSG"
evidence 0 "$MSG"
exit 0
