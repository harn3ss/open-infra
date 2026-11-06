#!/usr/bin/env bash
# Compatibility probe for the cfn engine's CloudFront subset, end to end through the aws-shim
# CloudFormation front door.
#
# It deploys an UNMODIFIED CloudFront-over-private-S3 template — a bucket, an OAC, the bucket policy
# granting CloudFront read, an in-stack ACM certificate, a response headers policy, and a distribution
# with SPA 403/404 fallback on an Alias — with the real AWS CLI, then asserts over real round-trips:
#   - NEGATIVE: the same template with a Lambda@Edge association is REFUSED WHOLE at validation (a
#     synchronous ValidationError naming Lambda@Edge), with no stack record and nothing created;
#   - NEGATIVE, when the operator validated domains (certificates.validatedDomains): an Alias outside them
#     is refused (ACM would never validate its certificate), and the probe's Alias is under one, so the
#     site's certificate must verify against the platform root alone (no -k), as ACM's are trusted;
#   - create-stack reaches CREATE_COMPLETE, and the distribution became a kind: StaticSite over the
#     template's bucket (spa: true, the Alias, the response headers) while the bucket stayed a kind: Bucket
#     whose CloudFront-only policy was realized by the site rather than stored;
#   - content uploaded to the bucket through the shim's S3 front door (what a CI `aws s3` step does) is
#     served through Traefik over HTTPS on the Alias: / and a deep SPA route → index.html (200), a real
#     asset as itself, and every response carries the policy's headers (X-Probe-Header, X-Frame-Options,
#     X-Content-Type-Options);
#   - a re-deploy, as the standard flow ends it: a new index.html is uploaded, then `aws cloudfront
#     create-invalidation` on the distribution id the stack reports and `aws cloudfront wait
#     invalidation-completed` — and the very next request serves the new content; list-invalidations shows
#     it Completed, an unknown distribution is NoSuchDistribution, and a reader may not invalidate;
#   - delete-stack removes the StaticSite and the Bucket.
#
# Everything it creates is removed on exit (EXIT trap): both stacks + their records, any claims left by
# label, the site/bucket secrets and TLS secret, the minio-namespace setup Jobs, the client namespace,
# the minted caller + access key, and — through a short-lived pod in the minio namespace that uses the
# platform's MinIO root secret — the bucket and the scoped MinIO users/policies the setups minted.
#
# On-demand (needs a deployed shim with the CloudFormation front door + impersonation RBAC, the cfn engine,
# Crossplane + the Bucket/StaticSite compositions, MinIO, cert-manager's openinfra-issuer, k3s Traefik, and
# an openinfra:admins caller). Exit 0 = pass, 1 = a real failure, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-cfn-cloudfront.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
CFN_NS="${CFN_NS:-open-infra-cfn}"
CREDS_NS="${CREDS_NS:-openinfra-bucket-creds}"
MINIO_NS="${MINIO_NS:-minio}"
TRAEFIK_NS="${TRAEFIK_NS:-kube-system}"
TRAEFIK_SVC="${TRAEFIK_SVC:-traefik}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.10.1}"
# The same pinned mc image the StaticSite/Bucket compositions use.
MC_IMAGE="${MC_IMAGE:-ghcr.io/harn3ss/open-infra-mc@sha256:a689825d5299d02e6f35973e726a6e49a77469cde644dd52d60586b07bd85744}"

SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"
STACK="cfprobe-cdn-$SFX"
BAD_STACK="cfprobe-cdn-bad-$SFX"
BUCKET="cfprobe-$SFX"
# The Alias: under a domain the environment validated (certificates.validatedDomains — ACM's domain
# validation, done once by the operator), so its certificate comes from the platform's ACM-style CA and
# must verify against the platform root; with none validated, a reserved .invalid name (self-signed).
VALIDATED="$(kubectl -n "${SHIM_NS:-open-infra-aws-shim}" get configmap openinfra-certificates -o jsonpath='{.data.validatedDomains}' 2>/dev/null | head -1 | tr -d '[:space:]' || true)"
if [ -n "$VALIDATED" ]; then HOST="cfprobe-$SFX.$VALIDATED"; else HOST="cfprobe-$SFX.probe.invalid"; fi # .invalid: reserved
MARKER="CF_PROBE_OK_$SFX"
# Logical ids carry the suffix so the claims (k8sName(logical id)) are unique in the shared CFN namespace.
L_BUCKET="Site$SFX"; L_OAC="Oac$SFX"; L_POLICY="Pol$SFX"; L_CERT="Cert$SFX"; L_HDR="Hdr$SFX"; L_CDN="Cdn$SFX"
# The engine names a resource <stack>-<logical id>, lowercased (cfn/naming.go); past 40 characters it
# keeps the first 31 and appends an 8-hex hash of "<stack>\0<logical id>".
phys_name() { # <stack> <logicalId>
  local s l n
  s="$(printf '%s' "$1" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9-' '-' | tr -s '-')"; s="${s#-}"; s="${s%-}"
  l="$(printf '%s' "$2" | tr 'A-Z' 'a-z')"
  n="$s-$l"; [ "$l" = "$s" ] && n="$s"
  if [ "${#n}" -le 40 ]; then printf '%s' "$n"; return; fi
  n="${n:0:31}"; n="${n%-}"
  printf '%s-%s' "$n" "$(printf '%s\0%s' "$1" "$2" | sha256sum | cut -c1-8)"
}
SITE="$(phys_name "$STACK" "$L_CDN")"      # the StaticSite claim
BCLAIM="$(phys_name "$STACK" "$L_BUCKET")" # the Bucket claim
CLIENT_NS="cfprobe-client-$SFX"
CLIENT="client-$SFX"
CREATED_USERS=(); CREATED_KEYS=()
AAK=""; ASK=""

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }
snip() { printf '%s' "$1" | head -c 600 | tr '\n' ' '; }

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
kubectl get ns "$CFN_NS" >/dev/null 2>&1 || inconclusive "CFN namespace ${CFN_NS} missing (apply the aws-shim overlay)"
kubectl get crd staticsites.openinfra.dev >/dev/null 2>&1 || inconclusive "the StaticSite CRD is not installed"
kubectl -n "$MINIO_NS" get secret minio >/dev/null 2>&1 || inconclusive "secret/minio in ns $MINIO_NS not readable (needed to clean up the probe's bucket + MinIO users)"

cfn() { AWS_ACCESS_KEY_ID="$AAK" AWS_SECRET_ACCESS_KEY="$ASK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager cloudformation "$@"; }
s3api() { AWS_ACCESS_KEY_ID="$AAK" AWS_SECRET_ACCESS_KEY="$ASK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager s3api "$@"; }
cf() { AWS_ACCESS_KEY_ID="$AAK" AWS_SECRET_ACCESS_KEY="$ASK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager cloudfront "$@"; }

# wait_pod <ns> <pod> <seconds>: 0 when the pod Succeeded, 1 when it Failed or timed out.
wait_pod() {
  local i=0 phase=""
  while [ "$i" -lt "$3" ]; do
    phase="$(kubectl -n "$1" get pod "$2" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    case "$phase" in Succeeded) return 0;; Failed) return 1;; esac
    sleep 3; i=$((i+3))
  done
  return 1
}

# minio_cleanup removes the bucket and the scoped MinIO users/policies the Bucket/StaticSite setups mint, via a
# one-shot pod in the minio namespace (root creds come from secret/minio and never leave that namespace).
# The MinIO user a bucket-owning claim gets (bucket-composition / staticsite-composition $appUser).
app_user() { # <Kind> <namespace> <name>
  local base; base="$(printf '%s-%s' "$2" "$3" | tr . - | cut -c1-40)"; base="${base%-}"
  printf 'app-%s-%s' "$base" "$(printf '%s/%s/%s' "$1" "$2" "$3" | sha256sum | cut -c1-10)"
}
minio_cleanup() { # <bucket> <minio-user>...
  local bucket="$1"; shift
  local pod="cfprobe-clean-$SFX"
  cat <<YAML | kubectl apply -f - >/dev/null 2>&1 || { printf '  (cleanup) could not start the MinIO cleanup pod\n' >&2; return 0; }
apiVersion: v1
kind: Pod
metadata: { name: "$pod", namespace: "$MINIO_NS", labels: { app.kubernetes.io/managed-by: cfn-cloudfront-probe } }
spec:
  restartPolicy: Never
  enableServiceLinks: false
  containers:
    - name: mc
      image: "$MC_IMAGE"
      env:
        - { name: RU, valueFrom: { secretKeyRef: { name: minio, key: rootUser } } }
        - { name: RP, valueFrom: { secretKeyRef: { name: minio, key: rootPassword } } }
      command: [sh, -c]
      args:
        - |
          export MC_CONFIG_DIR=/tmp/.mc   # the image runs as non-root with no writable HOME
          mc alias set m http://minio.$MINIO_NS.svc.cluster.local:9000 "\$RU" "\$RP" >/dev/null || exit 1
          mc rb --force "m/$bucket" >/dev/null 2>&1 && echo "removed bucket $bucket" || echo "bucket $bucket already gone"
          for u in $*; do
            mc admin user rm m "\$u" >/dev/null 2>&1 && echo "removed MinIO user \$u" || echo "MinIO user \$u already gone"
            mc admin policy rm m "\$u" >/dev/null 2>&1 || true
          done
YAML
  wait_pod "$MINIO_NS" "$pod" 120 || printf '  (cleanup) the MinIO cleanup pod did not succeed — remove bucket %s / users %s by hand\n' "$bucket" "$*" >&2
  kubectl -n "$MINIO_NS" logs "$pod" 2>/dev/null | sed 's/^/  (cleanup) /' || true
  kubectl -n "$MINIO_NS" delete pod "$pod" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}

cleanup() {
  set +e
  log "cleanup: stacks, claims, secrets, setup Jobs, MinIO bucket + users, client ns, minted caller"
  if [ -n "$AAK" ]; then
    cfn delete-stack --stack-name "$STACK" >/dev/null 2>&1
    cfn delete-stack --stack-name "$BAD_STACK" >/dev/null 2>&1
    sleep 3
  fi
  for k in staticsites.openinfra.dev buckets.openinfra.dev; do
    kubectl -n "$CFN_NS" delete "$k" -l "cfn.openinfra.dev/stack=$STACK" --ignore-not-found --wait=true --timeout=120s >/dev/null 2>&1
    kubectl -n "$CFN_NS" delete "$k" -l "cfn.openinfra.dev/stack=$BAD_STACK" --ignore-not-found --wait=false >/dev/null 2>&1
  done
  local su bu; su="$(app_user StaticSite "$CFN_NS" "$SITE")"; bu="$(app_user Bucket "$CFN_NS" "$BCLAIM")"
  # The claim creds Secrets are now composed (GC'd with the claim); delete any that linger, plus the
  # cert-manager TLS Secret (not owned by the claim until enableCertificateOwnerRef — #348).
  kubectl -n "$CFN_NS" delete secret "$SITE-minio" "$BCLAIM-minio" "staticsite-$SITE-tls" --ignore-not-found >/dev/null 2>&1
  kubectl -n "$SHIM_NS" delete secret "cfn-stack-$STACK" "cfn-stack-$BAD_STACK" "cfn-invalidations-$STACK" --ignore-not-found >/dev/null 2>&1  # the doorway's records
  kubectl -n "$CFN_NS" delete configmap "cfn-stack-$STACK" "cfn-stack-$BAD_STACK" --ignore-not-found >/dev/null 2>&1  # (an earlier doorway's)
  kubectl -n "$MINIO_NS" delete job "$SITE-site-setup" --ignore-not-found >/dev/null 2>&1
  for j in $(kubectl -n "$MINIO_NS" get jobs -o name 2>/dev/null | grep "/$BCLAIM-bucket-"); do
    kubectl -n "$MINIO_NS" delete "$j" --ignore-not-found >/dev/null 2>&1
  done
  minio_cleanup "$BUCKET" "app-$SITE" "app-$BCLAIM" "$su" "$bu"
  # Owner records and platform-side scoped-credential Secrets now live in the creds namespace.
  kubectl -n "$CREDS_NS" delete secret "bucket-owner-$BUCKET" "$su" "$bu" --ignore-not-found >/dev/null 2>&1
  kubectl delete ns "$CLIENT_NS" --ignore-not-found --wait=false >/dev/null 2>&1
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1; done
  for k in "${CREATED_KEYS[@]:-}";  do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1; done
  # Assert the teardown left nothing behind for this stack.
  local left
  left="$(kubectl -n "$CFN_NS" get secret "$SITE-minio" "$BCLAIM-minio" "staticsite-$SITE-tls" -o name 2>/dev/null; kubectl -n "$CREDS_NS" get secret "bucket-owner-$BUCKET" "$su" "$bu" -o name 2>/dev/null; true)"  # an absent Secret is the expected answer, not a set -e exit
  [ -z "$left" ] || printf '  (cleanup) WARNING: leftover Secrets remain after teardown: %s\n' "$(echo $left)" >&2
  rm -rf "$TMP"
}
trap cleanup EXIT

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }
mint_key() { # <owner> <group> -> sets MK_AK / MK_SK
  local owner="$1" group="$2"
  local ak="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  local sk; sk="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "${owner}", namespace: "${USERS_NS}" }
spec: { displayName: "${owner}", groups: ["${group}"], source: local }
YAML
  CREATED_USERS+=("$owner")
  local name; name="$(secret_name "$ak")"
  kubectl -n "$SHIM_NS" create secret generic "$name" --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  CREATED_KEYS+=("$name")
  MK_AK="$ak"; MK_SK="$sk"  # returned via globals: mint_key must run in THIS shell so CREATED_* reach cleanup
}

poll_stack() { # <stack> <want> <timeout> -> prints last status; 0 if reached
  local stack="$1" want="$2" t="${3:-300}" i=0 st=""
  while [ "$i" -lt "$t" ]; do
    st="$(cfn describe-stacks --stack-name "$stack" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
    if [ "$st" = "$want" ]; then printf '%s' "$st"; return 0; fi
    case "$st" in *_COMPLETE|*_FAILED) printf '%s' "$st"; return 1;; esac
    sleep 5; i=$((i+5))
  done
  printf '%s' "$st"; return 1
}

# template <extra DefaultCacheBehavior JSON members> — the CloudFront static-site template, unmodified
# AWS shape. The negative case adds a Lambda@Edge association.
template() {
  local extra="${1:-}"
  cat <<JSON
{"AWSTemplateFormatVersion":"2010-09-09","Resources":{
  "$L_BUCKET":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"$BUCKET",
    "PublicAccessBlockConfiguration":{"BlockPublicAcls":true,"BlockPublicPolicy":true,"IgnorePublicAcls":true,"RestrictPublicBuckets":true}}},
  "$L_OAC":{"Type":"AWS::CloudFront::OriginAccessControl","Properties":{"OriginAccessControlConfig":{
    "Name":"cfprobe-$SFX","OriginAccessControlOriginType":"s3","SigningBehavior":"always","SigningProtocol":"sigv4"}}},
  "$L_POLICY":{"Type":"AWS::S3::BucketPolicy","Properties":{"Bucket":{"Ref":"$L_BUCKET"},"PolicyDocument":{
    "Version":"2012-10-17","Statement":[{"Sid":"AllowCloudFrontRead","Effect":"Allow",
      "Principal":{"Service":"cloudfront.amazonaws.com"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::$BUCKET/*",
      "Condition":{"StringEquals":{"AWS:SourceArn":{"Fn::Sub":"arn:aws:cloudfront::\${AWS::AccountId}:distribution/\${$L_CDN}"}}}}]}}},
  "$L_CERT":{"Type":"AWS::CertificateManager::Certificate","Properties":{"DomainName":"$HOST","ValidationMethod":"DNS"}},
  "$L_HDR":{"Type":"AWS::CloudFront::ResponseHeadersPolicy","Properties":{"ResponseHeadersPolicyConfig":{
    "Name":"cfprobe-$SFX",
    "SecurityHeadersConfig":{"FrameOptions":{"FrameOption":"DENY","Override":true},"ContentTypeOptions":{"Override":true}},
    "CustomHeadersConfig":{"Items":[{"Header":"X-Probe-Header","Value":"$MARKER","Override":true}]}}}},
  "$L_CDN":{"Type":"AWS::CloudFront::Distribution","Properties":{"DistributionConfig":{
    "Enabled":true,"Aliases":["$HOST"],"DefaultRootObject":"index.html","PriceClass":"PriceClass_100",
    "Origins":[{"Id":"s3-site","DomainName":{"Fn::GetAtt":["$L_BUCKET","RegionalDomainName"]},
      "S3OriginConfig":{"OriginAccessIdentity":""},"OriginAccessControlId":{"Fn::GetAtt":["$L_OAC","Id"]}}],
    "DefaultCacheBehavior":{"TargetOriginId":"s3-site","ViewerProtocolPolicy":"redirect-to-https","Compress":true,
      "CachePolicyId":"658327ea-f89d-4fab-a63d-7e88639e58f6","ResponseHeadersPolicyId":{"Ref":"$L_HDR"}$extra},
    "CustomErrorResponses":[{"ErrorCode":403,"ResponseCode":200,"ResponsePagePath":"/index.html"},
                            {"ErrorCode":404,"ResponseCode":200,"ResponsePagePath":"/index.html"}],
    "ViewerCertificate":{"AcmCertificateArn":{"Ref":"$L_CERT"},"SslSupportMethod":"sni-only","MinimumProtocolVersion":"TLSv1.2_2021"}}}}
}}
JSON
}

# --- seed the caller ----------------------------------------------------------------------------------
log "seeding an openinfra:admins caller"
mint_key "cfprobe-cdn-admin-$SFX" "admins"; AAK="$MK_AK"; ASK="$MK_SK"
[ -n "$AAK" ] || inconclusive "failed to mint the caller key"
# A new principal's policies take effect after the IAM compiler's next pass and the authorizers' policy
# caches (as AWS IAM changes propagate): the stack acts as its caller, so wait that out first.
log "  waiting ${IAM_SETTLE_SECONDS:-45}s for the new caller's policies to propagate"
sleep "${IAM_SETTLE_SECONDS:-45}"

# --- 1. NEGATIVE: an out-of-subset feature refuses the whole stack at validation -----------------------
log "negative: the same template with a Lambda@Edge association is refused at validation, nothing created"
template ',"LambdaFunctionAssociations":[{"EventType":"origin-request","LambdaFunctionARN":"arn:aws:lambda:us-east-1:111122223333:function:rewrite:1"}]' > "$TMP/bad.json"
if cfn create-stack --stack-name "$BAD_STACK" --template-body "file://$TMP/bad.json" >/dev/null 2>"$TMP/bad.err"; then
  fail "create-stack with Lambda@Edge was ACCEPTED (the CloudFront subset must refuse it at validation)"
fi
grep -q 'Lambda@Edge' "$TMP/bad.err" || fail "the refusal does not name Lambda@Edge: $(cat "$TMP/bad.err")"
cfn describe-stacks --stack-name "$BAD_STACK" >/dev/null 2>&1 && fail "a stack record was created for a refused template"
kubectl -n "$CFN_NS" get staticsites.openinfra.dev "$SITE" >/dev/null 2>&1 && fail "a StaticSite was created despite the whole-stack refusal"
log "    ✓ refused whole at validation (names Lambda@Edge), nothing created"
if [ -n "$VALIDATED" ]; then
  # ACM validates only a domain you own: an Alias outside every validated domain can never get a
  # certificate, so the distribution is refused (on AWS its certificate would stay PENDING_VALIDATION).
  log "negative: an Alias outside the validated domains ($VALIDATED) is refused at validation"
  (HOST="cfprobe-$SFX.probe.invalid"; template) > "$TMP/unvalidated.json"
  if cfn create-stack --stack-name "$BAD_STACK" --template-body "file://$TMP/unvalidated.json" >/dev/null 2>"$TMP/unv.err"; then
    fail "create-stack with an Alias outside the validated domains was ACCEPTED"
  fi
  grep -q 'PENDING_VALIDATION' "$TMP/unv.err" || fail "the refusal does not say the certificate could not be validated: $(cat "$TMP/unv.err")"
  cfn describe-stacks --stack-name "$BAD_STACK" >/dev/null 2>&1 && fail "a stack record was created for the refused template"
  log "    ✓ refused (its certificate could never be validated), nothing created"
fi

# --- 2. create-stack → CREATE_COMPLETE, the distribution became a StaticSite ----------------------------
log "create-stack $STACK: bucket + OAC + policy + ACM cert + headers policy + distribution"
template > "$TMP/site.json"
cfn create-stack --stack-name "$STACK" --template-body "file://$TMP/site.json" >/dev/null 2>"$TMP/cs.err" \
  || fail "create-stack refused the CloudFront subset template: $(cat "$TMP/cs.err")"
ST="$(poll_stack "$STACK" CREATE_COMPLETE 600)" || {
  REASON="$(cfn describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatusReason' --output text 2>/dev/null || true)"
  fail "stack did not reach CREATE_COMPLETE (status=$ST): $REASON"
}
log "    ✓ CREATE_COMPLETE"

sget() { kubectl -n "$CFN_NS" get staticsites.openinfra.dev "$SITE" -o jsonpath="$1" 2>/dev/null || true; }
[ "$(sget '{.metadata.labels.cfn\.openinfra\.dev/stack}')" = "$STACK" ] || fail "StaticSite $SITE (from $L_CDN) not found with the stack label in $CFN_NS"
[ "$(sget '{.spec.spa}')" = "true" ]            || fail "StaticSite spec.spa = '$(sget '{.spec.spa}')', want true (the 403/404 -> /index.html mapping)"
[ "$(sget '{.spec.bucket}')" = "$BUCKET" ]      || fail "StaticSite spec.bucket = '$(sget '{.spec.bucket}')', want $BUCKET"
[ "$(sget '{.spec.domain}')" = "$HOST" ]        || fail "StaticSite spec.domain = '$(sget '{.spec.domain}')', want $HOST"
[ "$(sget '{.spec.tls}')" = "true" ]            || fail "StaticSite spec.tls is not true"
HDRS="$(sget '{range .spec.responseHeaders[*]}{.name}={.value};{end}')"
for want in "X-Probe-Header=$MARKER;" "X-Frame-Options=DENY;" "X-Content-Type-Options=nosniff;"; do
  printf '%s' "$HDRS" | grep -qF "$want" || fail "StaticSite responseHeaders missing $want (got $HDRS)"
done
BPOL="$(kubectl -n "$CFN_NS" get buckets.openinfra.dev "$BCLAIM" -o jsonpath='{.spec.policy}' 2>/dev/null || echo "<missing>")"
[ "$BPOL" = "<missing>" ] && fail "the template's bucket did not become kind: Bucket $BCLAIM"
[ -z "$BPOL" ] || fail "the CloudFront-only bucket policy was stored as a MinIO policy (should be realized by the site): $BPOL"
log "    ✓ StaticSite $SITE (spa, $HOST, headers) over kind: Bucket $BCLAIM (no stored CloudFront policy)"

# --- 3. upload through the shim's S3 front door ---------------------------------------------------------
log "uploading index.html + assets/app.js to s3://$BUCKET through the shim (as a CI aws-s3 step would)"
printf '<!doctype html><title>cf probe</title><div id="app">%s</div>\n' "$MARKER" > "$TMP/index.html"
{ printf 'console.log("asset-%s");\n' "$SFX"; for _ in $(seq 1 40); do printf '// padding so the asset is past CloudFront'"'"'s 1,000-byte compression floor\n'; done; } > "$TMP/app.js"
s3api put-object --bucket "$BUCKET" --key index.html --body "$TMP/index.html" --content-type text/html >/dev/null 2>"$TMP/up.err" \
  || inconclusive "uploading through the shim's S3 front door failed (S3 front door / authz, not the CloudFront path): $(cat "$TMP/up.err")"
s3api put-object --bucket "$BUCKET" --key assets/app.js --body "$TMP/app.js" --content-type application/javascript >/dev/null 2>"$TMP/up.err" \
  || inconclusive "uploading assets/app.js through the shim failed: $(cat "$TMP/up.err")"
log "    ✓ uploaded"

# --- 4. served through Traefik over HTTPS on the Alias -------------------------------------------------
TRAEFIK_IP="$(kubectl -n "$TRAEFIK_NS" get svc "$TRAEFIK_SVC" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
[ -n "$TRAEFIK_IP" ] || inconclusive "svc/$TRAEFIK_SVC in ns $TRAEFIK_NS not found (set TRAEFIK_NS/TRAEFIK_SVC)"
CERT_READY=""
for i in $(seq 1 24); do
  CERT_READY="$(kubectl -n "$CFN_NS" get certificate "staticsite-$SITE-tls" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
  [ "$CERT_READY" = "True" ] && break
  sleep 5
done
[ "$CERT_READY" = "True" ] || inconclusive "Certificate staticsite-$SITE-tls not Ready (an ACME openinfra-issuer can't issue for .invalid names)"

kubectl create ns "$CLIENT_NS" >/dev/null 2>&1 || inconclusive "could not create the client ns $CLIENT_NS"
# A new namespace gets its default ServiceAccount a moment later, and a pod created before it exists is refused.
for _ in $(seq 1 30); do kubectl -n "$CLIENT_NS" get sa default >/dev/null 2>&1 && break; sleep 1; done
started=""
for _ in 1 2 3; do
  if kubectl -n "$CLIENT_NS" run "$CLIENT" --restart=Never --image="$CURL_IMAGE" --command -- sleep 900 >/dev/null 2>&1; then started=1; break; fi
  sleep 3
done
[ -n "$started" ] || inconclusive "could not start the curl client pod"
kubectl -n "$CLIENT_NS" wait --for=condition=Ready "pod/$CLIENT" --timeout=120s >/dev/null 2>&1 || inconclusive "curl client pod not Ready"
# Under a validated domain the site must be trusted the way ACM's certificates are: the client verifies
# it against the platform root alone (no -k). Otherwise the certificate is self-signed and not checked.
TLS_OPT="-k"
if [ -n "$VALIDATED" ]; then
  kubectl get environmentconfig openinfra-platform-ca -o jsonpath='{.data.platformRootCA}' \
    | kubectl -n "$CLIENT_NS" exec -i "$CLIENT" -- sh -c 'cat > /tmp/root.crt' \
    || inconclusive "could not hand the platform root to the client"
  TLS_OPT="--cacert /tmp/root.crt"
fi
# fetch <path>: headers, a blank line, then the body — over HTTPS to the Alias through Traefik.
fetch() { kubectl -n "$CLIENT_NS" exec "$CLIENT" -- curl -sS -m 10 $TLS_OPT -D - --resolve "$HOST:443:$TRAEFIK_IP" "https://$HOST$1" 2>/dev/null | tr -d '\r' || true; }
status_of() { printf '%s' "$1" | awk 'NR==1{print $2}'; }
header_of() {
  printf '%s' "$1" | awk -v h="$(printf '%s' "$2" | tr 'A-Z' 'a-z')" \
    'NR>1 && /^$/ {exit} { i = index($0, ": "); if (i > 0 && tolower(substr($0, 1, i-1)) == h) { print substr($0, i+2); exit } }'
}

log "waiting for the site to sync the upload (every 30s) and serve it on https://$HOST/"
ROOT=""
# The policy's X-Probe-Header carries $MARKER too, so match the BODY (after the headers) and a 200: a
# site that answers before its first sync returns 403 with the header, which is not the upload served.
body_of() { printf '%s' "$1" | awk 'f; /^$/ {f=1}'; }
for i in $(seq 1 24); do
  ROOT="$(fetch /)"
  [ "$(status_of "$ROOT")" = 200 ] && body_of "$ROOT" | grep -q "$MARKER" && break
  sleep 5
done
body_of "$ROOT" | grep -q "$MARKER" || fail "https://$HOST/ never served the uploaded index.html; last response: $(snip "$ROOT")"
[ "$(status_of "$ROOT")" = "200" ] || fail "https://$HOST/ returned $(status_of "$ROOT"), want 200"
DEEP="$(fetch /deep/client/route)"
[ "$(status_of "$DEEP")" = "200" ] && body_of "$DEEP" | grep -q "$MARKER" \
  || fail "a deep SPA route did not fall back to index.html with 200 (the 403/404 -> /index.html mapping); got: $(snip "$DEEP")"
ASSET="$(fetch /assets/app.js)"
printf '%s' "$ASSET" | grep -q "asset-$SFX" || fail "a real asset was not served as itself: $(snip "$ASSET")"
for r in "$ROOT" "$DEEP" "$ASSET"; do
  [ "$(header_of "$r" X-Probe-Header)" = "$MARKER" ]        || fail "response missing the policy's X-Probe-Header: $(snip "$(printf '%s' "$r" | sed '/^$/q')")"
  [ "$(header_of "$r" X-Frame-Options)" = "DENY" ]          || fail "response missing the policy's X-Frame-Options: DENY"
  [ "$(header_of "$r" X-Content-Type-Options)" = "nosniff" ] || fail "response missing the policy's X-Content-Type-Options: nosniff"
done
log "    ✓ https://$HOST/ and a deep route → index.html (200), the asset as itself, policy headers on every response"

# The viewer protocol policy and Compress, as CloudFront answers them: http:// is a 301 to the https URL,
# and a client that accepts gzip gets the asset (past the 1,000-byte floor) gzip-compressed.
HTTP="$(kubectl -n "$CLIENT_NS" exec "$CLIENT" -- curl -sS -m 10 -D - -o /dev/null --resolve "$HOST:80:$TRAEFIK_IP" "http://$HOST/deep/route?q=1" 2>/dev/null | tr -d '\r' || true)"
[ "$(status_of "$HTTP")" = 301 ] && [ "$(header_of "$HTTP" Location)" = "https://$HOST/deep/route?q=1" ] \
  || fail "redirect-to-https: http://$HOST/deep/route?q=1 must answer 301 to the https URL; got: $(snip "$HTTP")"
GZ="$(kubectl -n "$CLIENT_NS" exec "$CLIENT" -- curl -sS -m 10 $TLS_OPT -D - -o /dev/null -H 'Accept-Encoding: gzip' --resolve "$HOST:443:$TRAEFIK_IP" "https://$HOST/assets/app.js" 2>/dev/null | tr -d '\r' || true)"
[ "$(header_of "$GZ" Content-Encoding)" = gzip ] || fail "Compress: the asset was not gzip-compressed for Accept-Encoding: gzip; got: $(snip "$GZ")"
log "    ✓ http:// → 301 to https:// (redirect-to-https); the asset gzip-compressed (Compress)"

# --- 4b. a re-deploy: upload, create-invalidation, wait invalidation-completed → served at once ----------
DIST="$(cfn describe-stack-resource --stack-name "$STACK" --logical-resource-id "$L_CDN" --query 'StackResourceDetail.PhysicalResourceId' --output text 2>/dev/null || true)"
[[ "$DIST" =~ ^E[A-Z0-9]{13}$ ]] || fail "the distribution's physical id is '$DIST', want a CloudFront id (E + 13 characters)"
log "re-deploy: upload a new index.html, create-invalidation on $DIST, wait invalidation-completed"
MARKER2="CF_PROBE_V2_$SFX"
printf '<!doctype html><title>cf probe</title><div id="app">%s</div>\n' "$MARKER2" > "$TMP/index.html"
s3api put-object --bucket "$BUCKET" --key index.html --body "$TMP/index.html" --content-type text/html >/dev/null 2>"$TMP/up.err" \
  || fail "re-uploading index.html failed: $(cat "$TMP/up.err")"
INV="$(cf create-invalidation --distribution-id "$DIST" --paths '/*' --query 'Invalidation.Id' --output text 2>"$TMP/inv.err")" \
  || fail "create-invalidation failed: $(cat "$TMP/inv.err")"
[[ "$INV" =~ ^I[A-Z0-9]{13}$ ]] || fail "create-invalidation returned the id '$INV'"
cf wait invalidation-completed --distribution-id "$DIST" --id "$INV" 2>"$TMP/inv.err" \
  || fail "wait invalidation-completed did not see $INV complete: $(cat "$TMP/inv.err")"
ROOT="$(fetch /)"
printf '%s' "$ROOT" | grep -q "$MARKER2" || fail "invalidation $INV is Completed, but https://$HOST/ still serves the old content: $(snip "$ROOT")"
LST="$(cf list-invalidations --distribution-id "$DIST" --query "InvalidationList.Items[?Id=='$INV'].Status | [0]" --output text 2>&1 || true)"
[ "$LST" = Completed ] || fail "list-invalidations does not show $INV Completed: $LST"
ERR="$(cf create-invalidation --distribution-id E0000000000000 --paths '/*' 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q NoSuchDistribution || fail "an unknown distribution should be NoSuchDistribution: $(snip "$ERR")"
mint_key "cfprobe-cdn-reader-$SFX" "readers"; RAK="$MK_AK"; RSK="$MK_SK"
sleep 2
ERR="$(AWS_ACCESS_KEY_ID="$RAK" AWS_SECRET_ACCESS_KEY="$RSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager \
  cloudfront create-invalidation --distribution-id "$DIST" --paths '/*' 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q AccessDenied || fail "a reader's create-invalidation was not AccessDenied: $(snip "$ERR")"
log "    ✓ Completed once the site serves the new upload (served on the next request); listed Completed; unknown distribution → NoSuchDistribution; a reader → AccessDenied"

log "reads: get-distribution(-config), list-distributions, and the headers policy / OAC by the ids the distribution names"
cf get-distribution --id "$DIST" --output json >"$TMP/dist.json" 2>&1 || fail "get-distribution: $(snip "$(cat "$TMP/dist.json")")"
python3 - "$TMP/dist.json" "$HOST" <<'PY' || fail "get-distribution did not answer the stack's distribution: $(snip "$(cat "$TMP/dist.json")")"
import json, sys
d = json.load(open(sys.argv[1]))["Distribution"]
c = d["DistributionConfig"]
assert d["Status"] == "Deployed", d["Status"]
assert c["Aliases"]["Items"] == [sys.argv[2]], c["Aliases"]
assert c["DefaultCacheBehavior"]["ResponseHeadersPolicyId"], c["DefaultCacheBehavior"]
assert ":certificate/" in c["ViewerCertificate"]["ACMCertificateArn"], c["ViewerCertificate"]
assert c["Origins"]["Items"][0].get("OriginAccessControlId"), c["Origins"]
PY
HDR_ID="$(cf get-distribution-config --id "$DIST" --query 'DistributionConfig.DefaultCacheBehavior.ResponseHeadersPolicyId' --output text 2>/dev/null || true)"
[ "$(cf get-response-headers-policy --id "$HDR_ID" --query 'ResponseHeadersPolicy.Id' --output text 2>/dev/null)" = "$HDR_ID" ] \
  || fail "get-response-headers-policy did not answer the policy the distribution names ($HDR_ID)"
OAC_ID="$(cf get-distribution-config --id "$DIST" --query 'DistributionConfig.Origins.Items[0].OriginAccessControlId' --output text 2>/dev/null || true)"
[ "$(cf get-origin-access-control --id "$OAC_ID" --query 'OriginAccessControl.Id' --output text 2>/dev/null)" = "$OAC_ID" ] \
  || fail "get-origin-access-control did not answer the OAC the distribution names ($OAC_ID)"
cf list-distributions --query 'DistributionList.Items[].Id' --output text >"$TMP/ld.txt" 2>&1 || fail "list-distributions: $(snip "$(cat "$TMP/ld.txt")")"
tr '\t' '\n' <"$TMP/ld.txt" | grep -qx "$DIST" || fail "list-distributions did not list $DIST"
ERR="$(cf get-distribution --id E0000000000000 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q NoSuchDistribution || fail "get-distribution of an unknown id: $(snip "$ERR")"
log "    ✓ the distribution, its headers policy and OAC read back by the ids the stack gave them; listed; an unknown id → NoSuchDistribution"
CERT_ARN="$(cf get-distribution-config --id "$DIST" --query 'DistributionConfig.ViewerCertificate.ACMCertificateArn' --output text 2>/dev/null || true)"
acmq() { AWS_ACCESS_KEY_ID="$AAK" AWS_SECRET_ACCESS_KEY="$ASK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager acm "$@"; }
CERT_STATUS="$(acmq describe-certificate --certificate-arn "$CERT_ARN" --query Certificate.Status --output text 2>&1 || true)"
[ "$CERT_STATUS" = ISSUED ] || fail "acm describe-certificate of the stack's certificate ($CERT_ARN): $(snip "$CERT_STATUS")"
acmq describe-certificate --certificate-arn "$CERT_ARN" --query 'Certificate.InUseBy' --output text 2>/dev/null | grep -q "distribution/$DIST" \
  || fail "acm describe-certificate does not name $DIST in InUseBy"
acmq get-certificate --certificate-arn "$CERT_ARN" --output json >"$TMP/cert.json" 2>&1 || fail "acm get-certificate: $(snip "$(cat "$TMP/cert.json")")"
grep -q 'BEGIN CERTIFICATE' "$TMP/cert.json" || fail "acm get-certificate answered no certificate"
if grep -q 'PRIVATE KEY' "$TMP/cert.json"; then fail "acm get-certificate answered a private key"; fi
log "    ✓ the stack's certificate through ACM: ISSUED, in use by $DIST, its PEM certificate (no key)"

# --- 5. delete-stack removes the StaticSite, the Bucket and everything they held ------------------------
# As on AWS, a stack whose bucket still holds data does not delete (BucketNotEmpty): empty it first, as a
# user would. Nothing is swept before the check: what the delete itself left is what is asserted.
log "empty $BUCKET, then delete-stack $STACK → the StaticSite, the Bucket and their leftovers are removed"
for k in index.html assets/app.js; do s3api delete-object --bucket "$BUCKET" --key "$k" >/dev/null 2>&1 || fail "could not delete $k from $BUCKET"; done
cfn delete-stack --stack-name "$STACK" >/dev/null 2>&1 || fail "delete-stack failed"
i=0; while [ $i -lt 240 ]; do
  st="$(cfn describe-stacks --stack-name "$STACK" --query 'Stacks[0].[StackStatus,StackStatusReason]' --output text 2>/dev/null || echo GONE)"
  case "$st" in GONE*|DELETE_COMPLETE*) break;; DELETE_FAILED*) fail "delete-stack ended DELETE_FAILED: $st";; esac
  sleep 5; i=$((i+5))
done
for i in $(seq 1 24); do
  kubectl -n "$CFN_NS" get staticsites.openinfra.dev "$SITE" >/dev/null 2>&1 || kubectl -n "$CFN_NS" get buckets.openinfra.dev "$BCLAIM" >/dev/null 2>&1 || break
  sleep 5
done
kubectl -n "$CFN_NS" get staticsites.openinfra.dev "$SITE" >/dev/null 2>&1 && fail "StaticSite $SITE still present after delete-stack"
kubectl -n "$CFN_NS" get buckets.openinfra.dev "$BCLAIM" >/dev/null 2>&1 && fail "Bucket $BCLAIM still present after delete-stack"
s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1 && fail "bucket $BUCKET still exists after delete-stack (an empty stack bucket is deleted with the stack)"
# The claim Secrets and the TLS Secret are composed (deleted with the claims); the scoped users' credentials
# and the owner record are removed by the bucket reaper shortly after.
su="$(app_user StaticSite "$CFN_NS" "$SITE")"; bu="$(app_user Bucket "$CFN_NS" "$BCLAIM")"
left=""
for i in $(seq 1 30); do
  left="$(kubectl -n "$CFN_NS" get secret "$SITE-minio" "$BCLAIM-minio" "staticsite-$SITE-tls" -o name 2>/dev/null; kubectl -n "$CREDS_NS" get secret "bucket-owner-$BUCKET" "$su" "$bu" -o name 2>/dev/null; true)"  # an absent Secret is the expected answer, not a set -e exit
  [ -z "$left" ] && break
  sleep 5
done
[ -z "$left" ] || fail "delete-stack left Secrets behind: $(echo $left)"
log "    ✓ stack destroyed: StaticSite, Bucket and the MinIO bucket gone; no credentials, owner record or TLS Secret left"

printf '\n✓ PASS — the cfn engine'"'"'s CloudFront subset is faithful through the aws-shim CloudFormation front door: an\n'
printf '  unmodified CloudFront-over-private-S3 template deploys as a kind: StaticSite over its kind: Bucket, content\n'
printf '  uploaded through the S3 front door is served on the Alias over HTTPS with SPA fallback and the response\n'
printf '  headers policy, a re-deploy'"'"'s invalidation completes once the site serves the new upload, an\n'
printf '  out-of-subset feature (Lambda@Edge) refuses the whole stack with nothing created, and delete-stack removes\n'
printf '  what was created.\n'
