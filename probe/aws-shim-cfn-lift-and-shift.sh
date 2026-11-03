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
#      http://<Elastic IP>/results.json): #!/bin/bash UserData runs, the encrypted data disk (the 1 GiB
#      volume) formats and mounts by its Nitro name /dev/nvme1n1, the root disk is encrypted (with
#      KUBECONFIG set: its PVC is on longhorn-encrypted), IMDSv2 requires a token and serves the role's credentials, `aws s3 cp` works with the
#      distro CLI and aws-cli v2, a call outside the role's policy is denied, the role sends email through
#      SES (SendEmail and SendRawEmail, as the sender identity its policy names), an image pulls from the
#      registry, and a container in the guest gets the role's credentials through the default chain; AWS's
#      own names reach open-infra (the guest resolver): with no AWS_ENDPOINT_URL the CLI sends and receives
#      by an AWS-style queue URL and reads the bucket at <bucket>.s3.<region>.amazonaws.com, an image pulls
#      by <account>.dkr.ecr.<region>.amazonaws.com, and the JavaScript SDK v3's default S3Client and
#      SQSClient (virtual-hosted bucket, a batch delete with a per-key AccessDenied, AWS-style QueueUrl)
#      work in a container; with
#      KUBECONFIG set and the mail relay in capture mode (mail.capture), both messages are in the sink;
#   3. the Elastic IP is a reachable LAN address; the CloudFront site serves its origin (SPA fallback +
#      the response-headers policy); the deploy flow's last step works — after the site upload,
#      `aws cloudfront create-invalidation` on the distribution in the Outputs and `aws cloudfront wait
#      invalidation-completed` — and on a re-deploy the next request after the wait serves the new content;
#      a pre-signed S3 link opens;
#   3a. the deploy flow's code update: `aws ssm send-command` on the stack's InstanceId output runs as root
#      through the instance's agent, `aws ssm wait command-executed` sees it succeed, and the instance-id
#      its metadata reports is that output;
#   3b. the shell route: a key pair imported with `aws ec2 import-key-pair`, named by KeyName, logs in over
#      SSH from the one address an SshCidr rule allows, and a client outside it is refused on 22;
#   3c. a resize: an update to a larger InstanceType (RESIZE_TYPE, default t3.medium) completes once the
#      instance was stopped and started and runs a new boot with more memory, on the same private address;
#   4. delete-stack removes everything (DELETE_COMPLETE; with KUBECONFIG set, no claim of the stack is
#      left in the cluster);
#   5. the instance's DNS names: PrivateDnsName is AWS's ip-a-b-c-d.<zone> form, and PublicDnsName is
#      either "" (the install sets no public DNS suffix) or ec2-<its address>.<suffix>, resolving to it.
# With ADDRESS_STACK=1 the address lives in its own stack (cfn/testdata/lift-and-shift/eip.yaml), passed to
# the app stack as AppAddressAllocationId: the instance is served on that stack's address; releasing the
# address while it is associated fails (DELETE_FAILED, InvalidIPAddress.InUse); deleting the app stack
# leaves the address with its stack; the address stack is deleted last.
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
#   SITE_CA_BUNDLE  (optional) verify the static site's TLS against this CA (the platform root, for a
#                   SITE_DOMAIN under a domain the operator validated: certificates.validatedDomains)
#   SITE_VALIDATED_DOMAINS (optional) those validated domains, comma-separated, for the offline plan
#   RESIZE_TYPE     (optional) the InstanceType the resize step moves to (default t3.medium; larger than
#                   the template's default t3.small)
#   APP_IMAGE       (optional) the image the instance pulls (default: the aws-cli image, copied into ECR)
#   CFN_BIN         (optional) path to the cfn CLI, for the fidelity summary
#   EVIDENCE_OUT    (optional) write {name, exit_code, reason, when} here
#   KEEP=1          (optional) leave the stack up for inspection
#   ADDRESS_STACK=1 (optional) keep the instance's Elastic IP in its own stack (eip.yaml), see above
# Needs: aws (v2), curl, python3, and crane or docker to push the app image.
# Exit 0 = pass, 1 = a real failure, 42 = inconclusive.
#
#   SHIM_ENDPOINT=https://s3.example SITE_DOMAIN=site.example AWS_CA_BUNDLE=ca.crt ./probe/aws-shim-cfn-lift-and-shift.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
NAME=aws-shim-cfn-lift-and-shift
HERE="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="${TEMPLATE:-$HERE/../cfn/testdata/lift-and-shift/template.yaml}"
EIP_TEMPLATE="${EIP_TEMPLATE:-$(dirname "$TEMPLATE")/eip.yaml}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
STACK="${STACK:-lsfix-$SFX}"
ADDR_STACK="${ADDR_STACK:-${STACK}-address}"
ADDR_STATE=""
REPO="${REPO:-lsfix-app-$SFX}"
CFN_NS="${CFN_NS:-open-infra-cfn}"
CREDS_NS="${CREDS_NS:-openinfra-bucket-creds}"
APP_IMAGE="${APP_IMAGE:-docker.io/amazon/aws-cli:2.27.50}"
RESULTS_TIMEOUT="${RESULTS_TIMEOUT:-1800}"
RESIZE_TYPE="${RESIZE_TYPE:-t3.medium}"
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
# The static site's TLS: verified against SITE_CA_BUNDLE when set (a site under a domain the operator
# validated has a certificate the platform root vouches for, as ACM's are trusted); otherwise not checked.
SITE_TLS=(-k); [ -n "${SITE_CA_BUNDLE:-}" ] && SITE_TLS=(--cacert "$SITE_CA_BUNDLE")

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
  if [ "${KEEP:-0}" != 1 ] && [ -n "$ADDR_STATE" ]; then
    # The address stack goes last: its address cannot be released while the app stack still holds it.
    "${A[@]}" cloudformation wait stack-delete-complete --stack-name "$STACK" >/dev/null 2>&1 || true
    "${A[@]}" cloudformation delete-stack --stack-name "$ADDR_STACK" >/dev/null 2>&1 || true
    "${A[@]}" cloudformation wait stack-delete-complete --stack-name "$ADDR_STACK" >/dev/null 2>&1 || true
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
  "$CFN_BIN" plan -stack-name "$STACK" -object-encryption ${SITE_VALIDATED_DOMAINS:+-validated-domains "$SITE_VALIDATED_DOMAINS"} -param SiteDomain="$SITE_DOMAIN" \
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
outof() { "${A[@]}" cloudformation describe-stacks --stack-name "$1" --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text; }
ADDR_OVERRIDE=()
if [ "${ADDRESS_STACK:-0}" = 1 ]; then
  # The address in its own stack, deployed first; the app stack takes its AllocationId.
  [ -f "$EIP_TEMPLATE" ] || inconclusive "address template not found: $EIP_TEMPLATE"
  log "aws cloudformation deploy --stack-name $ADDR_STACK (the instance's Elastic IP, in its own stack)"
  ADDR_STATE=deploying
  "${A[@]}" cloudformation deploy --template-file "$EIP_TEMPLATE" --stack-name "$ADDR_STACK" \
    > "$TMP/deploy-addr.txt" 2>&1 || fail "deploying the address stack failed: $(tail -3 "$TMP/deploy-addr.txt" | tr '\n' ' ')"
  ALLOC="$(outof "$ADDR_STACK" AllocationId)"; EIP_ADDR="$(outof "$ADDR_STACK" PublicIp)"
  [[ "$ALLOC" =~ ^eipalloc-[0-9a-f]{17}$ ]] || fail "the address stack's AllocationId output is '$ALLOC'"
  [ -n "$EIP_ADDR" ] && [ "$EIP_ADDR" != None ] || fail "the address stack returned no PublicIp output"
  log "  ✓ allocation $ALLOC holds $EIP_ADDR"
  ADDR_OVERRIDE=("AppAddressAllocationId=$ALLOC")
fi
# The shell route (#347 item 24): a key pair imported as on AWS, named by the template's KeyName, and an SSH
# rule scoped to this host's address alone (SSH_CIDR overrides it), the usual admin-only ingress.
SSH_OVERRIDE=(); KEY_NAME=""
if command -v ssh-keygen >/dev/null && command -v ssh >/dev/null; then
  KEY_NAME="lsfix-key-$SFX"
  ssh-keygen -q -t ed25519 -N "" -C "$KEY_NAME" -f "$TMP/ssh-key" || fail "ssh-keygen failed"
  "${A[@]}" ec2 import-key-pair --key-name "$KEY_NAME" --public-key-material "fileb://$TMP/ssh-key.pub" \
    --query KeyFingerprint --output text > "$TMP/kp.txt" 2>&1 || fail "aws ec2 import-key-pair failed: $(tr '\n' ' ' < "$TMP/kp.txt")"
  SSH_SRC="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="src") {print $(i+1); exit}}')"
  SSH_CIDR="${SSH_CIDR:-${SSH_SRC:+$SSH_SRC/32}}"
  [ -n "$SSH_CIDR" ] || inconclusive "could not find this host's address for the SSH rule (set SSH_CIDR)"
  log "  ✓ imported key pair $KEY_NAME ($(cat "$TMP/kp.txt")); SSH limited to $SSH_CIDR"
  SSH_OVERRIDE=("KeyName=$KEY_NAME" "SshCidr=$SSH_CIDR")
else
  log "  (no ssh client here: the shell-route step is skipped)"
fi
log "aws cloudformation deploy --stack-name $STACK (parameter overrides only)"
STATE=deploying
"${A[@]}" cloudformation deploy --template-file "$TEMPLATE" --stack-name "$STACK" --capabilities CAPABILITY_IAM \
  --parameter-overrides "SiteDomain=$SITE_DOMAIN" "AppRepositoryName=$REPO" "${ADDR_OVERRIDE[@]}" "${SSH_OVERRIDE[@]}" \
  > "$TMP/deploy.txt" 2>&1 || fail "aws cloudformation deploy failed: $(tail -3 "$TMP/deploy.txt" | tr '\n' ' ')"
ST="$("${A[@]}" cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' --output text)"
[ "$ST" = CREATE_COMPLETE ] || fail "stack status $ST, want CREATE_COMPLETE"
out() { outof "$STACK" "$1"; }
if [ "${ADDRESS_STACK:-0}" = 1 ]; then
  ADDR="$EIP_ADDR"
  [ "$(out InstanceAllocationId)" = "$ALLOC" ] || fail "the instance carries allocation '$(out InstanceAllocationId)', want $ALLOC"
else
  ADDR="$(out InstanceAddress)"
fi
SITE_URL="$(out SiteUrl)"; APPB="$(out AppBucketName)"; SITEB="$(out SiteBucketName)"
DIST="$(out SiteDistributionId)"
log "  ✓ CREATE_COMPLETE; Outputs: InstanceAddress=$ADDR SiteUrl=$SITE_URL AppBucketName=$APPB SiteBucketName=$SITEB SiteDistributionId=$DIST"
[ -n "$ADDR" ] && [ "$ADDR" != None ] || fail "the stack returned no InstanceAddress output (the Elastic IP)"
[ -n "$APPB" ] && [ "$APPB" != None ] || fail "the stack returned no AppBucketName output"
[ -n "$DIST" ] && [ "$DIST" != None ] || fail "the stack returned no SiteDistributionId output"
# The instance's DNS names: AWS's private form; the public one names its address on the install's suffix
# (and resolves to it), or is "" where the install gives instances no public DNS name.
PUB_DNS="$(out InstancePublicDnsName)"; PRIV_DNS="$(out InstancePrivateDnsName)"
[ "$PUB_DNS" = None ] && PUB_DNS=""
[[ "$PRIV_DNS" =~ ^ip-[0-9]+-[0-9]+-[0-9]+-[0-9]+\.(ec2\.internal|[a-z0-9-]+\.compute\.internal)$ ]] || fail "InstancePrivateDnsName is '$PRIV_DNS', want AWS's ip-a-b-c-d.<zone> form"
if [ -n "$PUB_DNS" ]; then
  [[ "$PUB_DNS" == "ec2-${ADDR//./-}."* ]] || fail "InstancePublicDnsName '$PUB_DNS' does not name the instance's address $ADDR"
  RES="$(getent hosts "$PUB_DNS" 2>/dev/null | awk '{print $1; exit}')"
  [ "$RES" = "$ADDR" ] || fail "InstancePublicDnsName $PUB_DNS resolves to '$RES', want $ADDR"
  log "  ✓ PublicDnsName $PUB_DNS resolves to $ADDR; PrivateDnsName $PRIV_DNS"
else
  log "  ✓ PublicDnsName is \"\" (no public DNS suffix on this install); PrivateDnsName $PRIV_DNS"
fi

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
# Every check passes, s3_cp_distro_cli (the distro aws CLI v1) included: v1 predates AWS_ENDPOINT_URL, so the
# guest's endpoint plugin applies it (docs/virtual-machines.md#aws-endpoints-inside-the-guest). The SES
# checks need the mail component (SES is not fronted without a relay).
[ -z "$FAILED" ] || fail "instance checks failed: $FAILED"
# The image's default user, SES v1 and v2, and AWS's own names inside the guest
# (platform/aws-shim/guest-aws-endpoints.yaml): an AWS-style queue URL and bucket name with no
# AWS_ENDPOINT_URL, an image by its ECR name, and the JavaScript SDK v3's default clients all reach the
# platform.
for k in default_user ses_send_email ses_send_raw_email ses_v2_send_email sqs_aws_style_queue_url s3_aws_name ecr_pull_aws_name sdk_v3_default_clients; do
  printf '%s' "$R" | grep -q "\"$k\": \"ok\"" || fail "the instance did not report its $k check"
done
log "  ✓ every instance check passed (served over the Elastic IP $ADDR)"

# The two messages the instance sent, in the capturing relay (a test cluster's mail.capture sink). Read
# from inside the sink's pod: its API listens on loopback only (platform/mail/relay-capture.yaml).
if command -v kubectl >/dev/null && [ -n "${KUBECONFIG:-}" ] \
   && [ "$(kubectl -n mail get deploy smtp-relay -o jsonpath='{.metadata.labels.openinfra\.dev/mail-capture}' 2>/dev/null)" = true ]; then
  SUBJECTS="$(kubectl -n mail exec deploy/smtp-relay -- wget -qO- 'http://127.0.0.1:8025/api/v1/messages?limit=500' 2>/dev/null \
    | python3 -c 'import json,sys; print("\n".join(m.get("Subject","") for m in json.load(sys.stdin).get("messages",[])))' 2>/dev/null || true)"
  for kind in send-email send-raw-email sesv2-send-email; do
    printf '%s\n' "$SUBJECTS" | grep -qx "lift-and-shift $STACK $kind" \
      || fail "the capturing relay has no message 'lift-and-shift $STACK $kind' (the instance's SES $kind)"
  done
  log "  ✓ the three SES messages (SendEmail, SendRawEmail, v2 SendEmail) reached the capturing relay"
else
  log "  (with KUBECONFIG set and mail.capture on, the probe also finds the instance's SES messages in the sink)"
fi
# The root mapping is Encrypted: the instance booted from a LUKS root (longhorn-encrypted), which the
# guest cannot tell from inside.
if command -v kubectl >/dev/null && [ -n "${KUBECONFIG:-}" ]; then
  VMN="$(kubectl -n "$CFN_NS" get virtualmachines.openinfra.dev -l "cfn.openinfra.dev/stack=$STACK" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [ -n "$VMN" ] || fail "no kind: VirtualMachine of $STACK in $CFN_NS"
  RSC="$(kubectl -n "$CFN_NS" get pvc "$VMN-root" -o jsonpath='{.spec.storageClassName}/{.spec.volumeMode}' 2>/dev/null || true)"
  [ "$RSC" = longhorn-encrypted/Block ] || fail "the instance's root disk is not the encrypted PVC (got '$RSC')"
  log "  ✓ the root disk is encrypted at rest (PVC $VMN-root on longhorn-encrypted)"
fi

# --- 4a. the deploy flow's code update: Run Command on the instance the stack reports ---------------------
#     (aws ssm send-command --instance-ids <InstanceId output>, then aws ssm wait command-executed). The
#     command reads the instance's own instance-id from its metadata, so the InstanceId output is shown to
#     be the id the guest reports; it runs as root and changes what the instance serves.
IID="$(out InstanceId)"
[[ "$IID" =~ ^i-[0-9a-f]{17}$ ]] || fail "the InstanceId output is '$IID', want an i- id (the instance's own)"
log "Run Command on $IID: waiting for its agent to register (describe-instance-information)"
PING=""
for _ in $(seq 1 30); do
  PING="$("${A[@]}" ssm describe-instance-information --filters "Key=InstanceIds,Values=$IID" \
    --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || true)"
  [ "$PING" = Online ] && break
  sleep 10
done
[ "$PING" = Online ] || fail "the instance's agent did not register with SSM (PingStatus '$PING'; its role attaches AmazonSSMManagedInstanceCore)"
cat > "$TMP/rc-params.json" <<JSON
{"commands": [
  "set -e",
  "T=\$(curl -s -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token)",
  "curl -s -H \"X-aws-ec2-metadata-token: \$T\" http://169.254.169.254/latest/meta-data/instance-id; echo",
  "id -un",
  "echo deployed-$SFX > /var/www/deployed.txt"
]}
JSON
CMD="$("${A[@]}" ssm send-command --document-name AWS-RunShellScript --instance-ids "$IID" --comment "lift-and-shift deploy" \
  --parameters "file://$TMP/rc-params.json" --query Command.CommandId --output text 2>"$TMP/rc.err")" \
  || fail "aws ssm send-command failed: $(tr '\n' ' ' < "$TMP/rc.err")"
"${A[@]}" ssm wait command-executed --command-id "$CMD" --instance-id "$IID" 2>"$TMP/rc.err" \
  || fail "aws ssm wait command-executed: $(tr '\n' ' ' < "$TMP/rc.err") ($("${A[@]}" ssm get-command-invocation --command-id "$CMD" --instance-id "$IID" --query '[Status,StandardErrorContent]' --output text 2>/dev/null | tr '\n' ' '))"
RC_OUT="$("${A[@]}" ssm get-command-invocation --command-id "$CMD" --instance-id "$IID" --query StandardOutputContent --output text)"
[ "$(printf '%s\n' "$RC_OUT" | sed -n 1p)" = "$IID" ] || fail "the instance's metadata reports instance-id '$(printf '%s\n' "$RC_OUT" | sed -n 1p)', but the stack's InstanceId output is $IID"
[ "$(printf '%s\n' "$RC_OUT" | sed -n 2p)" = root ] || fail "the command did not run as root (ran as '$(printf '%s\n' "$RC_OUT" | sed -n 2p)')"
[ "$(curl -s -m 5 "http://$ADDR/deployed.txt")" = "deployed-$SFX" ] || fail "the command ran, but the instance does not serve what it wrote"
log "  ✓ send-command $CMD → wait command-executed → Success: ran as root, IMDS instance-id = the InstanceId output ($IID)"

# --- 4c. the shell route: the imported key logs in over SSH from the one address the rule names, and a
#     client outside it is refused while it still reaches the instance's open port (#347 item 24) --------
if [ -n "$KEY_NAME" ]; then
  SSH_OPTS=(-i "$TMP/ssh-key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10)
  WHO=""
  for _ in $(seq 1 18); do
    WHO="$(ssh "${SSH_OPTS[@]}" "ubuntu@$ADDR" 'id -un' 2>"$TMP/ssh.err")" && break
    sleep 10
  done
  [ "$WHO" = ubuntu ] || fail "ssh -i <the imported key> ubuntu@$ADDR from $SSH_CIDR (the rule's own address) did not log in: $(tail -2 "$TMP/ssh.err" | tr '\n' ' ')"
  log "  ✓ ssh with key pair $KEY_NAME logs in as ubuntu from $SSH_CIDR, the address the rule allows"
  if [ -n "${KUBECONFIG:-}" ] && command -v kubectl >/dev/null; then
    # An in-cluster client: its address is outside $SSH_CIDR, so 22 must be refused while 80 (0.0.0.0/0)
    # answers it, which shows the refusal is the rule's and not a path that reaches nothing.
    PROBE_POD="lsfix-outside-$SFX"
    kubectl -n "$CFN_NS" run "$PROBE_POD" --restart=Never --image=docker.io/library/busybox:1.36.1 \
      --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":65534,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"c","image":"docker.io/library/busybox:1.36.1","command":["sh","-c","nc -z -w 8 '"$ADDR"' 80 && echo open80 || echo closed80; nc -z -w 8 '"$ADDR"' 22 && echo open22 || echo closed22"],"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}' \
      >/dev/null 2>"$TMP/pod.err" || fail "could not start the outside client pod: $(tr '\n' ' ' < "$TMP/pod.err")"
    for _ in $(seq 1 30); do
      ph="$(kubectl -n "$CFN_NS" get pod "$PROBE_POD" -o jsonpath='{.status.phase}' 2>/dev/null)"
      [ "$ph" = Succeeded ] || [ "$ph" = Failed ] && break
      sleep 2
    done
    OUTSIDE="$(kubectl -n "$CFN_NS" logs "$PROBE_POD" 2>/dev/null | tr '\n' ' ')"
    kubectl -n "$CFN_NS" delete pod "$PROBE_POD" --wait=false >/dev/null 2>&1 || true
    case "$OUTSIDE" in
      *open80*closed22*) log "  ✓ a client outside $SSH_CIDR reaches port 80 but is refused on 22" ;;
      *open80*open22*)   fail "a client outside $SSH_CIDR reached SSH on $ADDR (the rule allows only $SSH_CIDR)" ;;
      *)                 log "  ⚠ NOT PROVEN: the outside client could not reach port 80 either ('$OUTSIDE'), so its refusal on 22 shows nothing" ;;
    esac
  else
    log "  ⚠ NOT PROVEN: refusal of a client outside $SSH_CIDR needs KUBECONFIG (an in-cluster client)"
  fi
fi

# --- 4b. a resize: a new InstanceType in a stack update stops and starts the instance, and the update
#     completes once it runs at the new size (AWS: "Update requires: Some interruptions") ---------------
# boot_info: the instance's boot.json — its memory and this boot's id, written at every boot.
boot_info() { curl -s -m 5 "http://$ADDR/boot.json" 2>/dev/null; }
bfield() { python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1" 2>/dev/null; }
B0="$(boot_info)"; MEM0="$(printf '%s' "$B0" | bfield memTotalKiB)"; BOOT0="$(printf '%s' "$B0" | bfield bootId)"
[ -n "$MEM0" ] && [ -n "$BOOT0" ] || fail "the instance does not serve its boot.json (got '$B0')"
log "aws cloudformation deploy --stack-name $STACK with InstanceType=$RESIZE_TYPE (was the template's default; $MEM0 KiB)"
"${A[@]}" cloudformation deploy --template-file "$TEMPLATE" --stack-name "$STACK" --capabilities CAPABILITY_IAM \
  --parameter-overrides "SiteDomain=$SITE_DOMAIN" "AppRepositoryName=$REPO" "InstanceType=$RESIZE_TYPE" "${ADDR_OVERRIDE[@]}" \
  > "$TMP/resize.txt" 2>&1 || fail "the resize (aws cloudformation deploy, InstanceType=$RESIZE_TYPE) failed: $(tail -3 "$TMP/resize.txt" | tr '\n' ' ')"
ST="$("${A[@]}" cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' --output text)"
[ "$ST" = UPDATE_COMPLETE ] || fail "after the resize the stack is $ST, want UPDATE_COMPLETE"
"${A[@]}" cloudformation describe-stack-events --stack-name "$STACK" \
  --query "StackEvents[?LogicalResourceId=='AppInstance' && ResourceStatus=='UPDATE_IN_PROGRESS'].ResourceStatusReason" --output text \
  | grep -q "Stopping and starting the instance" || fail "the resize's events do not say the instance was stopped and started"
# When the update completes the instance runs at the new size: a new boot (its web unit starts with it),
# with more memory, on the same private address (AWS keeps it across a stop and start).
B1=""; MEM1=""; BOOT1=""
for _ in $(seq 1 30); do
  B1="$(boot_info)"; BOOT1="$(printf '%s' "$B1" | bfield bootId)"
  [ -n "$BOOT1" ] && [ "$BOOT1" != "$BOOT0" ] && break
  sleep 10
done
MEM1="$(printf '%s' "$B1" | bfield memTotalKiB)"
[ -n "$BOOT1" ] && [ "$BOOT1" != "$BOOT0" ] || fail "the instance did not boot again after the resize (boot.json: '$B1')"
[ -n "$MEM1" ] && [ "$MEM1" -gt $(( MEM0 * 3 / 2 )) ] || fail "after the resize to $RESIZE_TYPE the instance has $MEM1 KiB (was $MEM0 KiB), want the larger size"
[ "$(out InstancePrivateDnsName)" = "$PRIV_DNS" ] || fail "the resize changed the instance's private address ($PRIV_DNS -> $(out InstancePrivateDnsName)); AWS keeps it across a stop and start"
curl -s -m 5 "http://$ADDR/results.json" | grep -q '"done": "yes"' || fail "after the resize the instance no longer serves its results on $ADDR"
if command -v kubectl >/dev/null && [ -n "${KUBECONFIG:-}" ]; then
  RR="$(kubectl -n "$CFN_NS" get virtualmachines.openinfra.dev "$VMN" -o jsonpath='{.status.powerState}/{.status.restartRequired}' 2>/dev/null || true)"
  [ "$RR" = Running/false ] || fail "after the resize the VM reports '$RR' (powerState/restartRequired), want Running/false"
fi
log "  ✓ resized to $RESIZE_TYPE: UPDATE_COMPLETE after a stop and start; the instance runs a new boot with $MEM1 KiB (was $MEM0), same private address"

# --- 5. the static site (CloudFront subset) and a pre-signed link --------------------------------------
log "the static site at $SITE_URL"
SITE_OK=""
for i in $(seq 1 12); do
  B="$(curl -s "${SITE_TLS[@]}" -m 8 "$SITE_URL/" 2>/dev/null)"
  printf '%s' "$B" | grep -q "LSFIX_SITE_$SFX" && { SITE_OK=1; break; }
  sleep 10
done
[ -n "$SITE_OK" ] || fail "$SITE_URL/ did not serve the uploaded index.html"
H="$(curl -s "${SITE_TLS[@]}" -m 8 -D - -o "$TMP/deep.html" "$SITE_URL/some/client/route" | tr -d '\r')"
printf '%s' "$H" | head -1 | grep -q " 200" && grep -q "LSFIX_SITE_$SFX" "$TMP/deep.html" || fail "SPA fallback: a deep route did not serve index.html with 200"
printf '%s' "$H" | grep -qi '^x-fixture: lift-and-shift' || fail "the response-headers policy's X-Fixture header is missing"
if [ -n "${SITE_CA_BUNDLE:-}" ]; then
  log "  ✓ site serves its origin, SPA fallback + response headers, over TLS verified against the given CA (a validated domain)"
else
  log "  ✓ site serves its origin, SPA fallback + response headers (TLS not verified: set SITE_CA_BUNDLE for a validated domain)"
fi
# A re-deploy of the site: new content, the invalidation, the wait — and the very next request serves it.
printf '<!doctype html><title>fixture</title><p id="m">LSFIX_REDEPLOY_%s</p>\n' "$SFX" > "$TMP/index.html"
"${A[@]}" s3 cp "$TMP/index.html" "s3://$SITEB/index.html" >/dev/null || fail "re-uploading the site to $SITEB failed"
invalidate "$DIST"
B="$(curl -s "${SITE_TLS[@]}" -m 8 "$SITE_URL/" 2>/dev/null)"
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
if [ -n "$KEY_NAME" ] && [ "${KEEP:-0}" != 1 ]; then
  "${A[@]}" ec2 delete-key-pair --key-name "$KEY_NAME" >/dev/null 2>&1 || log "  (could not delete key pair $KEY_NAME)"
fi
if [ "${KEEP:-0}" = 1 ]; then
  log "KEEP=1: leaving stack $STACK up"; STATE=""
else
  if [ "${ADDRESS_STACK:-0}" = 1 ]; then
    # AWS refuses to release an address that is still associated (InvalidIPAddress.InUse).
    log "delete-stack $ADDR_STACK while its address is on the instance (AWS: the release fails, InvalidIPAddress.InUse)"
    "${A[@]}" cloudformation delete-stack --stack-name "$ADDR_STACK" || fail "delete-stack $ADDR_STACK failed"
    "${A[@]}" cloudformation wait stack-delete-complete --stack-name "$ADDR_STACK" 2>/dev/null \
      && fail "the address stack was deleted although its address was associated with the instance"
    ast="$("${A[@]}" cloudformation describe-stacks --stack-name "$ADDR_STACK" --query 'Stacks[0].[StackStatus,StackStatusReason]' --output text 2>&1)"
    printf '%s' "$ast" | grep -q DELETE_FAILED && printf '%s' "$ast" | grep -q InvalidIPAddress.InUse \
      || fail "releasing an associated address ended as '$ast', want DELETE_FAILED naming InvalidIPAddress.InUse"
    curl -s -m 5 -o /dev/null "http://$ADDR/results.json" || fail "the instance stopped answering on $ADDR after the refused release"
    log "  ✓ refused as AWS refuses it: DELETE_FAILED (InvalidIPAddress.InUse); the instance still answers on $ADDR"
  fi
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
  if [ "${ADDRESS_STACK:-0}" = 1 ]; then
    # The address stays with its allocation when the stack that used it goes; then it is released.
    still="$(outof "$ADDR_STACK" PublicIp 2>/dev/null)"
    [ "$still" = "$ADDR" ] || fail "after the app stack was deleted the address stack reports '$still', want $ADDR (the address must stay with its allocation)"
    log "  ✓ $ADDR_STACK still holds $ADDR after the app stack was deleted"
    "${A[@]}" cloudformation delete-stack --stack-name "$ADDR_STACK" || fail "delete-stack $ADDR_STACK (retry) failed"
    "${A[@]}" cloudformation wait stack-delete-complete --stack-name "$ADDR_STACK" 2>/dev/null \
      || { ast="$("${A[@]}" cloudformation describe-stacks --stack-name "$ADDR_STACK" --query 'Stacks[0].[StackStatus,StackStatusReason]' --output text 2>&1)"
           printf '%s' "$ast" | grep -q -E "does not exist|DELETE_COMPLETE" || fail "the address stack did not delete once released: $ast"; }
    ADDR_STATE=""
    if command -v kubectl >/dev/null && [ -n "${KUBECONFIG:-}" ]; then
      kubectl -n "$CFN_NS" get service "$ALLOC" >/dev/null 2>&1 && fail "the allocation's holder Service $ALLOC outlived its stack"
    fi
    log "  ✓ the address stack deleted once nothing used its address"
  fi
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

MSG="unmodified lift-and-shift template deployed through the CloudFormation front door from a LAN client: CREATE_COMPLETE with Outputs; instance checks all passed over the Elastic IP (bash UserData, encrypted root, encrypted data disk formatted by its Nitro name, IMDSv2 token + role creds, s3 cp distro+v2, out-of-policy call denied, ECR pull, container default-chain creds); resized to $RESIZE_TYPE by a stack update (stopped and started, a new boot with more memory, same private address)${ADDR_OVERRIDE:+, the address held by its own stack (released only once unassociated, kept when the app stack went)}; instance DNS names as AWS forms them${PUB_DNS:+ (public name resolves to the address)}; CloudFront site served with SPA fallback + headers; create-invalidation + wait invalidation-completed after each upload, the re-deployed content served on completion; pre-signed link opened; teardown clean${FIDELITY_N:+; fidelity summary lists $FIDELITY_N not-emulated properties}"
printf '\n✓ PASS — %s\n' "$MSG"
evidence 0 "$MSG"
exit 0
