#!/usr/bin/env bash
# Live end-to-end probe for CloudFormation Lambda-backed custom resources.
#
# Proves the full AWS-faithful flow on a real cluster: a custom resource's in-stack Function is invoked
# at deploy and its returned Data resolves a DEPENDENT's Fn::GetAtt. The cfn ENGINE logic (interleaved
# deploy, Data->GetAtt, rollback, fail-closed) is already unit-proven (cfn/translate_customresource_test.go);
# THIS probe proves the live integration: the aws-shim CloudFormation doorway's in-cluster invoker POSTs
# the custom-resource event to the Function's Knative URL, parses {Status,Data}, and feeds GetAtt.
#
# The stack: a Handler Function (the probe image below — returns {"Status":"SUCCESS","Data":{"Endpoint":...}}
# on any POST), a Custom::Probe whose ServiceToken !GetAtt's it, and a Consumer Function whose env
# ENDPOINT = !GetAtt Custom::Probe.Endpoint. After CREATE_COMPLETE the Consumer's env MUST carry the Data
# value, proving the custom resource was invoked mid-deploy and its Data flowed through GetAtt.
#
# Needs: a deployed aws-shim with the CloudFormation doorway enabled, the aws CLI + kubectl, and crane or
# docker. The probe handler image is built and pushed to the platform's own registry (an ECR repository
# through the shim, as CI would push an image), so no outside registry access is needed. Set PROBE_IMAGE to
# use an image already published where the cluster can pull it instead. AWS_CA_BUNDLE: the platform root CA,
# for TLS to the registry.
# Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-cfn-customresource.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
CFN_NS="${CFN_NS:-open-infra-cfn}"             # the namespace the CFN doorway deploys into
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
export AWS_REGION="$REGION" # every call signs for the same region (a profile's default may differ)
PROBE_IMAGE="${PROBE_IMAGE:-}"
PROBE_REPO="${PROBE_REPO:-cfn-cr-probe}"
STACK="cfn-cr-probe-$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
HERE="$(cd "$(dirname "$0")" && pwd)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

CREATED_REPO=""
USERS_NS="${USERS_NS:-open-infra-console}"
CREATED_USERS=(); CREATED_KEYS=()
cleanup() {
  # The stack goes first, and is waited for: its delete runs as this run's deployer, which is removed below.
  # A stack still being created cannot be deleted (as on AWS): wait for its create to settle first
  # (CREATE_COMPLETE, or a rollback's ROLLBACK_COMPLETE), so a timed-out run does not strand it.
  for _ in $(seq 1 100); do
    cst="$(aws --endpoint-url "$ENDPOINT" --region "$REGION" --no-cli-pager cloudformation describe-stacks --stack-name "$STACK" \
            --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
    case "$cst" in *_IN_PROGRESS) sleep 6 ;; *) break ;; esac
  done
  if aws --endpoint-url "$ENDPOINT" --region "$REGION" --no-cli-pager cloudformation delete-stack --stack-name "$STACK" >/dev/null 2>&1; then
    for _ in $(seq 1 60); do
      aws --endpoint-url "$ENDPOINT" --region "$REGION" --no-cli-pager cloudformation describe-stacks --stack-name "$STACK" >/dev/null 2>&1 || break
      sleep 3
    done
    aws --endpoint-url "$ENDPOINT" --region "$REGION" --no-cli-pager cloudformation describe-stacks --stack-name "$STACK" >/dev/null 2>&1 \
      && printf '  (cleanup) WARNING: stack %s is still present\n' "$STACK" >&2
  fi
  if [ -n "$CREATED_REPO" ]; then # the handler image's repository, created by this run
    AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-x}" AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-x}" \
      aws --endpoint-url "$ENDPOINT" --region "$REGION" --no-cli-pager ecr delete-repository --repository-name "$CREATED_REPO" --force >/dev/null 2>&1 || true
  fi
  # the deployer this run minted (never left behind: a minted key is an admin credential)
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for k in "${CREATED_KEYS[@]:-}";  do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
}
trap cleanup EXIT

# 0. A caller: the shim authenticates every request (SigV4 against a real key). Without one supplied in
# the environment, mint a throwaway openinfra:admins deployer for this run (removed by cleanup).
if [ -z "${AWS_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_SECRET_ACCESS_KEY:-}" ]; then
  owner="cfncr-admin-$(head -c3 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  ak="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  sk="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  printf 'apiVersion: iam.openinfra.dev/v1\nkind: User\nmetadata: { name: "%s", namespace: "%s" }\nspec: { displayName: "%s", groups: ["admins"], source: local }\n' \
    "$owner" "$USERS_NS" "$owner" | kubectl apply -f - >/dev/null || inconclusive "could not mint a deployer User"
  CREATED_USERS+=("$owner")
  kname="iam-ak-$(printf '%s' "$ak" | sha256sum | cut -c1-40)"
  kubectl -n "$SHIM_NS" create secret generic "$kname" --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" \
    --from-literal=owner="$owner" >/dev/null || inconclusive "could not mint a deployer key"
  CREATED_KEYS+=("$kname")
  export AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk"
  log "minted a throwaway openinfra:admins deployer ($owner)"
  sleep 20 # the key reaches the shim's key cache
fi

# 1. Publish the handler image where the cluster can pull it: the platform registry, through the shim's
# ECR front door (create the repository, log in with its token, push). Referenced by digest, so nothing
# has to resolve a tag against the registry.
if [ -z "$PROBE_IMAGE" ]; then
  AWSC=(aws --endpoint-url "$ENDPOINT" --region "$REGION" --no-cli-pager)
  export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-x}" AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-x}"
  if "${AWSC[@]}" ecr create-repository --repository-name "$PROBE_REPO" >/dev/null 2>"$PWD/.cr_ecr"; then
    CREATED_REPO="$PROBE_REPO"
  else
    grep -q RepositoryAlreadyExists "$PWD/.cr_ecr" || inconclusive "ecr create-repository $PROBE_REPO failed: $(head -c 300 "$PWD/.cr_ecr")"
  fi
  URI="$("${AWSC[@]}" ecr describe-repositories --repository-names "$PROBE_REPO" --query 'repositories[0].repositoryUri' --output text)" \
    || inconclusive "ecr describe-repositories $PROBE_REPO failed"
  REG="${URI%%/*}"
  [ -n "${AWS_CA_BUNDLE:-}" ] && export SSL_CERT_FILE="$AWS_CA_BUNDLE"
  log "building the probe handler image and pushing it to $URI"
  if command -v crane >/dev/null 2>&1; then
    export DOCKER_CONFIG="$(mktemp -d)"
    "${AWSC[@]}" ecr get-login-password | crane auth login "$REG" -u AWS --password-stdin >/dev/null 2>&1 \
      || inconclusive "registry login to $REG failed (is AWS_CA_BUNDLE the platform root CA?)"
    LAYER="$(mktemp)"; tar -C "$HERE/cfn-cr-probe" -cf "$LAYER" handler.py
    crane append -b python:3.12-alpine -f "$LAYER" -t "$URI:v1" >/dev/null 2>&1 \
      && crane mutate "$URI:v1" --cmd python,/handler.py --exposed-ports 8080 -t "$URI:v1" >/dev/null 2>&1 \
      || inconclusive "building/pushing the handler image to $URI failed"
    PROBE_IMAGE="$URI@$(crane digest "$URI:v1")"
  elif command -v docker >/dev/null 2>&1; then
    "${AWSC[@]}" ecr get-login-password | docker login -u AWS --password-stdin "$REG" >/dev/null 2>&1 \
      || inconclusive "docker login $REG failed (is the platform root CA trusted by docker?)"
    docker build -q -t "$URI:v1" "$HERE/cfn-cr-probe" >/dev/null && docker push -q "$URI:v1" >/dev/null \
      || inconclusive "building/pushing the handler image to $URI failed"
    PROBE_IMAGE="$(docker inspect --format '{{index .RepoDigests 0}}' "$URI:v1")"
  else
    inconclusive "crane or docker is needed to build the handler image"
  fi
fi
log "  ✓ handler image $PROBE_IMAGE"

# 2. Deploy the stack through the shim's CloudFormation doorway.
TMPL="$(mktemp)"; cat > "$TMPL" <<YAML
Resources:
  Handler:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: ${PROBE_IMAGE} } }
  Setup:
    Type: Custom::Probe
    Properties: { ServiceToken: !GetAtt Handler.Arn }
  Consumer:
    Type: AWS::Lambda::Function
    Properties:
      PackageType: Image
      Code: { ImageUri: ${PROBE_IMAGE} }
      Environment: { Variables: { ENDPOINT: !GetAtt Setup.Endpoint } }
YAML
log "deploying stack ${STACK} (Handler Function + Custom::Probe + Consumer that GetAtt's the Data)"
AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-x}" AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-x}" AWS_REGION="$REGION" \
  aws --endpoint-url "$ENDPOINT" --no-cli-pager cloudformation create-stack \
    --stack-name "$STACK" --template-body "file://$TMPL" >/dev/null 2>"$PWD/.cr_err" \
  || fail "create-stack was rejected: $(cat "$PWD/.cr_err" 2>/dev/null)"
rm -f "$PWD/.cr_err"

log "waiting for CREATE_COMPLETE (the custom resource is invoked mid-deploy)"
st=""
for i in $(seq 1 40); do
  st="$(aws --endpoint-url "$ENDPOINT" --no-cli-pager \
         cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
  case "$st" in
    CREATE_COMPLETE) log "  ✓ stack CREATE_COMPLETE"; break ;;
    *FAILED*|*ROLLBACK*) fail "stack reached $st (the custom-resource invoke or a dependent failed)" ;;
  esac
  sleep 6
done
# Out of time is a timeout, not a missing Data: say so, with what the stack was doing.
[ "$st" = CREATE_COMPLETE ] || fail "timed out after 4 minutes waiting for CREATE_COMPLETE: the stack is ${st:-<not found>} ($(aws --endpoint-url "$ENDPOINT" --no-cli-pager cloudformation describe-stack-events --stack-name "$STACK" --query 'StackEvents[0].[LogicalResourceId,ResourceStatus,ResourceStatusReason]' --output text 2>/dev/null || true))"

# 3. Verify the returned Data flowed into the Consumer's Fn::GetAtt (its env ENDPOINT).
CONSUMER="$(kubectl -n "$CFN_NS" get functions.openinfra.dev -l "cfn.openinfra.dev/stack=${STACK}" -o name 2>/dev/null | grep -i consumer || true)"
ENV_JSON="$(kubectl -n "$CFN_NS" get functions.openinfra.dev -o jsonpath='{range .items[*]}{.metadata.name}={.spec.env}{"\n"}{end}' 2>/dev/null | grep -i consumer || true)"
if printf '%s' "$ENV_JSON" | grep -q 'https://cfn-cr-probe.ok'; then
  printf '\n✓ PASS — the custom resource was invoked at deploy and its returned Data resolved the\n'
  printf '  dependent Consumer'\''s Fn::GetAtt (ENDPOINT=https://cfn-cr-probe.ok). Full AWS-faithful\n'
  printf '  custom-resource flow works live through the aws-shim CloudFormation doorway (#269).\n'
  exit 0
fi
fail "the Consumer did not receive the custom resource's Data via GetAtt; got env: ${ENV_JSON:-<none>}"
