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
# Needs: a deployed aws-shim with the CloudFormation doorway enabled, the probe handler image published
# where the cluster can pull it (build+push below; needs ghcr push access), and the aws CLI + kubectl.
# Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-cfn-customresource.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
CFN_NS="${CFN_NS:-open-infra-aws-shim}"        # the namespace the CFN doorway deploys into
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
PROBE_IMAGE="${PROBE_IMAGE:-ghcr.io/harn3ss/cfn-cr-probe:v1}"
STACK="cfn-cr-probe-$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
HERE="$(cd "$(dirname "$0")" && pwd)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

cleanup() {
  AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-x}" AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-x}" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager cloudformation delete-stack --stack-name "$STACK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 1. Publish the handler image where the cluster can pull it (idempotent; skip if already present).
if ! curl -fsS -m 5 "https://ghcr.io/v2/" >/dev/null 2>&1; then :; fi
log "building + pushing the probe handler image ${PROBE_IMAGE}"
if command -v docker >/dev/null 2>&1; then
  docker build -t "$PROBE_IMAGE" "$HERE/cfn-cr-probe" >/dev/null 2>&1 \
    && docker push "$PROBE_IMAGE" >/dev/null 2>&1 \
    || inconclusive "could not build/push ${PROBE_IMAGE} (ghcr push access required) — the engine logic is unit-proven in cfn/translate_customresource_test.go; this probe needs the handler image published for the cluster to pull"
else
  inconclusive "docker not available to publish the handler image"
fi

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
for i in $(seq 1 40); do
  st="$(AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=x aws --endpoint-url "$ENDPOINT" --no-cli-pager \
         cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
  case "$st" in
    CREATE_COMPLETE) log "  ✓ stack CREATE_COMPLETE"; break ;;
    *FAILED*|*ROLLBACK*) fail "stack reached $st (the custom-resource invoke or a dependent failed)" ;;
  esac
  sleep 6
done

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
