#!/usr/bin/env bash
# Compatibility probe for the API Gateway REST v1 CloudFormation deploy executor (#295). Proves the whole
# path end to end against a LIVE shim: a real `aws cloudformation create-stack` of a REST v1 template
# (RestApi + resource off the root + a MOCK method + Deployment + Stage) is provisioned by the in-cluster
# doorway via the apigateway store; a REAL HTTP GET to the deployed stage path returns 200; and
# `delete-stack` tears the API down (it no longer lists in get-rest-apis) — no orphan.
#
# This is the create+invoke+teardown contract of the executor, complementing aws-shim-apigateway-restv1.sh
# (which proves the apigateway API surface directly). Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-apigateway-restv1-cfn.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v curl >/dev/null || inconclusive "curl is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

WORK="$(mktemp -d)"
STACK="cfnprobe-$SFX"
APINAME="cfnprobe-api-$SFX"
CREATED_KEYS=(); CREATED_USERS=(); WAK=""; WSK=""
cleanup() {
  [ -n "$WAK" ] && aws --endpoint-url "$ENDPOINT" --no-cli-pager cloudformation delete-stack --stack-name "$STACK" >/dev/null 2>&1 || true
  for k in "${CREATED_KEYS[@]:-}";  do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }
mint_key() {
  local owner="$1"
  local ak="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  local sk; sk="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "${owner}", namespace: "${USERS_NS}" }
spec: { displayName: "${owner}", groups: ["powerusers"], source: local }
YAML
  CREATED_USERS+=("$owner")
  local name; name="$(secret_name "$ak")"
  kubectl -n "$SHIM_NS" create secret generic "$name" --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  CREATED_KEYS+=("$name")
  printf '%s %s' "$ak" "$sk"
}
awscli() { AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager "$@"; }

log "seeding a writer principal"
read -r WAK WSK <<<"$(mint_key "cfnprobe-$SFX")"
{ [ -n "$WAK" ] && [ -n "$WSK" ]; } || inconclusive "failed to mint a key"

cat > "$WORK/tmpl.yaml" <<YAML
Resources:
  ApiGatewayRestApi:
    Type: AWS::ApiGateway::RestApi
    Properties: { Name: ${APINAME} }
  Ping:
    Type: AWS::ApiGateway::Resource
    Properties:
      RestApiId: !Ref ApiGatewayRestApi
      ParentId: !GetAtt ApiGatewayRestApi.RootResourceId
      PathPart: ping
  GetPing:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref ApiGatewayRestApi
      ResourceId: !Ref Ping
      HttpMethod: GET
      AuthorizationType: NONE
      Integration: { Type: MOCK }
  Dep:
    Type: AWS::ApiGateway::Deployment
    DependsOn: GetPing
    Properties: { RestApiId: !Ref ApiGatewayRestApi }
  ProdStage:
    Type: AWS::ApiGateway::Stage
    Properties: { RestApiId: !Ref ApiGatewayRestApi, DeploymentId: !Ref Dep, StageName: prod }
YAML

log "cloudformation create-stack ($STACK) — a REST v1 template provisioned via the in-cluster executor"
awscli cloudformation create-stack --stack-name "$STACK" --template-body "file://$WORK/tmpl.yaml" >/dev/null 2>"$WORK/cs" \
  || inconclusive "create-stack call failed (is the CloudFormation front door enabled?): $(cat "$WORK/cs")"

# poll for CREATE_COMPLETE
STATUS=""
for _ in $(seq 1 60); do
  STATUS="$(awscli cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
  case "$STATUS" in
    CREATE_COMPLETE) break ;;
    CREATE_FAILED|ROLLBACK_*|*FAILED) fail "stack reached $STATUS (executor did not provision the API). Events: $(awscli cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatusReason' --output text 2>/dev/null)" ;;
  esac
  sleep 3
done
[ "$STATUS" = "CREATE_COMPLETE" ] || fail "stack did not reach CREATE_COMPLETE (last: '$STATUS')"
log "  ✓ stack CREATE_COMPLETE"

# find the provisioned REST API id by its Name
API="$(awscli apigateway get-rest-apis --query "items[?name=='${APINAME}'].id | [0]" --output text 2>/dev/null || true)"
{ [ -n "$API" ] && [ "$API" != "None" ]; } || fail "the provisioned REST API ($APINAME) is not listed in get-rest-apis"
log "  ✓ provisioned REST API $API"

log "REAL HTTP GET /prod/ping → the MOCK method returns 200"
CODE="$(curl -sS -o /dev/null -w '%{http_code}' "${ENDPOINT}/_apigw/${API}/prod/ping" 2>/dev/null || true)"
[ "$CODE" = "200" ] || fail "invoke of the CFN-provisioned stage returned '$CODE' (want 200 from the MOCK method)"
log "  ✓ invoke 200 — the executor built the resource tree, method, integration, deployment + stage"

log "cloudformation delete-stack → the API is torn down (no orphan)"
awscli cloudformation delete-stack --stack-name "$STACK" >/dev/null 2>&1 || fail "delete-stack call failed"
GONE=""
for _ in $(seq 1 40); do
  DS="$(awscli cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
  if [ -z "$DS" ] || [ "$DS" = "DELETE_COMPLETE" ] || printf '%s' "$DS" | grep -qiE 'does not exist|not found|ValidationError'; then GONE=1; break; fi
  [ "$DS" = "DELETE_FAILED" ] && fail "delete-stack reached DELETE_FAILED"
  sleep 3
done
[ -n "$GONE" ] || fail "stack did not delete"
STILL="$(awscli apigateway get-rest-apis --query "items[?name=='${APINAME}'].id | [0]" --output text 2>/dev/null || true)"
{ [ -z "$STILL" ] || [ "$STILL" = "None" ]; } || fail "the REST API ($API) survived delete-stack — deprovision did not tear it down (orphan)"
log "  ✓ delete-stack tore the REST API down (get-rest-apis no longer lists it)"
WAK="" # stack already deleted; skip the cleanup-trap delete

printf '\n✓ PASS — the API Gateway REST v1 CloudFormation deploy executor is faithful: a real create-stack of a REST v1 template is provisioned via the in-cluster doorway (resource tree + method + integration + deployment + stage), the deployed stage serves a real 200, and delete-stack tears the API down with no orphan.\n'
