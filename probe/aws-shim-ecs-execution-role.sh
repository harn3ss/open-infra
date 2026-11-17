#!/usr/bin/env bash
# Live probe: an ECS task's image is pulled with its task execution role (ExecutionRoleArn), as on ECS.
#
# An administrator pushes a small runnable image into an ECR repository the way an ECR user does
# (aws ecr get-login-password | docker login; docker push), creates two task execution roles trusting
# ecs-tasks.amazonaws.com — one allowed to pull the repository (ecr:GetAuthorizationToken, ecr:BatchGetImage,
# ecr:GetDownloadUrlForLayer, ecr:BatchCheckLayerAvailability), one allowed nothing in ECR — and runs one
# ECS service with each as its task definition's executionRoleArn:
#   - the service whose execution role may pull reaches runningCount 1;
#   - the service whose execution role may not pull never runs a task (runningCount 0, pendingCount 1): its
#     pull is refused, and the node does not fall back to its own credential, as ECS's
#     CannotPullContainerError;
#   - as ECS reports it, the refused task's container carries a CannotPullContainerError (DescribeTasks) and
#     the service's events say it is unable to consistently start tasks;
#   - ECR's BatchGetImage returns the pushed image's manifest;
#   - the tasks name the image as AWS names the account's registry (<account>.dkr.ecr.<region>.amazonaws.com):
#     it is that account's repository here, pulled with the execution role, never from AWS;
#   - a power user (PowerUserAccess has no iam:PassRole) naming the allowed role provisions nothing.
# A task is decided by the ECR credential provider of the node it lands on; on a node where it is not
# installed yet the result proves nothing, and the probe says so (exit 42).
#
# Exit 0 pass, 1 fail, 42 inconclusive. Needs the aws CLI, kubectl (KUBECONFIG), curl and docker; reaches the
# shim at SHIM_ENDPOINT (port-forward svc/aws-shim 4566) and the registry at REG_ENDPOINT (port-forward
# -n open-infra-ecr svc/ecr-registry 5000, on 127.0.0.1 so docker speaks plain HTTP to it).
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REG="${REG_ENDPOINT:-http://127.0.0.1:5000}"
NODE_REGISTRY="${NODE_REGISTRY:-ecr-registry.open-infra-ecr.svc.cluster.local:5000}"
SOURCE_IMAGE="${SOURCE_IMAGE:-registry.k8s.io/pause:3.10}"
REGION="${AWS_REGION:-us-east-1}"
ACCOUNT="${ACCOUNT_ID:-000000000000}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for c in aws kubectl curl docker; do command -v "$c" >/dev/null || inconclusive "$c is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
REGHOST="${REG#http://}"

ADMIN="ecsexec-admin-$SFX"; POWER="ecsexec-power-$SFX"; REPO="ecsexec-$SFX"
ROLE_OK="ecsexec-pull-$SFX"; ROLE_NONE="ecsexec-none-$SFX"
SVC_OK="ecsexec-ok-$SFX"; SVC_NONE="ecsexec-none-$SFX"; SVC_POWER="ecsexec-power-$SFX"
CREATED_KEYS=(); CREATED_USERS=(); ROLES=(); SERVICES=(); MADE_REPO=""
as() { local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$@"; }
cleanup() {
  for s in "${SERVICES[@]:-}"; do [ -n "$s" ] && as "$AAK" "$ASK" ecs delete-service --service "$s" --force >/dev/null 2>&1; done
  [ -n "$MADE_REPO" ] && as "$AAK" "$ASK" ecr delete-repository --repository-name "$REPO" --force >/dev/null 2>&1
  for r in "${ROLES[@]:-}"; do
    [ -n "$r" ] || continue
    as "$AAK" "$ASK" iam delete-role-policy --role-name "$r" --policy-name p >/dev/null 2>&1
    as "$AAK" "$ASK" iam delete-role --role-name "$r" >/dev/null 2>&1
  done
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1; done
  for k in "${CREATED_KEYS[@]:-}"; do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1; done
  docker logout "$REGHOST" >/dev/null 2>&1
  docker rmi "$REGHOST/$REPO:1" >/dev/null 2>&1
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

# --- 1. an image in ECR, pushed as an ECR user pushes it -----------------------------------------------
log "seeding an administrator and a power user; pushing ${SOURCE_IMAGE} to ${REPO}"
mint_key "$ADMIN" "admins"; AAK="$MK_AK"; ASK="$MK_SK"
mint_key "$POWER" "powerusers"; PAK="$MK_AK"; PSK="$MK_SK"
ok=""
for _ in $(seq 1 10); do
  as "$AAK" "$ASK" ecr create-repository --repository-name "$REPO" >/dev/null 2>"$TMP/repo" && { ok=1; break; }
  sleep 3
done
[ -n "$ok" ] || inconclusive "create-repository failed: $(head -c 300 "$TMP/repo")"
MADE_REPO=1
docker pull -q "$SOURCE_IMAGE" >/dev/null 2>&1 || inconclusive "could not pull ${SOURCE_IMAGE}"
as "$AAK" "$ASK" ecr get-login-password 2>/dev/null | docker login --username AWS --password-stdin "$REGHOST" >/dev/null 2>"$TMP/login" \
  || inconclusive "docker login to ${REGHOST} failed: $(head -c 300 "$TMP/login")"
docker tag "$SOURCE_IMAGE" "$REGHOST/$REPO:1" && docker push -q "$REGHOST/$REPO:1" >/dev/null 2>"$TMP/push" \
  || fail "docker push failed: $(head -c 300 "$TMP/push")"
# Tasks name the image as AWS names an account's registry; it is pulled from the platform's, never from AWS.
IMAGE="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/$REPO:1"
log "  ✓ pushed; tasks run ${IMAGE}"
got="$(as "$AAK" "$ASK" ecr batch-get-image --repository-name "$REPO" --image-ids imageTag=1 \
  --query 'images[0].[imageId.imageTag,imageId.imageDigest]' 2>/dev/null | tr '\t' ' ')"
want="$(as "$AAK" "$ASK" ecr describe-images --repository-name "$REPO" --query 'imageDetails[0].imageDigest' 2>/dev/null)"
[ -n "$want" ] && [ "$got" = "1 ${want}" ] || fail "BatchGetImage of ${REPO}:1 = '${got}', want tag 1 with DescribeImages' digest ${want}"
as "$AAK" "$ASK" ecr batch-get-image --repository-name "$REPO" --image-ids imageTag=1 --query 'images[0].imageManifest' 2>/dev/null \
  | python3 -c 'import json,sys; m=json.load(sys.stdin); assert m.get("layers") or m.get("manifests")' 2>/dev/null \
  || fail "BatchGetImage's imageManifest is not the image's manifest"
log "  ✓ BatchGetImage returns ${REPO}:1's manifest, with DescribeImages' digest"

# --- 2. two execution roles ----------------------------------------------------------------------------
TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
REPO_ARN="arn:aws:ecr:${REGION}:${ACCOUNT}:repository/${REPO}"
mkrole() { # <name> <policy>
  as "$AAK" "$ASK" iam create-role --role-name "$1" --assume-role-policy-document "$TRUST" >/dev/null 2>"$TMP/cr" \
    || inconclusive "create-role $1 failed: $(head -c 300 "$TMP/cr")"
  ROLES+=("$1")
  as "$AAK" "$ASK" iam put-role-policy --role-name "$1" --policy-name p --policy-document "$2" >/dev/null || fail "put-role-policy $1 failed"
}
mkrole "$ROLE_OK" '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ecr:GetAuthorizationToken","Resource":"*"},{"Effect":"Allow","Action":["ecr:BatchGetImage","ecr:GetDownloadUrlForLayer","ecr:BatchCheckLayerAvailability"],"Resource":"'"$REPO_ARN"'"}]}'
mkrole "$ROLE_NONE" '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"logs:CreateLogStream","Resource":"*"}]}'
log "waiting 35s for the IAM policy world to load the roles' policies"
sleep 35

# --- 3. a service per role -----------------------------------------------------------------------------
service() { # <ak> <sk> <service> <role>: register a task definition naming the role, create the service
  local fam="$3-td"
  as "$1" "$2" ecs register-task-definition --family "$fam" --requires-compatibilities FARGATE --network-mode awsvpc \
    --cpu 256 --memory 512 --execution-role-arn "arn:aws:iam::${ACCOUNT}:role/$4" \
    --container-definitions '[{"name":"app","image":"'"$IMAGE"'","essential":true}]' >/dev/null 2>"$TMP/td" \
    || { echo "register-task-definition: $(head -c 300 "$TMP/td")"; return 1; }
  as "$1" "$2" ecs create-service --service-name "$3" --task-definition "$fam" --desired-count 1 --launch-type FARGATE \
    --network-configuration "awsvpcConfiguration={subnets=[${SUBNET}],assignPublicIp=ENABLED}" \
    >/dev/null 2>"$TMP/cs" || { echo "create-service: $(head -c 300 "$TMP/cs")"; return 1; }
}
# An awsvpc task's service names where its interface goes, as ECS requires: the account's default subnet.
SUBNET="$(as "$AAK" "$ASK" ec2 describe-subnets --filters Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' 2>/dev/null)"
case "$SUBNET" in subnet-*) ;; *) inconclusive "the account has no default subnet to run its tasks in (got '${SUBNET}')" ;; esac
log "the administrator runs ${SVC_OK} (execution role may pull) and ${SVC_NONE} (execution role may not), in ${SUBNET}"
service "$AAK" "$ASK" "$SVC_OK" "$ROLE_OK" || fail "$SVC_OK not created"; SERVICES+=("$SVC_OK")
service "$AAK" "$ASK" "$SVC_NONE" "$ROLE_NONE" || fail "$SVC_NONE not created"; SERVICES+=("$SVC_NONE")

counts() { as "$AAK" "$ASK" ecs describe-services --services "$1" --query 'services[0].[runningCount,pendingCount]' 2>/dev/null | tr '\t' ' '; }
# diag <service>: where its task is and why (printed on a failure or an inconclusive result)
diag() {
  kubectl get pods -A -l "app.kubernetes.io/name=$1" -o jsonpath='{range .items[*]}  task pod {.metadata.namespace}/{.metadata.name} on {.spec.nodeName}: {.status.phase} {.status.containerStatuses[0].state.waiting.reason}{"\n"}{end}' >&2 2>/dev/null
  local ns; ns="$(kubectl get pods -A -l "app.kubernetes.io/name=$1" -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null)"
  [ -n "$ns" ] && kubectl -n "$ns" get events --sort-by=.lastTimestamp -o jsonpath='{range .items[*]}{.involvedObject.name} {.reason}: {.message}{"\n"}{end}' 2>/dev/null | grep -F "$1" | tail -4 | cut -c1-240 >&2
  [ -n "$ns" ] || kubectl get applications.openinfra.dev -A 2>/dev/null | grep -F "$1" >&2 || echo "  no Application $1" >&2
}
# armed <service>: the node its task landed on has the ECR credential provider (yes/no/unknown)
armed() {
  local node
  node="$(kubectl get pods -A -l "app.kubernetes.io/name=$1" -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null)"
  [ -n "$node" ] || { echo unknown; return; }
  [ "$(kubectl get node "$node" -o jsonpath='{.metadata.labels.openinfra\.dev/ecr-credential-provider}' 2>/dev/null)" = enabled ] && echo yes || echo no
}
st=""
for _ in $(seq 1 48); do st="$(counts "$SVC_OK")"; [ "$st" = "1 0" ] && break; sleep 5; done
[ "$(armed "$SVC_OK")" = yes ] || { diag "$SVC_OK"; inconclusive "${SVC_OK}'s task is on a node without the ECR credential provider (running pending = $st)"; }
if [ "$st" != "1 0" ]; then diag "$SVC_OK"; fail "${SVC_OK} never ran its task (running pending = $st): its execution role could not pull"; fi
log "  ✓ ${SVC_OK}: runningCount 1 — pulled as its execution role"

sleep 60 # well past the allowed service's pull
[ "$(armed "$SVC_NONE")" = yes ] || { diag "$SVC_NONE"; inconclusive "${SVC_NONE}'s task is on a node without the ECR credential provider"; }
st="$(counts "$SVC_NONE")"
case "$st" in
  "0 1") log "  ✓ ${SVC_NONE}: runningCount 0, pendingCount 1 — its pull was refused, with no fall back to the node's credential" ;;
  "1 0") diag "$SVC_NONE"; fail "WIDER THAN AWS: ${SVC_NONE} ran an image its execution role may not pull" ;;
  *) diag "$SVC_NONE"; fail "${SVC_NONE} reports running pending = '$st'" ;;
esac
# As ECS reports it: the task's container carries a CannotPullContainerError, and the service's events say
# it is unable to consistently start tasks.
ntask="$(as "$AAK" "$ASK" ecs list-tasks --service-name "$SVC_NONE" --query 'taskArns[0]' 2>/dev/null)"
reason="$(as "$AAK" "$ASK" ecs describe-tasks --tasks "$ntask" --query 'tasks[0].containers[0].reason' 2>/dev/null)"
case "$reason" in CannotPullContainerError:*) ;; *) diag "$SVC_NONE"; fail "${SVC_NONE}'s task reason is '${reason}', want a CannotPullContainerError" ;; esac
as "$AAK" "$ASK" ecs describe-services --services "$SVC_NONE" --query 'services[0].events[].message' 2>/dev/null | tr '\t' '\n' \
  | grep -qF "(service ${SVC_NONE}) is unable to consistently start tasks successfully." \
  || fail "${SVC_NONE}'s events do not say it is unable to consistently start tasks"
log "  ✓ ${SVC_NONE}: DescribeTasks says CannotPullContainerError, and its events say it is unable to consistently start tasks"

# --- 4. passing the role takes iam:PassRole --------------------------------------------------------------
log "a power user (no iam:PassRole) naming ${ROLE_OK} provisions nothing"
service "$PAK" "$PSK" "$SVC_POWER" "$ROLE_OK" >/dev/null && SERVICES+=("$SVC_POWER")
sleep 30
if kubectl get applications.openinfra.dev -A -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | grep -q "$SVC_POWER"; then
  fail "WIDER THAN AWS: a principal without iam:PassRole provisioned a service naming an execution role"
fi
log "  ✓ nothing provisioned"

printf '\n✓ PASS: an ECS task is pulled as its task execution role: a role that may pull runs the task, one that may not leaves it pending with no fall back, and naming the role takes iam:PassRole\n'
