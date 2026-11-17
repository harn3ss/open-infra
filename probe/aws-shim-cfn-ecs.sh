#!/usr/bin/env bash
# Live probe: an ECS service a CloudFormation stack creates is an ECS service like any other, as on AWS.
#
# An administrator creates one stack, as an AWS user writes it: a log group, an ECS cluster, a task role
# trusting ecs-tasks.amazonaws.com, a Fargate-sized task definition (Cpu 256, Memory 512) whose container
# logs with the awslogs driver to the stack's log group and names the stack's role with !GetAtt, and a
# service in the stack's cluster. Then, through the AWS CLI:
#   - ECS lists the stack's cluster and its service in it (ListClusters, DescribeClusters, ListServices),
#     DescribeTaskDefinition describes the stack's task definition, and DescribeServices reports the service
#     running its task, with its PRIMARY deployment and the stack's task definition;
#   - CloudWatch Logs reads the container's output from the stack's log group, in the stream
#     <awslogs-stream-prefix>/<container>/<task id>;
#   - ListTasks and DescribeTasks list and describe the service's task (RUNNING, group service:<name>, the
#     stack's task definition), and DescribeClusters counts the cluster's service and its running task;
#   - the service's task is sized as the task definition says (cpu 250m, memory 512Mi) and runs as the
#     stack's task role (the operator's view of its Application);
#   - an UPDATE change set that resizes the task reports the task definition replaced (Replacement True, Cpu
#     and Memory RequiresRecreation Always), as AWS's does, and a role allowed cloudformation:ExecuteChangeSet
#     and denied cloudformation:UpdateStack executes it: executing a change set is ExecuteChangeSet alone;
#   - in CloudFormation's default (STANDARD) mode an update completes only once the service is steady (every
#     desired task running); in EXPRESS mode (--deployment-config) it completes once applied;
#   - a principal with no policy is refused DescribeServices and GetLogEvents with AWS's access-denied error.
#
# Exit 0 pass, 1 fail, 42 inconclusive. Needs the aws CLI, kubectl (KUBECONFIG) and curl; reaches the shim at
# SHIM_ENDPOINT (e.g. a port-forward of svc/aws-shim 4566).
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
STACK_NS="${CFN_NAMESPACE:-open-infra-cfn}" # where the management account's stacks make their resources
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
IMAGE="${ECS_IMAGE:-nginx:1.27-alpine}" # a public image whose entrypoint writes to stdout at start
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for c in aws kubectl curl; do command -v "$c" >/dev/null || inconclusive "$c is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

ADMIN="cfnecs-admin-$SFX"; NOPOL="cfnecs-nopol-$SFX"
STACK="cfnecs-$SFX"; CLUSTER="cfnecs-$SFX"; SERVICE="cfnecs-$SFX"; FAMILY="cfnecs-$SFX"; GROUP="/probe/cfnecs-$SFX"
CREATED_KEYS=(); CREATED_USERS=(); MADE_STACK=""; DEPLOYER="cfnecs-deployer-$SFX"; MADE_ROLE=""
as() { local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$@"; }
cleanup() {
  if [ -n "$MADE_ROLE" ]; then
    as "$AAK" "$ASK" iam delete-role-policy --role-name "$DEPLOYER" --policy-name deploy >/dev/null 2>&1
    as "$AAK" "$ASK" iam delete-role --role-name "$DEPLOYER" >/dev/null 2>&1
  fi
  if [ -n "$MADE_STACK" ]; then
    as "$AAK" "$ASK" cloudformation delete-stack --stack-name "$STACK" >/dev/null 2>&1
    for _ in $(seq 1 60); do
      as "$AAK" "$ASK" cloudformation describe-stacks --stack-name "$STACK" >/dev/null 2>&1 || break
      sleep 5
    done
  fi
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1; done
  for k in "${CREATED_KEYS[@]:-}"; do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1; done
  rm -rf "$TMP"
}
trap cleanup EXIT

# mint_key <owner> [group]: a kind: User (in group, or in none) and an access key the shim authenticates;
# sets MK_AK MK_SK.
mint_key() {
  local owner="$1" group="${2:-}" ak sk name groups="[]"
  [ -n "$group" ] && groups="[\"${group}\"]"
  ak="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  sk="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  cat <<YAML | kubectl apply -f - >/dev/null || inconclusive "could not create User $owner"
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "${owner}", namespace: "${USERS_NS}" }
spec: { displayName: "${owner}", groups: ${groups}, source: local }
YAML
  CREATED_USERS+=("$owner")
  name="iam-ak-$(printf '%s' "$ak" | sha256sum | cut -c1-40)"
  kubectl -n "$SHIM_NS" create secret generic "$name" --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" \
    --from-literal=owner="$owner" >/dev/null || inconclusive "could not create the access key"
  CREATED_KEYS+=("$name")
  MK_AK="$ak"; MK_SK="$sk"
}

log "seeding an administrator and a principal with no policy"
mint_key "$ADMIN" "admins"; AAK="$MK_AK"; ASK="$MK_SK"
mint_key "$NOPOL"; NAK="$MK_AK"; NSK="$MK_SK"
log "waiting 35s for the IAM policy world to load them"
sleep 35

# --- 1. the stack ----------------------------------------------------------------------------------------
cat > "$TMP/template.yaml" <<YAML
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Logs:
    Type: AWS::Logs::LogGroup
    Properties: { LogGroupName: "${GROUP}" }
  Cluster:
    Type: AWS::ECS::Cluster
    Properties: { ClusterName: "${CLUSTER}" }
  TaskRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement: [{ Effect: Allow, Principal: { Service: ecs-tasks.amazonaws.com }, Action: "sts:AssumeRole" }]
  Task:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: "${FAMILY}"
      Cpu: "256"
      Memory: "512"
      TaskRoleArn: !GetAtt TaskRole.Arn
      ContainerDefinitions:
        - Name: web
          Image: "${IMAGE}"
          Essential: true
          PortMappings: [{ ContainerPort: 80 }]
          LogConfiguration:
            LogDriver: awslogs
            Options:
              awslogs-group: !Ref Logs
              awslogs-region: !Ref AWS::Region
              awslogs-stream-prefix: web
  Service:
    Type: AWS::ECS::Service
    Properties:
      ServiceName: "${SERVICE}"
      Cluster: !Ref Cluster
      TaskDefinition: !Ref Task
      DesiredCount: 1
YAML
log "the administrator creates stack ${STACK}: a log group, cluster ${CLUSTER}, a task role, a sized task definition logging with awslogs, service ${SERVICE}"
as "$AAK" "$ASK" cloudformation create-stack --stack-name "$STACK" --template-body "file://$TMP/template.yaml" \
  --capabilities CAPABILITY_IAM >/dev/null 2>"$TMP/cs" || fail "create-stack refused: $(head -c 400 "$TMP/cs")"
MADE_STACK=1
status=""
for _ in $(seq 1 90); do
  status="$(as "$AAK" "$ASK" cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' 2>/dev/null)"
  case "$status" in CREATE_COMPLETE|*FAILED|ROLLBACK*) break ;; esac
  sleep 5
done
if [ "$status" != CREATE_COMPLETE ]; then
  as "$AAK" "$ASK" cloudformation describe-stack-events --stack-name "$STACK" \
    --query 'StackEvents[?contains(ResourceStatus, `FAILED`)].[LogicalResourceId,ResourceStatusReason]' 2>/dev/null | head -5 >&2
  fail "stack ${STACK} is ${status:-unknown}, not CREATE_COMPLETE"
fi
log "  ✓ CREATE_COMPLETE"

# --- 2. ECS reports the stack's cluster and service ------------------------------------------------------
as "$AAK" "$ASK" ecs list-clusters --query 'clusterArns' | tr '\t' '\n' | grep -q ":cluster/${CLUSTER}\$" \
  || fail "ListClusters does not list the stack's cluster ${CLUSTER}"
[ "$(as "$AAK" "$ASK" ecs describe-clusters --clusters "$CLUSTER" --query 'clusters[0].status' 2>/dev/null)" = ACTIVE ] \
  || fail "DescribeClusters does not report ${CLUSTER} ACTIVE"
as "$AAK" "$ASK" ecs list-services --cluster "$CLUSTER" --query 'serviceArns' | tr '\t' '\n' | grep -q ":service/${CLUSTER}/${SERVICE}\$" \
  || fail "ListServices --cluster ${CLUSTER} does not list the stack's service"
log "  ✓ ListClusters, DescribeClusters and ListServices report the stack's cluster and service"
td="$(as "$AAK" "$ASK" ecs describe-task-definition --task-definition "$FAMILY" \
  --query 'taskDefinition.[family,revision,cpu,memory,containerDefinitions[0].logConfiguration.options."awslogs-group"]' 2>/dev/null | tr '\t' ' ')"
[ "$td" = "${FAMILY} 1 256 512 ${GROUP}" ] || fail "DescribeTaskDefinition of the stack's task definition = '${td}', want '${FAMILY} 1 256 512 ${GROUP}'"
log "  ✓ DescribeTaskDefinition describes the stack's task definition (${FAMILY}:1, 256 / 512, awslogs ${GROUP})"

st=""
for _ in $(seq 1 60); do
  st="$(as "$AAK" "$ASK" ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" \
    --query 'services[0].[runningCount,pendingCount,deployments[0].status,taskDefinition]' 2>/dev/null | tr '\t' ' ')"
  case "$st" in "1 0 PRIMARY "*) break ;; esac
  sleep 5
done
case "$st" in
  "1 0 PRIMARY "*":task-definition/${FAMILY}:1") log "  ✓ DescribeServices: runningCount 1, a PRIMARY deployment, task definition ${FAMILY}:1" ;;
  *) as "$AAK" "$ASK" ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" --output json 2>&1 | head -c 600 >&2
     fail "DescribeServices of the stack's service = '${st}', want running 1, pending 0, PRIMARY, ${FAMILY}:1" ;;
esac

tasks="$(as "$AAK" "$ASK" ecs list-tasks --cluster "$CLUSTER" --service-name "$SERVICE" --query 'taskArns' 2>/dev/null | tr '\t' '\n' | grep -c ":task/${CLUSTER}/")"
[ "$tasks" = 1 ] || fail "ListTasks lists ${tasks} tasks of the service, want 1"
task="$(as "$AAK" "$ASK" ecs list-tasks --cluster "$CLUSTER" --service-name "$SERVICE" --query 'taskArns[0]' 2>/dev/null)"
dt="$(as "$AAK" "$ASK" ecs describe-tasks --cluster "$CLUSTER" --tasks "$task" \
  --query 'tasks[0].[lastStatus,group,taskDefinitionArn,containers[0].name]' 2>/dev/null | tr '\t' ' ')"
case "$dt" in
  "RUNNING service:${SERVICE} "*":task-definition/${FAMILY}:1 web") ;;
  *) fail "DescribeTasks of the service's task = '${dt}', want RUNNING service:${SERVICE} ${FAMILY}:1 web" ;;
esac
counts="$(as "$AAK" "$ASK" ecs describe-clusters --clusters "$CLUSTER" \
  --query 'clusters[0].[activeServicesCount,runningTasksCount,pendingTasksCount]' 2>/dev/null | tr '\t' ' ')"
[ "$counts" = "1 1 0" ] || fail "DescribeClusters counts '${counts}', want 1 service, 1 running task, 0 pending"
log "  ✓ ListTasks and DescribeTasks report the service's RUNNING task; DescribeClusters counts 1 service, 1 running task"

# --- 3. its container's logs are in the stack's log group ------------------------------------------------
stream=""; events=""
for _ in $(seq 1 36); do
  stream="$(as "$AAK" "$ASK" logs describe-log-streams --log-group-name "$GROUP" --query 'logStreams[0].logStreamName' 2>/dev/null)"
  if [ -n "$stream" ] && [ "$stream" != None ]; then
    events="$(as "$AAK" "$ASK" logs get-log-events --log-group-name "$GROUP" --log-stream-name "$stream" \
      --start-from-head --query 'events[].message' 2>/dev/null)"
    [ -n "$events" ] && break
  fi
  sleep 5
done
case "$stream" in web/web/*) ;; *) fail "the stack's log group ${GROUP} has no stream web/web/<task id> (got '${stream}')" ;; esac
[ -n "$events" ] || fail "stream ${stream} of ${GROUP} has no events: the container's output is not in the stack's log group"
log "  ✓ CloudWatch Logs: the container's output is in ${GROUP}, stream ${stream}"

# --- 4. the task's size and role (the operator's view of its Application) -------------------------------
app="$(kubectl -n "$STACK_NS" get applications.openinfra.dev -o jsonpath="{range .items[?(@.spec.logGroup==\"${GROUP}\")]}{.metadata.name}{end}" 2>/dev/null)"
[ -n "$app" ] || inconclusive "the stack's Application is not readable in ${STACK_NS} (KUBECONFIG?)"
size="$(kubectl -n "$STACK_NS" get applications.openinfra.dev "$app" -o jsonpath='{.spec.cpu} {.spec.memory}')"
[ "$size" = "250m 512Mi" ] || fail "the task is sized '${size}', want the task definition's 250m 512Mi"
role="$(as "$AAK" "$ASK" cloudformation describe-stack-resource --stack-name "$STACK" --logical-resource-id TaskRole \
  --query 'StackResourceDetail.PhysicalResourceId' 2>/dev/null)"
assumed="$(kubectl -n "$STACK_NS" get applications.openinfra.dev "$app" -o jsonpath='{.spec.assumeRole}')"
[ -n "$role" ] && [ "$assumed" = "$role" ] || fail "the task runs as role '${assumed}', want the stack's task role '${role}'"
log "  ✓ the task is sized 250m / 512Mi and runs as the stack's task role ${role}"

# --- 5. an UPDATE change set: AWS's Replacement, executed with ExecuteChangeSet alone ---------------------
sed -e 's/Cpu: "256"/Cpu: "512"/' -e 's/Memory: "512"/Memory: "1024"/' "$TMP/template.yaml" > "$TMP/template2.yaml"
as "$AAK" "$ASK" cloudformation create-change-set --stack-name "$STACK" --change-set-name resize \
  --template-body "file://$TMP/template2.yaml" --capabilities CAPABILITY_IAM >/dev/null 2>"$TMP/ccs" \
  || fail "create-change-set refused: $(head -c 300 "$TMP/ccs")"
cs=""
for _ in $(seq 1 24); do
  cs="$(as "$AAK" "$ASK" cloudformation describe-change-set --stack-name "$STACK" --change-set-name resize --output json 2>/dev/null)"
  [ "$(printf '%s' "$cs" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("Status",""))' 2>/dev/null)" = CREATE_COMPLETE ] && break
  sleep 5
done
rep="$(printf '%s' "$cs" | python3 -c '
import json, sys
for c in json.load(sys.stdin).get("Changes", []):
    rc = c["ResourceChange"]
    if rc["LogicalResourceId"] == "Task":
        d = sorted((x["Target"]["Name"], x["Target"]["RequiresRecreation"]) for x in rc.get("Details", []))
        print(rc["Action"], rc.get("Replacement"), " ".join(n + "=" + r for n, r in d))' 2>/dev/null)"
[ "$rep" = "Modify True Cpu=Always Memory=Always" ] || fail "the change set reports the task definition as '${rep}', want Modify True Cpu=Always Memory=Always"
log "  ✓ the change set reports the task definition replaced (Replacement True; Cpu, Memory RequiresRecreation Always)"

ME="$(as "$AAK" "$ASK" sts get-caller-identity --query Arn)"; ACCT="$(as "$AAK" "$ASK" sts get-caller-identity --query Account)"
as "$AAK" "$ASK" iam create-role --role-name "$DEPLOYER" --assume-role-policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"'"$ME"'"},"Action":"sts:AssumeRole"}]}' >/dev/null 2>"$TMP/cr" \
  || fail "create-role ${DEPLOYER}: $(head -c 300 "$TMP/cr")"
MADE_ROLE=1
as "$AAK" "$ASK" iam put-role-policy --role-name "$DEPLOYER" --policy-name deploy --policy-document '{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":["cloudformation:ExecuteChangeSet","cloudformation:DescribeChangeSet","cloudformation:DescribeStacks",
   "cloudformation:DescribeStackEvents","ecs:*","logs:*","iam:GetRole","iam:PassRole"],"Resource":"*"},
 {"Effect":"Deny","Action":["cloudformation:UpdateStack","cloudformation:CreateStack"],"Resource":"*"}]}' >/dev/null \
  || fail "put-role-policy ${DEPLOYER}"
log "waiting 35s for the IAM policy world to load ${DEPLOYER} (ExecuteChangeSet allowed, UpdateStack denied)"
sleep 35
read -r RAK RSK RTOK <<<"$(as "$AAK" "$ASK" sts assume-role --role-arn "arn:aws:iam::${ACCT}:role/${DEPLOYER}" --role-session-name probe \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' 2>"$TMP/ar")"
[ -n "${RTOK:-}" ] || fail "assume-role ${DEPLOYER}: $(head -c 300 "$TMP/ar")"
role() { AWS_ACCESS_KEY_ID="$RAK" AWS_SECRET_ACCESS_KEY="$RSK" AWS_SESSION_TOKEN="$RTOK" AWS_REGION="$REGION" \
  aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$@"; }
if role cloudformation update-stack --stack-name "$STACK" --template-body "file://$TMP/template2.yaml" --capabilities CAPABILITY_IAM >/dev/null 2>"$TMP/us"; then
  fail "${DEPLOYER} updated the stack directly, though its policy denies cloudformation:UpdateStack"
fi
grep -q AccessDenied "$TMP/us" || fail "UpdateStack as ${DEPLOYER} failed without AccessDenied: $(head -c 300 "$TMP/us")"
role cloudformation execute-change-set --stack-name "$STACK" --change-set-name resize >/dev/null 2>"$TMP/ecs" \
  || fail "execute-change-set as ${DEPLOYER} (ExecuteChangeSet allowed, UpdateStack denied) refused: $(head -c 400 "$TMP/ecs")"
status=""
for _ in $(seq 1 90); do
  status="$(as "$AAK" "$ASK" cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' 2>/dev/null)"
  case "$status" in UPDATE_COMPLETE|*FAILED|*ROLLBACK*) break ;; esac
  sleep 5
done
[ "$status" = UPDATE_COMPLETE ] || fail "the stack is ${status:-unknown} after executing the change set, not UPDATE_COMPLETE"
size="$(kubectl -n "$STACK_NS" get applications.openinfra.dev "$app" -o jsonpath='{.spec.cpu} {.spec.memory}')"
[ "$size" = "500m 1024Mi" ] || fail "after the change set the task is sized '${size}', want 500m 1024Mi"
log "  ✓ ${DEPLOYER} (UpdateStack denied: AccessDenied) executed the change set: UPDATE_COMPLETE, the task resized to 500m / 1024Mi"

# --- 6. STANDARD waits for the service's steady state; EXPRESS completes once applied -------------------
stack_wait() { # <want>: the stack's status once it settles, as UPDATE_COMPLETE or a failure
  local st=""
  for _ in $(seq 1 120); do
    st="$(as "$AAK" "$ASK" cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' 2>/dev/null)"
    case "$st" in *_COMPLETE|*FAILED) break ;; esac
    sleep 3
  done
  echo "$st"
}
sed -e 's/DesiredCount: 1/DesiredCount: 2/' "$TMP/template2.yaml" > "$TMP/template3.yaml"
as "$AAK" "$ASK" cloudformation update-stack --stack-name "$STACK" --template-body "file://$TMP/template3.yaml" --capabilities CAPABILITY_IAM \
  >/dev/null 2>"$TMP/u3" || fail "update-stack DesiredCount 2: $(head -c 300 "$TMP/u3")"
[ "$(stack_wait)" = UPDATE_COMPLETE ] || fail "the DesiredCount 2 update did not complete"
st="$(as "$AAK" "$ASK" ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" --query 'services[0].[runningCount,pendingCount]' 2>/dev/null | tr '\t' ' ')"
[ "$st" = "2 0" ] || fail "the stack reported UPDATE_COMPLETE with the service at running pending = ${st}: STANDARD mode must wait for its steady state"
log "  ✓ STANDARD: the update completed only once the service was steady (running 2, pending 0)"
sed -e 's/DesiredCount: 1/DesiredCount: 3/' "$TMP/template2.yaml" > "$TMP/template4.yaml"
as "$AAK" "$ASK" cloudformation update-stack --stack-name "$STACK" --template-body "file://$TMP/template4.yaml" --capabilities CAPABILITY_IAM \
  --deployment-config '{"Mode": "EXPRESS"}' >/dev/null 2>"$TMP/u4" || fail "update-stack in EXPRESS mode: $(head -c 300 "$TMP/u4")"
[ "$(stack_wait)" = UPDATE_COMPLETE ] || fail "the EXPRESS update did not complete"
st=""
for _ in $(seq 1 40); do
  st="$(as "$AAK" "$ASK" ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" --query 'services[0].runningCount' 2>/dev/null)"
  [ "$st" = 3 ] && break
  sleep 3
done
[ "$st" = 3 ] || fail "after the EXPRESS update the service never reached 3 tasks (running ${st})"
log "  ✓ EXPRESS: the update completed once applied, and the service reached its 3 tasks in the background"

# --- 7. a principal with no policy is refused ------------------------------------------------------------
denied() { # <what> <command...>: the call must fail with AWS's access-denied error
  local what="$1"; shift
  if as "$NAK" "$NSK" "$@" >/dev/null 2>"$TMP/deny"; then fail "${what} was allowed for a principal with no policy"; fi
  grep -qE 'AccessDenied' "$TMP/deny" || fail "${what} failed without AWS's access-denied error: $(head -c 300 "$TMP/deny")"
}
denied "ecs:DescribeServices" ecs describe-services --cluster "$CLUSTER" --services "$SERVICE"
denied "logs:GetLogEvents" logs get-log-events --log-group-name "$GROUP" --log-stream-name "$stream"
log "  ✓ a principal with no policy is refused DescribeServices and GetLogEvents (AccessDenied)"

printf '\n✓ PASS: a stack-made ECS service is an ECS service: its cluster, service and tasks are listed and described, its container logs to the stack'"'"'s log group, it is sized and runs as its task definition says, a change set reports AWS'"'"'s Replacement and executes with ExecuteChangeSet alone, and a principal with no policy is refused\n'
