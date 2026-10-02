#!/usr/bin/env bash
# Compatibility probe for the aws-shim ECS surface (polyhedron#177).
#
# The ECS front door collates an ECS service + its referenced task definition into ONE kind: Application
# (Deployment + Service + Ingress + HPA) through the owned cfn engine, provisioning under the CALLER's own
# authority via k8s impersonation (the same seam as the CloudFormation doorway, polyhedron#175). This probe
# fires REAL `aws ecs` SDK calls at a deployed shim and asserts, end to end:
#
#   - the create→run→describe path: RegisterTaskDefinition (one PUBLIC-image container + a containerPort)
#     returns a task-def ARN at :1; CreateService provisions a kind: Application that becomes Ready; and
#     DescribeServices reports desiredCount==runningCount==1 (an honest "running == desired once Ready",
#     derived from the Application's own readiness, not a fabricated live count); DeleteService removes it
#   - AUTHORITY (the #177 proof): a READER caller's identical CreateService is refused / provisions NOTHING,
#     because the service is created AS the reader (who cannot create applications), never as the shim — the
#     confused-deputy blast radius is structurally impossible (mirrors cloudformation.sh's reader test)
#   - UNSUPPORTED refused, nothing created: a Fargate service with a raw/opaque awsvpc `subnet-…` is refused
#     synchronously at the fail-closed gate (BuildPlan + the translate gate via BuildChangeSet, which applies
#     nothing), and RunTask (a one-off task has no long-lived Application form) is refused — in both cases no
#     kind: Application and no service record are left behind
#   - a valid key id with a WRONG secret on a management call → signature mismatch
#
# On-demand (needs a deployed shim with the ECS front door + impersonation RBAC, the cfn engine, and the
# kind: Application XRD/composition, plus openinfra:admins + openinfra:readers callers). Exit 0 = pass,
# 1 = a real fidelity/enforcement failure, 42 = INCONCLUSIVE (a prerequisite was missing, so nothing was
# proven — neither green nor red). Per polyhedron#157, a probe failure is presumed a shim defect.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-ecs.sh   # e.g. behind a kubectl port-forward
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ECS_NS="${ECS_NAMESPACE:-open-infra-ecs}"   # where the kind: Application + the ecs-* bookkeeping CMs land
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
# A PUBLIC image (like the Lambda / API Gateway probes): the resulting Deployment is pulled anonymously by
# containerd, so a private registry would never become Ready in a self-contained probe.
ECS_IMAGE="${ECS_IMAGE:-nginx:1.27-alpine}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"
kubectl get crd applications.openinfra.dev >/dev/null 2>&1 || inconclusive "the kind: Application XRD is not installed (ECS collates into it)"

TD_FAM="ecsprobe-td-$SFX"
POS_SVC="ecsprobe-svc-$SFX"
READER_SVC="ecsprobe-reader-$SFX"
RAW_SVC="ecsprobe-raw-$SFX"
CREATED_USERS=(); CREATED_KEYS=(); CREATED_SVCS=("$POS_SVC" "$READER_SVC" "$RAW_SVC")
AAK=""; ASK=""; RAK=""; RSK=""

# ecs_name mirrors cfn.k8sName exactly (lowercase, invalid runs -> "-", trimmed), so an ECS service name
# resolves to the SAME object name the cfn engine derives for the Application it creates.
ecs_name()   { printf '%s' "$1" | tr 'A-Z' 'a-z' | sed -E 's/[^a-z0-9-]+/-/g; s/^-+//; s/-+$//'; }
service_cm() { printf 'ecs-service-%s' "$(ecs_name "$1")"; }
taskdef_cm() { printf 'ecs-taskdef-%s-%s' "$(ecs_name "$1")" "$2"; }
app_exists() { kubectl -n "$ECS_NS" get application.openinfra.dev "$1" >/dev/null 2>&1; }
cm_exists()  { kubectl -n "$ECS_NS" get configmap "$1" >/dev/null 2>&1; }

ecs() { # <ak> <sk> -- <ecs args...>
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager ecs "$@"
}

cleanup() {
  if [ -n "$AAK" ]; then
    ecs "$AAK" "$ASK" delete-service --service "$POS_SVC" >/dev/null 2>&1 || true
    ecs "$AAK" "$ASK" deregister-task-definition --task-definition "$TD_FAM:1" >/dev/null 2>&1 || true
  fi
  sleep 2
  # belt-and-suspenders: remove anything this probe could have left in the ECS namespace
  for s in "${CREATED_SVCS[@]:-}"; do
    [ -n "$s" ] || continue
    kubectl -n "$ECS_NS" delete application.openinfra.dev "$(ecs_name "$s")" --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$ECS_NS" delete configmap "$(service_cm "$s")" --ignore-not-found >/dev/null 2>&1 || true
  done
  kubectl -n "$ECS_NS" delete configmap "$(taskdef_cm "$TD_FAM" 1)" --ignore-not-found >/dev/null 2>&1 || true
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for k in "${CREATED_KEYS[@]:-}";  do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
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
  CREATED_USERS+=("$owner")
  local name; name="$(secret_name "$ak")"
  kubectl -n "$SHIM_NS" create secret generic "$name" \
    --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  CREATED_KEYS+=("$name")
  printf '%s %s' "$ak" "$sk"
}

# --- seed callers -----------------------------------------------------------------------------------
log "seeding an openinfra:admins caller and an openinfra:readers caller"
read -r AAK ASK <<<"$(mint_key "ecsprobe-admin-$SFX"  "admins")"
read -r RAK RSK <<<"$(mint_key "ecsprobe-reader-$SFX" "readers")"
[ -n "$AAK" ] && [ -n "$RAK" ] || inconclusive "failed to mint caller keys"
sleep 2

# --- gate: the ECS front door must be enabled -------------------------------------------------------
# A signed ecs call to a shim that does not front ECS returns an honest 501 (NotImplemented / not fronted).
if ! ecs "$AAK" "$ASK" list-clusters >/dev/null 2>"$TMP/en.err"; then
  grep -qiE 'NotImplemented|not fronted' "$TMP/en.err" && inconclusive "the ECS front door is not enabled on this shim"
  inconclusive "ECS list-clusters failed, cannot confirm the front door: $(cat "$TMP/en.err")"
fi

# --- 1. positive: register task def -> create service -> Ready -> describe ---------------------------
log "register-task-definition ${TD_FAM}: one public-image container (${ECS_IMAGE}) + containerPort 80"
TDARN="$(ecs "$AAK" "$ASK" register-task-definition --family "$TD_FAM" \
  --container-definitions "[{\"name\":\"web\",\"image\":\"${ECS_IMAGE}\",\"portMappings\":[{\"containerPort\":80}]}]" \
  --query 'taskDefinition.taskDefinitionArn' --output text 2>"$TMP/td.err")" \
  || fail "register-task-definition failed: $(cat "$TMP/td.err")"
case "$TDARN" in
  *":task-definition/${TD_FAM}:1") : ;;
  *) fail "register-task-definition returned an unexpected arn: '$TDARN' (want …/task-definition/${TD_FAM}:1)";;
esac
log "    ✓ ${TDARN}"

log "create-service ${POS_SVC} --task-definition ${TD_FAM}:1 --desired-count 1"
SVCARN="$(ecs "$AAK" "$ASK" create-service --service-name "$POS_SVC" --task-definition "$TD_FAM:1" --desired-count 1 \
  --query 'service.serviceArn' --output text 2>"$TMP/cs.err")" \
  || fail "create-service failed: $(cat "$TMP/cs.err")"
case "$SVCARN" in
  *":service/"*"/${POS_SVC}") : ;;
  *) fail "create-service returned an unexpected serviceArn: '$SVCARN' (want …:service/<cluster>/${POS_SVC})";;
esac
log "    ✓ ${SVCARN}"

# The composite is created ASYNChronously by the caller-impersonating applier (claim -> engine Deploy), so
# it does not exist the instant CreateService returns. `kubectl wait` on a not-yet-created object errors
# NotFound and exits immediately, so wait for CREATION first, then readiness.
APP="$(ecs_name "$POS_SVC")"
log "  waiting for kind: Application ${APP} to be created (async, under the caller's authority)..."
i=0; created=0
while [ "$i" -lt 180 ]; do
  if app_exists "$APP"; then created=1; break; fi
  sleep 3; i=$((i+3))
done
[ "$created" = 1 ] || fail "kind: Application ${APP} was never created (the caller-authority deploy did not run)"

log "  waiting for ${APP} to become Ready (the composite is Ready when its Deployment's replicas are available)..."
i=0; ready=0
while [ "$i" -lt 180 ]; do
  rd="$(kubectl -n "$ECS_NS" get application.openinfra.dev "$APP" -o jsonpath='{.status.ready}' 2>/dev/null || true)"
  rc="$(kubectl -n "$ECS_NS" get application.openinfra.dev "$APP" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
  { [ "$rd" = "true" ] || [ "$rc" = "True" ]; } && { ready=1; break; }
  sleep 4; i=$((i+4))
done
[ "$ready" = 1 ] || fail "kind: Application ${APP} did not become Ready within 180s"

log "  describe-services ${POS_SVC} → desiredCount==1 and runningCount==1 (running == desired once Ready)"
i=0; dc=""; rcnt=""
while [ "$i" -lt 60 ]; do
  dc="$(ecs "$AAK" "$ASK" describe-services --services "$POS_SVC" --query 'services[0].desiredCount' --output text 2>/dev/null || true)"
  rcnt="$(ecs "$AAK" "$ASK" describe-services --services "$POS_SVC" --query 'services[0].runningCount' --output text 2>/dev/null || true)"
  [ "$dc" = "1" ] && [ "$rcnt" = "1" ] && break
  sleep 4; i=$((i+4))
done
[ "$dc" = "1" ]   || fail "describe-services desiredCount='$dc', want 1 (the service was not read back faithfully)"
[ "$rcnt" = "1" ] || fail "describe-services runningCount='$rcnt', want 1 (the service never reported its desired replicas Ready)"
log "    ✓ Application Ready; describe-services desiredCount=1, runningCount=1"

# --- 2. teardown removes what was created ----------------------------------------------------------
log "delete-service ${POS_SVC} → the kind: Application is deleted"
ecs "$AAK" "$ASK" delete-service --service "$POS_SVC" >/dev/null 2>"$TMP/del.err" || fail "delete-service failed: $(cat "$TMP/del.err")"
i=0; gone=0
while [ "$i" -lt 150 ]; do
  app_exists "$APP" || { gone=1; break; }
  sleep 4; i=$((i+4))
done
[ "$gone" = 1 ] || fail "kind: Application ${APP} still present after delete-service"
log "    ✓ service destroyed (Application gone)"

# --- 3. AUTHORITY — a reader's identical service provisions NOTHING ----------------------------------
log "authority: a READER caller's create-service provisions nothing (it runs AS the reader, not the shim)"
if ecs "$RAK" "$RSK" create-service --service-name "$READER_SVC" --task-definition "$TD_FAM:1" --desired-count 1 \
    >/dev/null 2>"$TMP/auth.err"; then
  # Accepted async (like AWS): the proof is then that NO Application is EVER created under the reader's authority.
  log "    create-service accepted async — asserting NO kind: Application is created under the reader's authority"
  i=0; while [ "$i" -lt 60 ]; do
    app_exists "$(ecs_name "$READER_SVC")" && fail "the reader provisioned a kind: Application it lacks authority for (confused deputy — the service ran as the shim, not the reader!)"
    sleep 4; i=$((i+4))
  done
else
  grep -qiE 'AccessDenied|denied|forbidden' "$TMP/auth.err" || fail "reader create-service refused with the wrong error: $(cat "$TMP/auth.err")"
fi
# In both branches: nothing created for the reader.
app_exists "$(ecs_name "$READER_SVC")" && fail "a kind: Application exists for the denied reader (nothing should be created)"
cm_exists  "$(service_cm "$READER_SVC")" && fail "a service record exists for the denied reader (nothing should be created)"
log "    ✓ reader provisions nothing — no Application, no service record (service runs under the CALLER's authority)"

# --- 4. UNSUPPORTED refused WHOLE at the gate, nothing created ---------------------------------------
log "unsupported refused: a Fargate service with a raw/opaque awsvpc subnet is refused at the gate, nothing created"
if ecs "$AAK" "$ASK" create-service --service-name "$RAW_SVC" --task-definition "$TD_FAM:1" --desired-count 1 \
    --launch-type FARGATE \
    --network-configuration '{"awsvpcConfiguration":{"subnets":["subnet-0abc123def4567890"],"assignPublicIp":"ENABLED"}}' \
    >/dev/null 2>"$TMP/raw.err"; then
  fail "create-service with a raw awsvpc subnet was ACCEPTED (must refuse synchronously at the gate)"
fi
grep -qiE 'refused|raw AWS subnet|subnet|REJECTED|InvalidParameter' "$TMP/raw.err" \
  || fail "raw-subnet refusal had the wrong error: $(cat "$TMP/raw.err")"
app_exists "$(ecs_name "$RAW_SVC")" && fail "a kind: Application was created despite the gate refusal (partial creation!)"
cm_exists  "$(service_cm "$RAW_SVC")" && fail "a service record was left behind for a refused service"
log "    ✓ raw-subnet service refused at the gate — no Application, no service record"

log "unsupported refused: RunTask (a one-off task has no long-lived kind: Application form)"
if ecs "$AAK" "$ASK" run-task --task-definition "$TD_FAM:1" >/dev/null 2>"$TMP/run.err"; then
  fail "run-task was ACCEPTED (a one-off task has no open-infra Application form; it must refuse)"
fi
grep -qiE 'Application form|RunTask|InvalidParameter|CreateService' "$TMP/run.err" \
  || fail "run-task refusal had the wrong error: $(cat "$TMP/run.err")"
log "    ✓ RunTask refused (use CreateService) — nothing created"

# --- 5. negative: wrong SigV4 secret ---------------------------------------------------------------
log "negative: a valid key id with a WRONG secret on a management call → signature mismatch"
if ecs "$AAK" "wrong-secret-not-the-real-one" list-clusters >/dev/null 2>"$TMP/sig.err"; then
  fail "a wrong secret was accepted on a management call"
fi
grep -qiE 'Signature|does not match' "$TMP/sig.err" || fail "wrong-secret rejection had the wrong error: $(cat "$TMP/sig.err")"
log "    ✓ rejected on signature mismatch"

printf '\n✓ PASS — aws-shim ECS is faithful: an ECS service + task definition collate into one kind: Application (register → create → Ready → describe desiredCount==runningCount==1 → delete), a service provisions under the CALLER'"'"'s own authority (a reader provisions nothing — never the shim'"'"'s, closing the confused-deputy blast radius), and unsupported surface is refused synchronously with nothing created (a raw awsvpc subnet at the translate gate; RunTask has no Application form), with the auth/refusal boundaries enforced.\n'
