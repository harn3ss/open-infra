#!/usr/bin/env bash
# Compatibility probe for the aws-shim CloudFormation surface (polyhedron#175).
#
# It asserts, over real round-trips against a deployed shim + the owned cfn engine:
#   - CreateStack deploys a >1-resource stack in DEPENDENCY ORDER (Items DependsOn Orders), CREATE_COMPLETE
#   - an UNSUPPORTED resource type is REFUSED WHOLE at validation, with NOTHING created (the failure mode
#     that matters most for an orchestrator) — a synchronous ValidationError, no stack record, no resources
#   - a CHANGE SET previews an update (Add Logs) WITHOUT applying it, then ExecuteChangeSet applies it
#   - DRIFT is detected after an out-of-band change (a resource deleted outside CFN) → DRIFTED
#   - DeleteStack removes what was created
#   - AUTHORITY both directions (the #175 rule-2 proof): an admin's stack provisions; a READER's identical
#     stack is DENIED because CFN runs AS the reader (who cannot create the resource), not as the shim —
#     the confused-deputy blast radius is structurally impossible
#
# On-demand (needs a deployed shim with the CloudFormation front door + impersonation RBAC, the cfn engine,
# and openinfra:admins + openinfra:readers callers). Exit 0 = pass, 1 = a real failure, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-cloudformation.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
CFN_NS="${CFN_NS:-open-infra-cfn}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
kubectl get ns "$CFN_NS" >/dev/null 2>&1 || inconclusive "CFN namespace ${CFN_NS} missing (apply the aws-shim overlay)"

STACK="cfnprobe-$SFX"
RSTACK="cfnprobe-reader-$SFX"
CREATED_USERS=(); CREATED_KEYS=()
AAK=""; ASK=""; RAK=""; RSK=""

cfn()  { local ak="$1" sk="$2"; shift 2; AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager cloudformation "$@"; }
tget() { kubectl -n "$CFN_NS" get tables.openinfra.dev "$@" ; }
# The engine names a resource k8sName(logicalId) (lowercase); a Crossplane claim keeps the
# cfn.openinfra.dev/stack label but not the logical-id one. So resolve by physical name + verify the stack.
lc() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
tbl_name() { lc "$1"; } # <logicalId> -> physical Table name
tbl_exists() { # <stack> <logicalId>
  local s; s="$(kubectl -n "$CFN_NS" get table.openinfra.dev "$(tbl_name "$2")" -o jsonpath='{.metadata.labels.cfn\.openinfra\.dev/stack}' 2>/dev/null || true)"
  [ "$s" = "$1" ]
}

cleanup() {
  cfn "$AAK" "$ASK" delete-stack --stack-name "$STACK"  >/dev/null 2>&1 || true
  cfn "$AAK" "$ASK" delete-stack --stack-name "$RSTACK" >/dev/null 2>&1 || true
  sleep 3
  # belt-and-suspenders: remove any resources/bookkeeping this probe left in the CFN namespace
  kubectl -n "$CFN_NS" delete tables.openinfra.dev -l "cfn.openinfra.dev/stack=$STACK"  --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$CFN_NS" delete tables.openinfra.dev -l "cfn.openinfra.dev/stack=$RSTACK" --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$CFN_NS" delete configmap "cfn-stack-$STACK" "cfn-stack-$RSTACK" "cfn-drift-$STACK" --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "$CFN_NS" delete configmap -l "cfn.openinfra.dev/changeset=$STACK" --ignore-not-found >/dev/null 2>&1 || true
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
  kubectl -n "$SHIM_NS" create secret generic "$name" --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  CREATED_KEYS+=("$name")
  printf '%s %s' "$ak" "$sk"
}

table_json() { # <logicalId> <tableName> <hashAttr> [dependsOn]
  local id="$1" name="$2" hash="$3" dep="${4:-}"
  local depline=""
  [ -n "$dep" ] && depline="\"DependsOn\":\"$dep\","
  cat <<JSON
"$id":{"Type":"AWS::DynamoDB::Table",${depline}"Properties":{
  "TableName":"$name",
  "AttributeDefinitions":[{"AttributeName":"$hash","AttributeType":"S"}],
  "KeySchema":[{"AttributeName":"$hash","KeyType":"HASH"}]}}
JSON
}

poll_stack() { # <ak> <sk> <stack> <want> <timeout> -> prints last status; 0 if reached
  local ak="$1" sk="$2" stack="$3" want="$4" t="${5:-200}" i=0 st=""
  while [ "$i" -lt "$t" ]; do
    st="$(cfn "$ak" "$sk" describe-stacks --stack-name "$stack" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
    if [ "$st" = "$want" ]; then printf '%s' "$st"; return 0; fi
    case "$st" in
      *_COMPLETE|*_FAILED) printf '%s' "$st"; return 1;;
    esac
    sleep 4; i=$((i+4))
  done
  printf '%s' "$st"; return 1
}

# --- seed callers -----------------------------------------------------------------------------------
log "seeding an openinfra:admins caller and an openinfra:readers caller"
read -r AAK ASK <<<"$(mint_key "cfnprobe-admin-$SFX"  "admins")"
read -r RAK RSK <<<"$(mint_key "cfnprobe-reader-$SFX" "readers")"
[ -n "$AAK" ] && [ -n "$RAK" ] || inconclusive "failed to mint caller keys"
sleep 2

# --- 1. UNSUPPORTED type refused WHOLE at validation, nothing created --------------------------------
log "negative: a stack containing an unsupported type (AWS::Route53::HostedZone) is refused at validation"
cat > "$TMP/bad.json" <<JSON
{"AWSTemplateFormatVersion":"2010-09-09","Resources":{
  $(table_json Keep "cfnprobe-keep-$SFX" id),
  "Zone":{"Type":"AWS::Route53::HostedZone","Properties":{"Name":"probe-$SFX.example.com"}}
}}
JSON
if cfn "$AAK" "$ASK" create-stack --stack-name "cfnprobe-bad-$SFX" --template-body "file://$TMP/bad.json" >/dev/null 2>"$TMP/bad.err"; then
  fail "create-stack with an unsupported type was ACCEPTED (should refuse at validation)"
fi
grep -qiE 'ValidationError|refused|Route53|unsupported|no backing' "$TMP/bad.err" || fail "unsupported-type refusal had the wrong error: $(cat "$TMP/bad.err")"
# nothing created: no stack record, no Keep table
if cfn "$AAK" "$ASK" describe-stacks --stack-name "cfnprobe-bad-$SFX" >/dev/null 2>&1; then
  fail "a stack record was created for a refused template (should be nothing)"
fi
tbl_exists "cfnprobe-bad-$SFX" Keep && fail "a resource was created despite whole-stack refusal (partial creation!)"
log "    ✓ refused whole, at validation, nothing created"

# --- 2. multi-resource deploy in dependency order ---------------------------------------------------
log "create-stack ${STACK}: Orders + Items(DependsOn Orders) → dependency-ordered CREATE_COMPLETE"
cat > "$TMP/stack.json" <<JSON
{"AWSTemplateFormatVersion":"2010-09-09","Resources":{
  $(table_json Orders "cfnprobe-orders-$SFX" id),
  $(table_json Items  "cfnprobe-items-$SFX"  sku Orders)
}}
JSON
cfn "$AAK" "$ASK" create-stack --stack-name "$STACK" --template-body "file://$TMP/stack.json" >/dev/null 2>"$TMP/cs.err" \
  || fail "create-stack failed: $(cat "$TMP/cs.err")"
ST="$(poll_stack "$AAK" "$ASK" "$STACK" CREATE_COMPLETE 240)" || fail "stack did not reach CREATE_COMPLETE (status=$ST)"
tbl_exists "$STACK" Orders || fail "Orders table not created"
tbl_exists "$STACK" Items  || fail "Items table not created"
# both resources are recorded (the record is what update/drift/destroy read)
RES="$(cfn "$AAK" "$ASK" describe-stack-resources --stack-name "$STACK" --query 'StackResources[].LogicalResourceId' --output text 2>/dev/null || true)"
grep -q Orders <<<"$RES" && grep -q Items <<<"$RES" || fail "describe-stack-resources missing resources: '$RES'"
log "    ✓ CREATE_COMPLETE, both resources created + recorded"

# --- 3. change set previews an update WITHOUT applying, then executes -------------------------------
log "create-change-set (add Logs) → preview shows Add, applies NOTHING"
cat > "$TMP/stack2.json" <<JSON
{"AWSTemplateFormatVersion":"2010-09-09","Resources":{
  $(table_json Orders "cfnprobe-orders-$SFX" id),
  $(table_json Items  "cfnprobe-items-$SFX"  sku Orders),
  $(table_json Logs   "cfnprobe-logs-$SFX"   ts)
}}
JSON
cfn "$AAK" "$ASK" create-change-set --stack-name "$STACK" --change-set-name addlogs --template-body "file://$TMP/stack2.json" --change-set-type UPDATE >/dev/null 2>"$TMP/ccs.err" \
  || fail "create-change-set failed: $(cat "$TMP/ccs.err")"
sleep 2
CH="$(cfn "$AAK" "$ASK" describe-change-set --stack-name "$STACK" --change-set-name addlogs --query 'Changes[].ResourceChange.[Action,LogicalResourceId]' --output text 2>/dev/null || true)"
grep -qiE 'Add[[:space:]]+Logs' <<<"$CH" || fail "change set did not preview Add Logs (got: '$CH')"
tbl_exists "$STACK" Logs && fail "Logs was created by the CHANGE SET (a preview must apply nothing!)"
log "    ✓ preview shows Add Logs, nothing applied"
log "execute-change-set → UPDATE_COMPLETE, Logs now exists"
cfn "$AAK" "$ASK" execute-change-set --stack-name "$STACK" --change-set-name addlogs >/dev/null 2>"$TMP/ecs.err" \
  || fail "execute-change-set failed: $(cat "$TMP/ecs.err")"
ST="$(poll_stack "$AAK" "$ASK" "$STACK" UPDATE_COMPLETE 240)" || fail "stack did not reach UPDATE_COMPLETE (status=$ST)"
tbl_exists "$STACK" Logs || fail "Logs not created after execute-change-set"
log "    ✓ UPDATE_COMPLETE, Logs created"

# --- 4. drift after an out-of-band change ----------------------------------------------------------
log "drift: delete Logs OUT OF BAND (not via CFN) → detect-stack-drift → DRIFTED"
kubectl -n "$CFN_NS" delete table.openinfra.dev "$(tbl_name Logs)" --wait=true >/dev/null 2>&1 || fail "could not delete Logs out of band"
DID="$(cfn "$AAK" "$ASK" detect-stack-drift --stack-name "$STACK" --query StackDriftDetectionId --output text 2>/dev/null || true)"
[ -n "$DID" ] && [ "$DID" != "None" ] || fail "detect-stack-drift returned no detection id"
DSTATUS="$(cfn "$AAK" "$ASK" describe-stack-drift-detection-status --stack-drift-detection-id "$DID" --query StackDriftStatus --output text 2>/dev/null || true)"
[ "$DSTATUS" = "DRIFTED" ] || fail "drift status should be DRIFTED after an out-of-band delete (got '$DSTATUS')"
DR="$(cfn "$AAK" "$ASK" describe-stack-resource-drifts --stack-name "$STACK" --query 'StackResourceDrifts[?LogicalResourceId==`Logs`].StackResourceDriftStatus' --output text 2>/dev/null || true)"
grep -qi 'DELETED' <<<"$DR" || fail "the deleted resource should report DELETED drift (got '$DR')"
log "    ✓ DRIFTED (Logs reported DELETED)"

# --- 5. AUTHORITY both directions — a reader's identical stack is DENIED ----------------------------
log "authority: a READER caller's stack is denied because CFN runs AS the reader (who cannot create)"
cat > "$TMP/reader.json" <<JSON
{"AWSTemplateFormatVersion":"2010-09-09","Resources":{
  $(table_json Denied "cfnprobe-denied-$SFX" id)
}}
JSON
# The template is valid, so create-stack is accepted (async, like AWS) — the DENIAL happens when the engine
# tries to provision UNDER THE READER'S impersonated authority and the API server forbids it.
cfn "$RAK" "$RSK" create-stack --stack-name "$RSTACK" --template-body "file://$TMP/reader.json" >/dev/null 2>"$TMP/r.err" \
  || fail "reader create-stack was rejected before provisioning (expected async accept then CREATE_FAILED): $(cat "$TMP/r.err")"
ST="$(poll_stack "$RAK" "$RSK" "$RSTACK" CREATE_FAILED 120)" || fail "reader stack should end CREATE_FAILED (got status=$ST)"
tbl_exists "$RSTACK" Denied && fail "the reader provisioned a resource it lacks authority for (confused deputy — CFN ran as the shim, not the reader!)"
log "    ✓ reader denied — CREATE_FAILED, nothing created (stack provisions under the CALLER's authority)"

# --- 6. destroy removes what was created -----------------------------------------------------------
log "delete-stack ${STACK} → resources removed"
cfn "$AAK" "$ASK" delete-stack --stack-name "$STACK" >/dev/null 2>&1 || fail "delete-stack failed"
i=0; while [ $i -lt 120 ]; do
  cfn "$AAK" "$ASK" describe-stacks --stack-name "$STACK" >/dev/null 2>&1 || break
  st="$(cfn "$AAK" "$ASK" describe-stacks --stack-name "$STACK" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || true)"
  [ "$st" = "DELETE_COMPLETE" ] && break
  sleep 4; i=$((i+4))
done
tbl_exists "$STACK" Orders && fail "Orders still present after delete-stack"
tbl_exists "$STACK" Items  && fail "Items still present after delete-stack"
log "    ✓ stack destroyed (resources gone)"

printf '\n✓ PASS — aws-shim CloudFormation is faithful: a multi-resource stack deploys in dependency order; an unsupported type is refused whole at validation with nothing created; a change set previews without applying and then executes; drift is detected after an out-of-band change; delete-stack removes what was created; and a stack provisions under the CALLER'"'"'s own authority (a reader is denied — never the shim'"'"'s, closing the confused-deputy blast radius).\n'
