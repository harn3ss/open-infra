#!/usr/bin/env bash
# Live proof for open-appsync's DIRECT Lambda resolvers and BatchInvoke (#341), against a REAL
# kind: Function behind a kind: GraphQLApi.
#
# A throwaway namespace gets a platform-owned fixture (synthetic handler + schema, no customer code):
#   - a nodejs22 kind: Function (inline code, a ConfigMap) that answers both an AppSync Context (a direct
#     resolver's event) and a LIST of Contexts (a batched resolver's BatchInvoke): each batched result
#     carries the size of the batch it arrived in, its position in it and a per-invocation id, and the
#     Parent p3 item is a deliberate {errorMessage, errorType};
#   - a kind: GraphQLApi (API-key auth, @aws_api_key) whose lambda data source names that Function
#     (dataSources[].function), with
#       Query.echo      a direct Lambda resolver (no templates) — the handler echoes the event's shape,
#       Query.parents   a direct Lambda resolver returning 5 Parents,
#       Parent.child    a direct Lambda resolver with maxBatchSize 2 (5 parents → batches of 2, 2, 1),
#       Query.fireAndForget  a VTL resolver whose request asks for invocationType Event (unserved).
#
# It asserts, over GraphQL with the API key:
#   1. Query.echo returns the function's raw value (a returned statusCode 500 is data, not an error),
#      and the event had AWS's Context shape: exactly arguments/identity/info/prev/request/source/stash,
#      info.fieldName/parentTypeName/selectionSetList/selectionSetGraphQL, the arguments, the API key's
#      identity, the client's header, null source/prev and an empty stash at the root;
#   2. Parent.child comes back in order for every parent, from 3 invocations of 2, 2 and 1 items (each
#      item reports the batch size and position it saw; items sharing an invocation share its id);
#   3. the deliberate item error is exactly one GraphQL error, on ["parents", 3, "child"], with its
#      errorType and message, and that field is null while its siblings resolve;
#   4. invocationType Event fails closed: the field is null with an error naming invocationType Event;
#   5. without the API key the @aws_api_key field is Unauthorized.
#
# The engine is reached by `kubectl port-forward` to its Service (the GraphQL endpoint is /graphql; the
# API key goes in x-api-key, as AppSync's API_KEY mode takes it). On-demand, not CI-gated.
#
#   ./probe/appsync-lambda-direct-batch.sh
#
# Env (all optional):
#   KUBECONFIG          the cluster (kubectl as the cluster operator)
#   PROBE_NS            namespace to create and delete (default probe-appsync-lambda-<pid>)
#   APPSYNC_IMAGE       the open-appsync engine image for the GraphQLApi's spec.image (default: the
#                       composition's own, ghcr.io/harn3ss/open-infra-open-appsync:latest)
#   PROBE_LOCAL_PORT    local port for the port-forward (default: a random one)
#   READY_TIMEOUT       seconds to wait for the Function and for the engine (default 300 each)
#   KEEP=1              leave the namespace up for inspection
#
# Needs: kubectl, curl, python3; the #341 platform (the GraphQLApi XRD with dataSources[].function and
# maxBatchSize, the open-appsync engine image, and the nodejs22 Lambda runtime image).
# Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE (the platform or cluster could not run the check).
set -euo pipefail

EXIT_INCONCLUSIVE=42
NS="${PROBE_NS:-probe-appsync-lambda-$$}"
FN="probe-lambda-fn"
API="probe-lambda-api"
ENGINE="open-appsync-${API}"
KEY_SECRET="probe-lambda-apikeys"
KEY_USER="probe-appsync-lambda"
LOCAL_PORT="${PROBE_LOCAL_PORT:-$((20000 + RANDOM % 20000))}"
READY_TIMEOUT="${READY_TIMEOUT:-300}"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v curl >/dev/null || inconclusive "curl is required"
command -v python3 >/dev/null || inconclusive "python3 is required (the GraphQL client and assertions)"
kubectl get --raw /readyz >/dev/null 2>&1 || inconclusive "the cluster is not reachable with this KUBECONFIG"
kubectl get crd graphqlapis.openinfra.dev >/dev/null 2>&1 || inconclusive "kind: GraphQLApi is not installed (no graphqlapis.openinfra.dev CRD)"
kubectl get crd functions.openinfra.dev >/dev/null 2>&1 || inconclusive "kind: Function is not installed (no functions.openinfra.dev CRD)"
# The #341 contract on the cluster: an XRD without these fields prunes them, and the check would be
# about an older platform, not this feature.
XRD="$(kubectl get compositeresourcedefinitions.apiextensions.crossplane.io xgraphqlapis.openinfra.dev -o json 2>/dev/null || true)"
grep -q '"maxBatchSize"' <<<"$XRD" && grep -q '"function"' <<<"$XRD" \
  || inconclusive "the GraphQLApi XRD on this cluster predates dataSources[].function / maxBatchSize (#341) — sync the platform first"

WORK="$(mktemp -d)"; PF_PID=""; MADE_NS=""
cleanup() {
  [ -n "$PF_PID" ] && kill "$PF_PID" >/dev/null 2>&1 || true
  if [ -n "$MADE_NS" ] && [ "${KEEP:-}" != 1 ]; then
    # The claims first, so Crossplane removes what they composed; then the namespace.
    kubectl -n "$NS" delete graphqlapis.openinfra.dev "$API" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    kubectl -n "$NS" delete functions.openinfra.dev "$FN" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    kubectl delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  elif [ -n "$MADE_NS" ]; then
    printf '▸ KEEP=1: leaving namespace %s up\n' "$NS"
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

log "namespace ${NS}"
kubectl get ns "$NS" >/dev/null 2>&1 && inconclusive "namespace ${NS} already exists — set PROBE_NS to a fresh one"
kubectl create ns "$NS" >/dev/null || inconclusive "could not create namespace ${NS}"
MADE_NS=1

# --- The Function: one handler for a direct Context and for a BatchInvoke list of Contexts. ---
cat > "$WORK/index.js" <<'JS'
// Platform-owned probe fixture (#341). An AppSync direct Lambda resolver sends ONE Context; a batched
// one (maxBatchSize > 0) sends a LIST of Contexts and must answer a list in the same order.
exports.handler = async (event) => {
  if (Array.isArray(event)) {
    const invocation = Math.random().toString(36).slice(2, 12); // one id per invocation (= per batch)
    return event.map((ctx, i) => {
      const id = ctx && ctx.source ? ctx.source.id : null;
      if (id === "p3") {
        return { data: null, errorMessage: "probe: deliberate item error", errorType: "ProbeItemError" };
      }
      const info = (ctx && ctx.info) || {};
      return { data: { id: "c-" + id, parentId: id, batchSize: event.length, position: i, invocation,
                       fieldName: info.fieldName, parentTypeName: info.parentTypeName } };
    });
  }
  // A runtime that wraps a non-object event (pre-#341) hands a batch over as {body: [...]}.
  if (event && Array.isArray(event.body)) {
    throw new Error("WRAPPED_BATCH: the runtime delivered the BatchInvoke list wrapped as {body}");
  }
  const info = (event && event.info) || {};
  if (info.fieldName === "parents") {
    const n = (event.arguments && event.arguments.n) || 5;
    return Array.from({ length: n }, (_, i) => ({ id: "p" + i }));
  }
  if (info.fieldName === "echo") {
    const headers = (event.request && event.request.headers) || {};
    return {
      statusCode: 500, // a RETURNED statusCode is data (AWS Invoke semantics), never an error
      fieldName: info.fieldName,
      parentTypeName: info.parentTypeName,
      argId: event.arguments ? event.arguments.id : null,
      sourceIsNull: event.source === null,
      prevIsNull: event.prev === null,
      stashIsEmpty: !!event.stash && typeof event.stash === "object" && Object.keys(event.stash).length === 0,
      identityUsername: event.identity ? event.identity.username : null,
      probeHeader: headers["x-probe"] || null,
      eventKeys: Object.keys(event).sort(),
      selectionSetList: info.selectionSetList,
      selectionSetGraphQL: info.selectionSetGraphQL,
    };
  }
  throw new Error("probe: unexpected event " + JSON.stringify(event).slice(0, 300));
};
JS
kubectl -n "$NS" create configmap "${FN}-code" --from-file=index.js="$WORK/index.js" >/dev/null

log "kind: Function ${FN} (nodejs22, inline code)"
cat <<YAML | kubectl -n "$NS" apply -f - >/dev/null
apiVersion: openinfra.dev/v1
kind: Function
metadata: { name: ${FN} }
spec:
  expose: false          # cluster-local: only the GraphQLApi's engine invokes it
  code:
    runtime: nodejs22
    handler: index.handler
    source:
      configMap: ${FN}-code
YAML

# --- The API key: THE KEY IS AN IDENTITY (it impersonates KEY_USER). Never printed. ---
API_KEY="probe-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf '[{"key":"%s","username":"%s","groups":[]}]' "$API_KEY" "$KEY_USER" > "$WORK/apikeys.json"
kubectl -n "$NS" create secret generic "$KEY_SECRET" --from-file=apikeys.json="$WORK/apikeys.json" >/dev/null
rm -f "$WORK/apikeys.json"

log "kind: GraphQLApi ${API} (API-key auth; direct Lambda resolvers; Parent.child maxBatchSize 2)"
IMAGE_LINE=""
[ -n "${APPSYNC_IMAGE:-}" ] && IMAGE_LINE="image: \"${APPSYNC_IMAGE}\""
cat <<YAML | kubectl -n "$NS" apply -f - >/dev/null
apiVersion: openinfra.dev/v1
kind: GraphQLApi
metadata: { name: ${API} }
spec:
  ${IMAGE_LINE}
  apiKeysSecret: ${KEY_SECRET}
  schema: |
    type Echo @aws_api_key {
      statusCode: Int
      fieldName: String
      parentTypeName: String
      argId: String
      sourceIsNull: Boolean
      prevIsNull: Boolean
      stashIsEmpty: Boolean
      identityUsername: String
      probeHeader: String
      eventKeys: [String]
      selectionSetList: [String]
      selectionSetGraphQL: String
    }
    type Child @aws_api_key {
      id: ID
      parentId: ID
      batchSize: Int
      position: Int
      invocation: String
      fieldName: String
      parentTypeName: String
    }
    type Parent @aws_api_key {
      id: ID!
      child: Child
    }
    type Query @aws_api_key {
      echo(id: ID!): Echo
      parents(n: Int!): [Parent]
      fireAndForget: String
    }
  dataSources:
    - { name: fn, type: lambda, function: ${FN} }
  resolvers:
    # Direct Lambda resolvers: no request and no response mapping template.
    - { type: Query, field: echo, dataSource: fn }
    - { type: Query, field: parents, dataSource: fn }
    # Batched: the child of every Parent in one list goes to the function as BatchInvokes of <= 2.
    - { type: Parent, field: child, dataSource: fn, maxBatchSize: 2 }
    # An asynchronous invoke (invocationType Event) is not served: it must fail closed.
    - type: Query
      field: fireAndForget
      dataSource: fn
      request: |
        {"version": "2018-05-29", "operation": "Invoke", "invocationType": "Event", "payload": {}}
      response: |
        \$util.toJson(\$ctx.result)
YAML

# The admitted claim must carry the #341 fields (an older XRD would have pruned them).
[ "$(kubectl -n "$NS" get graphqlapis.openinfra.dev "$API" -o jsonpath='{.spec.dataSources[0].function}')" = "$FN" ] \
  || inconclusive "the GraphQLApi claim lost dataSources[].function on admission (the XRD predates #341)"
[ "$(kubectl -n "$NS" get graphqlapis.openinfra.dev "$API" -o jsonpath='{.spec.resolvers[2].maxBatchSize}')" = 2 ] \
  || inconclusive "the GraphQLApi claim lost maxBatchSize on admission (the XRD predates #341)"

# --- Wait for both to be Ready (bounded). Each composes asynchronously (claim → XR → provider Object →
#     the real resource), so wait for the resource to EXIST before waiting on its readiness. ---
wait_exists() { # kind name seconds
  local i; for i in $(seq 1 "$(( $3 / 2 ))"); do kubectl -n "$NS" get "$1" "$2" >/dev/null 2>&1 && return 0; sleep 2; done; return 1
}
log "waiting for the Function (Knative Service ${FN}) to be Ready (≤ ${READY_TIMEOUT}s)"
wait_exists ksvc "$FN" 120 || inconclusive "the Function's Knative Service was not created (the Function composition did not reconcile in time)"
kubectl -n "$NS" wait --for=condition=Ready "ksvc/${FN}" --timeout="${READY_TIMEOUT}s" >/dev/null 2>&1 \
  || inconclusive "the Function did not become Ready in ${READY_TIMEOUT}s (Knative / runtime image pull): $(kubectl -n "$NS" get ksvc "$FN" -o jsonpath='{.status.conditions}' 2>/dev/null | head -c 400)"

log "waiting for the engine (Deployment ${ENGINE}) to be Ready (≤ ${READY_TIMEOUT}s)"
wait_exists deployment "$ENGINE" 120 || inconclusive "the engine Deployment was not created (the GraphQLApi composition did not reconcile in time): $(kubectl -n "$NS" get graphqlapis.openinfra.dev "$API" -o jsonpath='{.status.conditions}' 2>/dev/null | head -c 400)"
if ! kubectl -n "$NS" rollout status "deployment/${ENGINE}" --timeout="${READY_TIMEOUT}s" >/dev/null 2>&1; then
  LOGS="$(kubectl -n "$NS" logs "deployment/${ENGINE}" --tail=30 2>&1 || true)"
  # The engine refusing this config (fail-closed load) is a real failure; anything else is the cluster.
  if grep -Eq 'open-appsync: (resolver|data source|read|parse)|refusing to serve' <<<"$LOGS"; then
    fail "the engine refused the probe's GraphQLApi config:\n${LOGS}"
  fi
  inconclusive "the engine did not become Ready in ${READY_TIMEOUT}s:\n${LOGS}"
fi

log "port-forward svc/${ENGINE} → 127.0.0.1:${LOCAL_PORT}"
kubectl -n "$NS" port-forward "svc/${ENGINE}" "${LOCAL_PORT}:80" >"$WORK/pf.log" 2>&1 &
PF_PID=$!
for _ in $(seq 1 30); do curl -fsS -m 2 "http://127.0.0.1:${LOCAL_PORT}/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS -m 2 "http://127.0.0.1:${LOCAL_PORT}/healthz" >/dev/null 2>&1 \
  || inconclusive "the engine is not reachable through the port-forward: $(head -c 300 "$WORK/pf.log")"

# --- The GraphQL client + assertions (python3 stdlib). Exit 0 = ok, 1 = fail (reason printed),
#     3 = transient (the function was not reachable yet — retry). ---
cat > "$WORK/check.py" <<'PY'
import json, os, sys, urllib.request, urllib.error

URL = os.environ["GQL_URL"]
KEY = os.environ.get("API_KEY", "")

def post(query, key=KEY):
    headers = {"Content-Type": "application/json", "X-Probe": "hello"}
    if key:
        headers["x-api-key"] = key
    req = urllib.request.Request(URL, data=json.dumps({"query": query}).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            body = r.read().decode()
    except urllib.error.HTTPError as e:
        body = e.read().decode()
    try:
        return json.loads(body)
    except ValueError:
        die("the engine did not answer JSON: " + body[:300])

def die(msg):
    print(msg)
    sys.exit(1)

def transient(res):
    for e in res.get("errors") or []:
        m = e.get("message", "")
        if "lambdasource: invoke failed" in m or "lambdasource: invocation failed" in m:
            print("the function was not reachable yet: " + m[:200])
            sys.exit(3)

def hints(res):
    for e in res.get("errors") or []:
        m = e.get("message", "")
        if "WRAPPED_BATCH" in m:
            die("the Lambda runtime wrapped the BatchInvoke list as {body: [...]} — its image predates #341 (direct mode passes a list verbatim): " + m)
        if "response template did not emit JSON" in m:
            die("the engine treated a direct resolver as an empty template — its image predates #341: " + m)

ECHO_FIELDS = ["statusCode", "fieldName", "parentTypeName", "argId", "sourceIsNull", "prevIsNull",
               "stashIsEmpty", "identityUsername", "probeHeader", "eventKeys", "selectionSetList",
               "selectionSetGraphQL"]

def check_echo():
    res = post('{ echo(id: "e2e-1") { %s } }' % " ".join(ECHO_FIELDS))
    transient(res); hints(res)
    if res.get("errors"):
        die("Query.echo errored: %s" % json.dumps(res["errors"])[:600])
    got = (res.get("data") or {}).get("echo")
    if not isinstance(got, dict):
        die("Query.echo is not the function's value: %s" % json.dumps(res)[:600])
    want = {
        "statusCode": 500,
        "fieldName": "echo",
        "parentTypeName": "Query",
        "argId": "e2e-1",
        "sourceIsNull": True,
        "prevIsNull": True,
        "stashIsEmpty": True,
        "identityUsername": os.environ["KEY_USER"],
        "probeHeader": "hello",
        "eventKeys": ["arguments", "identity", "info", "prev", "request", "source", "stash"],
        "selectionSetList": ECHO_FIELDS,
        "selectionSetGraphQL": "{\n" + "".join("  %s\n" % f for f in ECHO_FIELDS) + "}",
    }
    bad = {k: (got.get(k), v) for k, v in want.items() if got.get(k) != v}
    if bad:
        die("Query.echo: the event or the returned value is not AWS's (field: got, want): %s" % json.dumps(bad)[:900])
    print("direct resolver: the function's raw value came back (statusCode 500 is data) and the event was AWS's Context")

def check_batch():
    res = post("{ parents(n: 5) { id child { id parentId batchSize position invocation fieldName parentTypeName } } }")
    transient(res); hints(res)
    parents = (res.get("data") or {}).get("parents")
    if not isinstance(parents, list) or [p.get("id") for p in parents] != ["p0", "p1", "p2", "p3", "p4"]:
        die("Query.parents did not return p0..p4 in order: %s" % json.dumps(res)[:600])
    errs = res.get("errors") or []
    if len(errs) != 1:
        die("want exactly ONE error (the deliberate item), got %d: %s" % (len(errs), json.dumps(errs)[:600]))
    e = errs[0]
    if e.get("path") != ["parents", 3, "child"] or e.get("errorType") != "ProbeItemError" or e.get("message") != "probe: deliberate item error":
        die("the item error did not land on exactly its item: %s" % json.dumps(e))
    if parents[3].get("child") is not None:
        die("the errored item's field must be null, got %s" % json.dumps(parents[3]))
    want_size = {0: 2, 1: 2, 2: 2, 4: 1}
    want_pos = {0: 0, 1: 1, 2: 0, 4: 0}
    for i in (0, 1, 2, 4):
        c = parents[i].get("child") or {}
        exp = {"id": "c-p%d" % i, "parentId": "p%d" % i, "batchSize": want_size[i], "position": want_pos[i],
               "fieldName": "child", "parentTypeName": "Parent"}
        bad = {k: (c.get(k), v) for k, v in exp.items() if c.get(k) != v}
        if bad:
            die("parents[%d].child is not its own result from a batch of [2,2,1] (field: got, want): %s" % (i, json.dumps(bad)))
    inv = {i: parents[i]["child"].get("invocation") for i in (0, 1, 2, 4)}
    if not all(inv.values()) or inv[0] != inv[1] or len({inv[0], inv[2], inv[4]}) != 3:
        die("the batches were not one invocation each (p0,p1 | p2,p3 | p4): invocation ids %s" % json.dumps(inv))
    print("batched resolver: 5 parents → 3 invocations of 2, 2, 1 items, results in order; "
          "the deliberate item error is exactly [parents, 3, child] (ProbeItemError) and that field is null")

def check_event():
    res = post("{ fireAndForget }")
    errs = res.get("errors") or []
    if (res.get("data") or {}).get("fireAndForget") is not None:
        die("invocationType Event resolved to a value instead of failing closed: %s" % json.dumps(res)[:400])
    if len(errs) != 1 or errs[0].get("path") != ["fireAndForget"] or "invocationType Event" not in errs[0].get("message", ""):
        die("invocationType Event did not fail closed with an error naming it: %s" % json.dumps(res)[:600])
    print("invocationType Event fails closed: " + errs[0]["message"])

def check_noauth():
    res = post('{ echo(id: "x") { fieldName } }', key="")
    errs = res.get("errors") or []
    if (res.get("data") or {}).get("echo") is not None or not errs or errs[0].get("errorType") != "Unauthorized":
        die("an @aws_api_key field answered a request without the API key: %s" % json.dumps(res)[:400])
    print("without the API key the field is Unauthorized")

{"echo": check_echo, "batch": check_batch, "event": check_event, "noauth": check_noauth}[sys.argv[1]]()
PY

export GQL_URL="http://127.0.0.1:${LOCAL_PORT}/graphql" API_KEY KEY_USER
run_check() { # name — retries while the function is still coming up (scale-from-zero)
  local rc out i
  for i in $(seq 1 10); do
    set +e; out="$(python3 "$WORK/check.py" "$1" 2>&1)"; rc=$?; set -e
    [ "$rc" -ne 3 ] && break
    sleep 6
  done
  case "$rc" in
    0) log "  ✓ ${out}" ;;
    3) inconclusive "the engine could not reach the Function: ${out}" ;;
    *) fail "${out}" ;;
  esac
}

log "1. a direct Lambda resolver (no templates): AWS's Context in, the raw return value out"
run_check echo
log "2–3. a batched list field (maxBatchSize 2 over 5 parents) with one deliberate item error"
run_check batch
log "4. invocationType Event fails closed"
run_check event
log "5. API-key auth: no key, no field"
run_check noauth

echo
echo "✓ PASS — open-appsync's direct Lambda resolvers and BatchInvoke behave as AWS AppSync's against a real kind: Function."
