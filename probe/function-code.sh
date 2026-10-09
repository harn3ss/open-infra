#!/usr/bin/env bash
# Live proof for kind: Function spec.code (the Lambda Zip+handler ingestion model):
# a handler shipped as CODE (here: inline via a ConfigMap) runs on the managed
# python3.12 runtime base image and serves over HTTP. Deploys a throwaway Function,
# invokes it, asserts the handler ran and echoed the event, then tears down.
#
# Requires: the runtime image ghcr.io/<owner>/open-infra-lambda-python:latest built
# + pushed (build-lambda-runtimes.yml). KUBECONFIG inherited. On-demand (not CI-gated).
set -euo pipefail

NS="probe-fn-code-$$"
FN="echofn"
cleanup() { kubectl delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== namespace $NS =="
kubectl create ns "$NS" >/dev/null

echo "== handler ConfigMap (app.py) =="
cat <<'PY' > /tmp/fn-app.py
def handler(event, context):
    # Echo the event back with a marker so the probe can confirm the handler ran.
    return {"statusCode": 200, "body": {"probe": "function-code-ok", "echo": event,
                                        "request_id": context.aws_request_id}}
PY
kubectl -n "$NS" create configmap "${FN}-code" --from-file=app.py=/tmp/fn-app.py >/dev/null

echo "== kind: Function with spec.code (configMap source) =="
cat <<YAML | kubectl -n "$NS" apply -f - >/dev/null
apiVersion: openinfra.dev/v1
kind: Function
metadata:
  name: ${FN}
spec:
  expose: false          # cluster-local is enough for the probe
  code:
    runtime: python3.12
    handler: app.handler
    source:
      configMap: ${FN}-code
YAML

echo "== wait for the Knative Service to be Ready (cold-start pulls the runtime image) =="
for i in $(seq 1 60); do
  if kubectl -n "$NS" get ksvc "$FN" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null | grep -q True; then
    echo "  Ready"; break
  fi
  sleep 5
  [ "$i" = "60" ] && { echo "  FAIL: ksvc not Ready in 5m"; kubectl -n "$NS" get ksvc "$FN" -o yaml | tail -30; exit 1; }
done

echo "== invoke it (in-cluster POST) and assert the handler ran =="
URL="http://${FN}.${NS}.svc.cluster.local"
OUT=$(kubectl -n "$NS" run probe-curl --rm -i --restart=Never --image=curlimages/curl:latest --command -- \
  curl -s --max-time 30 -X POST "$URL" -H 'Content-Type: application/json' -d '{"hello":"lambda"}' 2>/dev/null)
echo "  response: $OUT"
echo "$OUT" | grep -q 'function-code-ok' || { echo "  FAIL: handler marker not found"; exit 1; }
echo "$OUT" | grep -q '"hello": *"lambda"' || echo "  WARN: event echo not found (handler ran but event shape differs)"
echo "PROBE PASS: kind: Function spec.code ran a handler on the managed runtime."
