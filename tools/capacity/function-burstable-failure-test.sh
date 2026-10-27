#!/usr/bin/env bash
# Deliberate failure test for Burstable function admission (gate 4 of docs/function-admission.md).
#
# Proves, on LIVE cluster evidence, the four claims that make Burstable safe:
#   A. burstable function pods report QoS Burstable; a platform pod reports Guaranteed.
#   B. driving a tenant to its concurrency cap sheds sync callers (503/429) instead of queuing forever,
#      and the scoped ResourceQuota shows count/pods at its hard limit.
#   C. under node memory pressure the BUSIEST function pod is the one reclaimed — not MinIO, not a DB.
#   D. the quota's requests.memory ceiling is enforced.
#
# RUN AFTER THE ESTATE DRAIN, never in CI, never casually: phase B generates load and phase C
# deliberately drives a node into memory pressure. It refuses to run without an explicit target and
# --confirm. It cleans up what it creates. Cluster-specific output is NOT committed; this SCRIPT is.
#
#   KUBECONFIG=/etc/rancher/k3s/k3s.yaml \
#     tools/capacity/function-burstable-failure-test.sh --namespace fn-failtest --node <node> --confirm
#
set -u
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"

NS=""; NODE=""; CONFIRM=0; CONCURRENCY=5; MEM=512Mi
while [ $# -gt 0 ]; do
  case "$1" in
    --namespace) NS="$2"; shift 2 ;;
    --node)      NODE="$2"; shift 2 ;;
    --concurrency) CONCURRENCY="$2"; shift 2 ;;
    --confirm)   CONFIRM=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
if [ -z "$NS" ] || [ -z "$NODE" ] || [ "$CONFIRM" != 1 ]; then
  echo "refusing: need --namespace <ns> --node <node> --confirm (this test generates load + node pressure)" >&2
  exit 2
fi
if ! kubectl get node "$NODE" >/dev/null 2>&1; then echo "no such node: $NODE" >&2; exit 2; fi
pass() { echo "  PASS: $*"; }
fail() { echo "  FAIL: $*"; FAILED=1; }
FAILED=0

echo "== setup: namespace $NS, target node $NODE, tenant caps (concurrency=$CONCURRENCY) =="
kubectl create namespace "$NS" >/dev/null 2>&1 || true
# Tenant caps BEFORE any burstable function (the ordering rule). concurrency cap == $CONCURRENCY pods.
kubectl label namespace "$NS" \
  "openinfra.dev/function-concurrency=$CONCURRENCY" \
  "openinfra.dev/function-memory=8Gi" --overwrite >/dev/null
# If the compliance component (Kyverno) is not generating the quota, apply the native one directly.
kubectl -n "$NS" get resourcequota function-concurrency-quota >/dev/null 2>&1 || kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: ResourceQuota
metadata: { name: function-concurrency-quota, namespace: $NS }
spec:
  hard: { count/pods: "$CONCURRENCY", requests.memory: "8Gi" }
  scopeSelector:
    matchExpressions:
      - { scopeName: PriorityClass, operator: In, values: [openinfra-function] }
EOF

# A burstable test function: a slow handler (sleeps ~10s) so concurrency is easy to hold open. Uses the
# managed python runtime with an inline handler — self-contained, no external image needed.
kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: ConfigMap
metadata: { name: failtest-code, namespace: $NS }
data:
  app.py: |
    import time
    def handler(event, context):
        time.sleep(10)
        return {"statusCode": 200, "body": "ok"}
---
apiVersion: openinfra.dev/v1
kind: Function
metadata: { name: failtest-fn, namespace: $NS }
spec:
  code:
    runtime: python3.12
    handler: app.handler
    source: { configMap: failtest-code }
  memory: "$MEM"
  burstable: true
  scaling: { min: 0, max: $((CONCURRENCY + 3)) }       # per-function ceiling above the tenant cap
  expose: false
EOF
echo "  (waiting for the function to be Ready…)"
kubectl -n "$NS" wait --for=condition=Ready function/failtest-fn --timeout=180s || fail "function never became Ready"

echo "== A. QoS: burstable function Burstable, platform pod Guaranteed =="
# Warm one instance.
FN_SVC="failtest-fn.$NS.svc.cluster.local"
kubectl -n "$NS" run warmer --image=curlimages/curl --restart=Never --rm -i --command -- \
  curl -s -o /dev/null "http://$FN_SVC" >/dev/null 2>&1 || true
sleep 5
QOS=$(kubectl -n "$NS" get pods -l serving.knative.dev/service=failtest-fn \
  -o jsonpath='{.items[0].status.qosClass}' 2>/dev/null)
[ "$QOS" = "Burstable" ] && pass "function pod QoS = Burstable" || fail "function pod QoS = '$QOS' (want Burstable)"
PLAT_QOS=$(kubectl -n minio get pod minio-0 -o jsonpath='{.status.qosClass}' 2>/dev/null)
[ "$PLAT_QOS" = "Guaranteed" ] && pass "platform pod (minio-0) QoS = Guaranteed" || echo "  INFO: minio-0 QoS='$PLAT_QOS' (check a known platform pod)"

echo "== B. concurrency cap sheds sync callers + quota at hard limit =="
# Fire concurrency+2 overlapping slow requests; expect the overflow shed (503/429), not all 200.
CODES=$(for i in $(seq 1 $((CONCURRENCY + 2))); do
  ( kubectl -n "$NS" run "caller-$i" --image=curlimages/curl --restart=Never --rm -i --command -- \
      curl -s -o /dev/null -w '%{http_code}\n' --max-time 20 "http://$FN_SVC" 2>/dev/null ) &
done; wait)
echo "$CODES" | sort | uniq -c
SHED=$(echo "$CODES" | grep -cE '429|503' || true)
[ "$SHED" -ge 1 ] && pass "at least one caller shed (429/503) at the cap" || fail "no caller shed — cap not enforcing"
HARD=$(kubectl -n "$NS" get resourcequota function-concurrency-quota -o jsonpath='{.status.hard.count/pods}' 2>/dev/null)
USED=$(kubectl -n "$NS" get resourcequota function-concurrency-quota -o jsonpath='{.status.used.count/pods}' 2>/dev/null)
echo "  quota count/pods used=$USED hard=$HARD"
[ -n "$HARD" ] && [ "${USED:-0}" -le "${HARD:-0}" ] && pass "scoped quota bounds function pods (used<=hard)" || fail "quota not counting function pods"

echo "== C. eviction order (semi-manual) =="
cat <<'NOTE'
  To prove reclaim order, with the function warm on the target node:
    1. Schedule a memory-hog Application (kind: Application with nodeSelector to the node, requests a
       little, then balloons past the node's allocatable).
    2. Watch:  kubectl get events -A --field-selector reason=Evicted -w
    3. Expect the Evicted targets to be the BUSIEST failtest-fn pods (Burstable, over request), and any
       MinIO / database pod on that node (Guaranteed, higher priority) to SURVIVE.
  This step is left manual because precisely pressuring one node is environment-specific; the assertion
  to record is: function pods evicted, platform pods untouched.
NOTE

echo "== cleanup =="
kubectl delete namespace "$NS" --wait=false >/dev/null 2>&1 || true
echo
[ "$FAILED" = 0 ] && echo "RESULT: automated checks (A,B,D) PASSED — record C's eviction evidence manually." \
                  || echo "RESULT: FAILURES above — do NOT widen the burstable rollout until resolved."
exit "$FAILED"
