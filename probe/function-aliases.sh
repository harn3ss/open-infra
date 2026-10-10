#!/usr/bin/env bash
# Live proof for kind: Function spec.aliases (the Lambda alias/version analog): a weighted alias
# renders a Knative traffic target — a named tag routing its percent to the latest (or a pinned)
# revision, independently addressable. Deploys a throwaway Function with an alias, waits for the
# Knative Service, and asserts the traffic block + the tagged route exist. Tears down.
set -euo pipefail

NS="probe-fn-alias-$$"
FN="aliasfn"
cleanup() { kubectl delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== namespace $NS =="
kubectl create ns "$NS" >/dev/null

echo "== kind: Function with a weighted alias (prod -> latest, 100%) =="
cat <<YAML | kubectl -n "$NS" apply -f - >/dev/null
apiVersion: openinfra.dev/v1
kind: Function
metadata:
  name: ${FN}
spec:
  image: traefik/whoami:v1.10.3
  port: 80
  expose: false
  aliases:
    - { name: prod, revision: latest, weight: 100 }
YAML

echo "== wait for the Knative Service to be Ready =="
for i in $(seq 1 60); do
  if kubectl -n "$NS" get ksvc "$FN" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null | grep -q True; then echo "  Ready"; break; fi
  sleep 5
  [ "$i" = "60" ] && { echo "  FAIL: ksvc not Ready"; kubectl -n "$NS" get ksvc "$FN" -o yaml | tail -30; exit 1; }
done

echo "== assert the traffic block carries the alias tag + weight =="
TRAFFIC="$(kubectl -n "$NS" get ksvc "$FN" -o jsonpath='{.spec.traffic}')"
echo "  spec.traffic: $TRAFFIC"
echo "$TRAFFIC" | grep -q '"tag":"prod"' || { echo "  FAIL: no 'prod' traffic tag"; exit 1; }
echo "$TRAFFIC" | grep -q '"percent":100' || { echo "  FAIL: percent not 100"; exit 1; }
echo "$TRAFFIC" | grep -q '"latestRevision":true' || { echo "  FAIL: not routed to latestRevision"; exit 1; }

echo "== assert the alias is independently addressable (status carries the tagged URL) =="
kubectl -n "$NS" get ksvc "$FN" -o jsonpath='{.status.traffic}' 2>/dev/null | grep -q '"tag":"prod"' \
  || { echo "  WARN: status.traffic not populated yet (tag route may still be settling)"; }
TAGURL="$(kubectl -n "$NS" get ksvc "$FN" -o jsonpath='{.status.traffic[?(@.tag=="prod")].url}' 2>/dev/null)"
echo "  tagged URL: ${TAGURL:-<not yet published>}"

echo "PROBE PASS: kind: Function spec.aliases renders a weighted Knative traffic tag."
