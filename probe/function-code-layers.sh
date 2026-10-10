#!/usr/bin/env bash
# Live proof for kind: Function spec.code.layers (the Lambda LAYERS model): a handler imports a
# module PROVIDED BY A LAYER. The runtime shim fetches + unzips the handler into /var/task and the
# layer into /opt at cold start, and puts /opt/python on sys.path — so `import mylayer` resolves to
# the layer's code. Stages a handler zip + a layer zip into a throwaway bucket, deploys the Function
# with a layer, invokes it, and asserts the handler used the layer module. Tears down.
#
# Requires: the runtime image built WITH the layers support; KUBECONFIG; live MinIO (ns 'minio').
set -euo pipefail

SFX="$$"
NS="probe-fn-layers-${SFX}"
FN="layerfn"
BUCKET="probe-fn-layers-${SFX}"
MC_IMG="ghcr.io/harn3ss/open-infra-mc@sha256:a689825d5299d02e6f35973e726a6e49a77469cde644dd52d60586b07bd85744"
E="http://minio.minio.svc.cluster.local:9000"
WORK="$(mktemp -d)"

cleanup() {
  cat <<YAML | kubectl -n "$NS" apply -f - >/dev/null 2>&1 || true
apiVersion: v1
kind: Pod
metadata: { name: mc-teardown }
spec:
  restartPolicy: Never
  containers:
    - name: mc
      image: ${MC_IMG}
      command: ["/bin/sh","-c"]
      args: ["mc alias set m \$E \$ROOT_USER \$ROOT_PASS >/dev/null 2>&1 && mc rb --force m/\$BUCKET >/dev/null 2>&1 || true"]
      env:
        - { name: HOME, value: /tmp }
        - { name: MC_CONFIG_DIR, value: /tmp/.mc }
        - { name: E, value: "${E}" }
        - { name: BUCKET, value: "${BUCKET}" }
        - { name: ROOT_USER, valueFrom: { secretKeyRef: { name: probe-mc-root, key: rootUser } } }
        - { name: ROOT_PASS, valueFrom: { secretKeyRef: { name: probe-mc-root, key: rootPassword } } }
YAML
  kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded pod/mc-teardown --timeout=60s >/dev/null 2>&1 || true
  kubectl delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

echo "== build the handler zip (imports a layer module) + the layer zip =="
cat > "$WORK/app.py" <<'PY'
import mylayer  # provided by the layer, extracted to /opt/python

def handler(event, context):
    return {"statusCode": 200, "body": {"probe": "function-layers-ok", "layer": mylayer.greet()}}
PY
mkdir -p "$WORK/python"
cat > "$WORK/python/mylayer.py" <<'PY'
def greet():
    return "hello-from-the-layer"
PY
( cd "$WORK" && python3 -c "import zipfile; z=zipfile.ZipFile('app.zip','w',zipfile.ZIP_DEFLATED); z.write('app.py'); z.close()" )
( cd "$WORK" && python3 -c "import zipfile; z=zipfile.ZipFile('layer.zip','w',zipfile.ZIP_DEFLATED); z.write('python/mylayer.py'); z.close()" )

echo "== namespace $NS + stage both zips into the bucket =="
kubectl create ns "$NS" >/dev/null
kubectl -n "$NS" create configmap fn-zip-blob --from-file=app.zip="$WORK/app.zip" --from-file=layer.zip="$WORK/layer.zip" >/dev/null
RU=$(kubectl get secret minio -n minio -o jsonpath='{.data.rootUser}' | base64 -d)
RP=$(kubectl get secret minio -n minio -o jsonpath='{.data.rootPassword}' | base64 -d)
kubectl -n "$NS" create secret generic probe-mc-root --from-literal=rootUser="$RU" --from-literal=rootPassword="$RP" >/dev/null
cat <<YAML | kubectl -n "$NS" apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: { name: mc-setup }
spec:
  restartPolicy: Never
  containers:
    - name: mc
      image: ${MC_IMG}
      command: ["/bin/sh","-c"]
      args: ["set -e; mc alias set m \$E \$ROOT_USER \$ROOT_PASS >/dev/null; mc mb --ignore-existing m/\$BUCKET; mc cp /blob/app.zip m/\$BUCKET/app.zip; mc cp /blob/layer.zip m/\$BUCKET/layer.zip; echo SETUP_OK"]
      env:
        - { name: HOME, value: /tmp }
        - { name: MC_CONFIG_DIR, value: /tmp/.mc }
        - { name: E, value: "${E}" }
        - { name: BUCKET, value: "${BUCKET}" }
        - { name: ROOT_USER, valueFrom: { secretKeyRef: { name: probe-mc-root, key: rootUser } } }
        - { name: ROOT_PASS, valueFrom: { secretKeyRef: { name: probe-mc-root, key: rootPassword } } }
      volumeMounts: [{ name: blob, mountPath: /blob, readOnly: true }]
  volumes:
    - name: blob
      configMap: { name: fn-zip-blob }
YAML
kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded pod/mc-setup --timeout=120s >/dev/null 2>&1 || {
  echo "  FAIL: mc-setup failed"; kubectl -n "$NS" logs mc-setup 2>&1 | tail; exit 1; }

echo "== the Function's code-source secret (S3 creds) =="
kubectl -n "$NS" create secret generic "${FN}-s3" \
  --from-literal=AWS_ACCESS_KEY_ID="$RU" --from-literal=AWS_SECRET_ACCESS_KEY="$RP" --from-literal=AWS_ENDPOINT_URL="$E" >/dev/null

echo "== kind: Function with a bucket handler + a LAYER =="
cat <<YAML | kubectl -n "$NS" apply -f - >/dev/null
apiVersion: openinfra.dev/v1
kind: Function
metadata:
  name: ${FN}
spec:
  expose: false
  code:
    runtime: python3.12
    handler: app.handler
    source: { bucket: ${BUCKET}, key: app.zip, secret: ${FN}-s3 }
    layers:
      - { bucket: ${BUCKET}, key: layer.zip }
YAML

echo "== wait for Ready (cold-start fetches handler + layer) =="
for i in $(seq 1 72); do
  if kubectl -n "$NS" get ksvc "$FN" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null | grep -q True; then echo "  Ready"; break; fi
  sleep 5
  [ "$i" = "72" ] && { echo "  FAIL: ksvc not Ready"; kubectl -n "$NS" get pods 2>&1 | tail; exit 1; }
done

echo "== invoke + assert the handler used the layer module =="
URL="http://${FN}.${NS}.svc.cluster.local"
OUT=$(kubectl -n "$NS" run probe-curl --rm -i --restart=Never --image=curlimages/curl:latest --command -- \
  curl -s --max-time 30 -X POST "$URL" -H 'Content-Type: application/json' -d '{}' 2>/dev/null)
echo "  response: $OUT"
echo "$OUT" | grep -q 'function-layers-ok' || { echo "  FAIL: handler marker not found"; exit 1; }
echo "$OUT" | grep -q 'hello-from-the-layer' || { echo "  FAIL: layer module was not imported"; exit 1; }
echo "PROBE PASS: kind: Function spec.code.layers — the handler imported a layer-provided module."
