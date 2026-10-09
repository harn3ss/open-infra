#!/usr/bin/env bash
# Live proof for kind: Function spec.code BUCKET/ZIP source — the Lambda S3-code model.
# A handler shipped as a .zip OBJECT in a bucket is fetched + unzipped into /var/task by the
# runtime shim at cold start (boto3, PATH-STYLE against MinIO), then served over HTTP. This
# exercises the half of spec.code the configMap probe (function-code.sh) does NOT: the
# OPENINFRA_CODE_BUCKET/KEY env + source-secret envFrom wiring in the composition, and the
# shim's _fetch_code() fetch+unzip. Builds the zip locally, stages it into a throwaway bucket
# via the first-party mc image, deploys the Function, invokes, asserts, and tears down.
#
# Creds: this probe puts the MinIO ROOT creds in the Function's throwaway source secret for
# brevity. A REAL operator should instead reference a SCOPED (non-root) user with only
# s3:GetObject on the one bucket — the pattern the Application / TrainingJob compositions use
# (mint-per-app user + per-bucket policy). The code path under test is identical either way.
#
# Requires: runtime image ghcr.io/<owner>/open-infra-lambda-python:latest built+pushed WITH the
# path-style fetch fix; KUBECONFIG inherited; the live MinIO (ns 'minio', root secret 'minio').
set -euo pipefail

SFX="$$"
NS="probe-fn-zip-${SFX}"
FN="zipfn"
BUCKET="probe-fn-zip-${SFX}"
MC_IMG="ghcr.io/harn3ss/open-infra-mc@sha256:a689825d5299d02e6f35973e726a6e49a77469cde644dd52d60586b07bd85744"
E="http://minio.minio.svc.cluster.local:9000"
WORK="$(mktemp -d)"

cleanup() {
  # Remove the staged object + bucket while the ns (and root secret) still exist, then the ns.
  kubectl -n "$NS" delete pod mc-teardown --ignore-not-found >/dev/null 2>&1 || true
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

echo "== build the handler zip locally =="
cat > "$WORK/app.py" <<'PY'
def handler(event, context):
    # Shipped as a ZIP in a bucket; fetched + unzipped by the runtime shim at cold start.
    return {"statusCode": 200,
            "body": {"probe": "function-zip-ok", "src": "bucket-zip",
                     "echo": event, "request_id": context.aws_request_id}}
PY
( cd "$WORK" && python3 -c "import zipfile; z=zipfile.ZipFile('fn.zip','w',zipfile.ZIP_DEFLATED); z.write('app.py','app.py'); z.close()" )

echo "== namespace $NS =="
kubectl create ns "$NS" >/dev/null

echo "== stage the zip as a ConfigMap blob (kubelet decodes binaryData -> file) =="
kubectl -n "$NS" create configmap fn-zip-blob --from-file=fn.zip="$WORK/fn.zip" >/dev/null

echo "== copy the MinIO root creds into a throwaway secret in this ns =="
RU=$(kubectl get secret minio -n minio -o jsonpath='{.data.rootUser}' | base64 -d)
RP=$(kubectl get secret minio -n minio -o jsonpath='{.data.rootPassword}' | base64 -d)
kubectl -n "$NS" create secret generic probe-mc-root \
  --from-literal=rootUser="$RU" --from-literal=rootPassword="$RP" >/dev/null

echo "== stage s3://$BUCKET/fn.zip via the first-party mc image (root provisions only) =="
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
      args: ["set -e; mc alias set m \$E \$ROOT_USER \$ROOT_PASS >/dev/null; mc mb --ignore-existing m/\$BUCKET; mc cp /blob/fn.zip m/\$BUCKET/fn.zip; echo SETUP_OK"]
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
  echo "  FAIL: mc-setup did not succeed"; kubectl -n "$NS" logs mc-setup 2>&1 | tail -20; exit 1; }
kubectl -n "$NS" logs mc-setup 2>&1 | sed 's/^/  mc: /'

echo "== the Function's code-source secret (S3 creds + endpoint the shim's boto3 reads) =="
kubectl -n "$NS" create secret generic "${FN}-s3" \
  --from-literal=AWS_ACCESS_KEY_ID="$RU" \
  --from-literal=AWS_SECRET_ACCESS_KEY="$RP" \
  --from-literal=AWS_ENDPOINT_URL="$E" >/dev/null

echo "== kind: Function with spec.code (bucket/zip source) =="
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
    source:
      bucket: ${BUCKET}
      key: fn.zip
      secret: ${FN}-s3
YAML

echo "== wait for the Knative Service to be Ready (cold-start fetches+unzips the zip) =="
for i in $(seq 1 72); do
  if kubectl -n "$NS" get ksvc "$FN" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null | grep -q True; then
    echo "  Ready"; break
  fi
  sleep 5
  [ "$i" = "72" ] && { echo "  FAIL: ksvc not Ready in 6m"; kubectl -n "$NS" get ksvc "$FN" -o yaml | tail -40; \
    kubectl -n "$NS" get pods 2>&1 | tail; exit 1; }
done

echo "== invoke it (in-cluster POST) and assert the zipped handler ran =="
URL="http://${FN}.${NS}.svc.cluster.local"
OUT=$(kubectl -n "$NS" run probe-curl --rm -i --restart=Never --image=curlimages/curl:latest --command -- \
  curl -s --max-time 30 -X POST "$URL" -H 'Content-Type: application/json' -d '{"hello":"zip"}' 2>/dev/null)
echo "  response: $OUT"
echo "$OUT" | grep -q 'function-zip-ok' || { echo "  FAIL: zip-handler marker not found"; exit 1; }
echo "$OUT" | grep -q '"hello": *"zip"' || echo "  WARN: event echo not found (handler ran but event shape differs)"
echo "PROBE PASS: kind: Function spec.code fetched+unzipped a handler from a bucket and ran it."
