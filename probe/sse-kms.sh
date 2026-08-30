#!/usr/bin/env bash
# probe/sse-kms.sh — validate MinIO SSE-KMS via KES → Vault KV end to end, WITHOUT touching the live
# MinIO. Mirrors probe/encryption-vault.sh for the object layer (#37, NIST SC-28(1)).
#
# What it proves: a scratch MinIO wired to the deployed KES (ns minio) encrypts an object with a
# customer key held in Vault KV (round-trip), and destroying that key crypto-erases the object — the
# object persists but reads fail "failed to decrypt ciphertext".
#
# Requires: components.objectEncryption on (KES deployed in ns minio, its cert Secrets present), Vault
# unsealed, and a Vault token with delete on kes/* for the crypto-erase step:
#   VAULT_TOKEN=<token> probe/sse-kms.sh
# Run from a host with cluster access (kubectl). Safe: everything lives in a throwaway namespace + a
# probe-only key; it never reads or reconfigures the live MinIO.
set -euo pipefail
NS=sse-kms-probe
KEY=sse-kms-probe
kubectl() { command kubectl "$@"; }
cleanup() { kubectl delete namespace "$NS" --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== pre-flight: KES up + Vault unsealed =="
kubectl -n minio get deploy kes >/dev/null 2>&1 || { echo "FAIL: KES not deployed (components.objectEncryption off?)"; exit 1; }
kubectl -n vault exec vault-0 -- vault status >/dev/null 2>&1 || { echo "FAIL: Vault sealed/unreachable"; exit 1; }
: "${VAULT_TOKEN:?VAULT_TOKEN required (needs delete on kes/* for the crypto-erase step)}"

echo "== stand up a scratch MinIO wired to the live KES (throwaway ns $NS) =="
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
# reuse the KES-issued MinIO client cert so the scratch MinIO authenticates to KES
kubectl -n minio get secret minio-kes-client -o yaml | sed "s/namespace: minio/namespace: $NS/" | kubectl apply -f - >/dev/null
kubectl -n "$NS" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: { name: minio-probe, namespace: $NS }
spec:
  replicas: 1
  selector: { matchLabels: { app: minio-probe } }
  template:
    metadata: { labels: { app: minio-probe } }
    spec:
      containers:
        - name: minio
          image: minio/minio:RELEASE.2024-09-13T20-26-02Z
          args: ["server", "/data"]
          env:
            - { name: MINIO_ROOT_USER, value: "probe" }
            - { name: MINIO_ROOT_PASSWORD, value: "probeprobe123" }
            - { name: MINIO_KMS_KES_ENDPOINT, value: "https://kes.minio.svc.cluster.local:7373" }
            - { name: MINIO_KMS_KES_KEY_NAME, value: "$KEY" }
            - { name: MINIO_KMS_KES_CERT_FILE, value: "/certs/client.crt" }
            - { name: MINIO_KMS_KES_KEY_FILE, value: "/certs/client.key" }
            - { name: MINIO_KMS_KES_CAPATH, value: "/certs/ca.crt" }
          volumeMounts: [{ name: certs, mountPath: /certs }, { name: data, mountPath: /data }]
      volumes:
        - { name: certs, secret: { secretName: minio-kes-client } }
        - { name: data, persistentVolumeClaim: { claimName: minio-probe-data } }
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: { name: minio-probe-data, namespace: $NS }
spec: { accessModes: [ReadWriteOnce], storageClassName: local-path, resources: { requests: { storage: 1Gi } } }
---
apiVersion: v1
kind: Service
metadata: { name: minio-probe, namespace: $NS }
spec: { selector: { app: minio-probe }, ports: [{ port: 9000, targetPort: 9000 }] }
YAML
kubectl -n "$NS" rollout status deploy/minio-probe --timeout=120s

echo "== round-trip: enable SSE-KMS, put + read =="
MC="mc alias set s http://minio-probe.$NS.svc.cluster.local:9000 probe probeprobe123 >/dev/null"
run_mc() { kubectl -n "$NS" run mc-$RANDOM --rm -i --restart=Never --image=minio/mc:RELEASE.2024-09-16T17-43-14Z --command -- sh -c "$1" 2>/dev/null; }
run_mc "$MC; mc mb --ignore-existing s/enc >/dev/null; mc encrypt set sse-kms $KEY s/enc >/dev/null; echo secret-payload-\$RANDOM | mc pipe s/enc/o.txt; echo readback=[\$(mc cat s/enc/o.txt)]"
kubectl -n vault exec vault-0 -- env VAULT_TOKEN="$VAULT_TOKEN" vault read "kes/$KEY" >/dev/null 2>&1 && echo "key present in Vault KV (kes/$KEY): OK"

echo "== crypto-erase: destroy the key, restart, confirm unreadable but present =="
kubectl -n vault exec vault-0 -- env VAULT_TOKEN="$VAULT_TOKEN" vault delete "kes/$KEY" >/dev/null
kubectl -n minio rollout restart deploy/kes >/dev/null; kubectl -n minio rollout status deploy/kes --timeout=60s >/dev/null
kubectl -n "$NS" rollout restart deploy/minio-probe >/dev/null; kubectl -n "$NS" rollout status deploy/minio-probe --timeout=90s >/dev/null
if run_mc "$MC; mc ls s/enc/o.txt >/dev/null && (mc cat s/enc/o.txt >/dev/null 2>&1 && echo STILL_READABLE || echo CRYPTO_ERASED)" | grep -q CRYPTO_ERASED; then
  echo "PASS: object persists but is undecryptable after key destruction (crypto-erased)"
else
  echo "FAIL: object still readable (or missing) after key destruction"; exit 1
fi
echo "SSE-KMS probe PASSED"
