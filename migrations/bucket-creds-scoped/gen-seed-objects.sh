#!/usr/bin/env bash
# One-time migration generator for the scoped-credentials model (#347).
#
# Before: each bucket/ML/Application claim's MinIO key was written only into the claim's own Secret
# (<name>-minio / <name>-db-backup-creds) by a Job with cluster-wide secret access.
# After: the key lives in a platform-side Secret (openinfra-bucket-creds/<user>); a provider Object in
# the composition copies it into the claim Secret and GCs it with the claim, and the setup SA is scoped
# to the openinfra-bucket-creds namespace only.
#
# A LEGACY claim (one created before the new model) has a claim Secret but no platform Secret yet. Its
# key is only in the claim Secret, which the newly-scoped setup SA can no longer read — so the setup Job
# deliberately never rotates it. This generator emits, for each legacy claim, a provider-kubernetes
# Object that copies the key from the claim Secret into the platform Secret (via references[].patchesFrom,
# using the provider's own credentials — no new broad RBAC). Once the platform Secret exists, the
# composition's copy Object adopts the claim Secret with the SAME key: no rotation, no NotReady.
#
# The emitted Objects use managementPolicies WITHOUT Delete, so removing them (after the migration) does
# NOT delete the platform Secrets they seeded. They are idempotent: re-applying copies the same key.
#
# Usage (read-only; prints a manifest to stdout — review, then apply, then retire — see README.md):
#   KUBECONFIG=/etc/rancher/k3s/k3s.yaml ./gen-seed-objects.sh > seed-objects.yaml
set -euo pipefail
CREDS_NS=openinfra-bucket-creds

# app_user <Kind> <ns> <name> — must match the composition's $appUser exactly.
app_user() {
  local base
  base="$(printf '%s-%s' "$2" "$3" | tr . - | cut -c1-40)"; base="${base%-}"
  printf 'app-%s-%s' "$base" "$(printf '%s/%s/%s' "$1" "$2" "$3" | sha256sum | cut -c1-10)"
}

emit() { # <user> <claim-ns> <claim-secret> <src-key>
  local user="$1" cns="$2" csecret="$3" srckey="$4"
  # Skip if the claim Secret is gone (nothing to migrate) or the platform Secret already exists (done).
  kubectl -n "$cns" get secret "$csecret" >/dev/null 2>&1 || { echo "# skip $user: no claim Secret $cns/$csecret" >&2; return; }
  if kubectl -n "$CREDS_NS" get secret "$user" >/dev/null 2>&1; then
    echo "# skip $user: platform Secret already present" >&2; return
  fi
  cat <<YAML
---
apiVersion: kubernetes.crossplane.io/v1alpha2
kind: Object
metadata:
  name: seed-creds-${user}
  labels: { openinfra.dev/one-time-migration: bucket-creds-scoped }
spec:
  # No Delete: retiring this Object must NOT delete the platform Secret it seeded.
  managementPolicies: ["Observe", "Create", "Update"]
  providerConfigRef: { name: default }
  references:
    - patchesFrom: { apiVersion: v1, kind: Secret, namespace: ${cns}, name: ${csecret}, fieldPath: data.${srckey} }
      toFieldPath: data.MINIO_SECRET_KEY
  forProvider:
    manifest:
      apiVersion: v1
      kind: Secret
      type: Opaque
      metadata: { name: ${user}, namespace: ${CREDS_NS} }
      stringData: { MINIO_ACCESS_KEY: ${user} }
YAML
}

# Bucket owner records: the ownership check now reads bucket-owner-<bucket> from the creds namespace.
# Records written before the move are still in minio; without a copy, a claim whose bucket predates it
# is refused as unowned. Copy each one (same namespace and owner fields), unless the creds namespace
# already has it.
kubectl -n minio get secrets -l openinfra.dev/bucket-owner=true -o name 2>/dev/null | sed 's#^secret/##' \
  | while read -r rec; do
      if kubectl -n "$CREDS_NS" get secret "$rec" >/dev/null 2>&1; then
        echo "# skip $rec: already in $CREDS_NS" >&2; continue
      fi
      cat <<YAML
---
apiVersion: kubernetes.crossplane.io/v1alpha2
kind: Object
metadata:
  name: seed-owner-${rec#bucket-owner-}
  labels: { openinfra.dev/one-time-migration: bucket-creds-scoped }
spec:
  managementPolicies: ["Observe", "Create", "Update"]
  providerConfigRef: { name: default }
  references:
    - patchesFrom: { apiVersion: v1, kind: Secret, namespace: minio, name: ${rec}, fieldPath: data.namespace }
      toFieldPath: data.namespace
    - patchesFrom: { apiVersion: v1, kind: Secret, namespace: minio, name: ${rec}, fieldPath: data.owner }
      toFieldPath: data.owner
  forProvider:
    manifest:
      apiVersion: v1
      kind: Secret
      type: Opaque
      metadata: { name: ${rec}, namespace: ${CREDS_NS}, labels: { openinfra.dev/bucket-owner: "true" } }
YAML
    done
# kind: Bucket / StaticSite / Model / TrainingJob / ProcessingJob / BatchTransform / ModelMonitor —
# one scoped user per claim, key in <claim>-minio under MINIO_SECRET_KEY.
for kv in XBucket:Bucket XStaticSite:StaticSite XModel:Model XTrainingJob:TrainingJob \
          XProcessingJob:ProcessingJob XBatchTransform:BatchTransform XModelMonitor:ModelMonitor; do
  xr="${kv%%:*}"; kind="${kv##*:}"
  kubectl get "${xr}.openinfra.dev" -o json 2>/dev/null \
    | jq -r '.items[] | [.metadata.labels["crossplane.io/claim-namespace"], .metadata.labels["crossplane.io/claim-name"]] | @tsv' \
    | while IFS=$'\t' read -r ns name; do
        [ -n "$ns" ] && [ -n "$name" ] || continue
        emit "$(app_user "$kind" "$ns" "$name")" "$ns" "${name}-minio" MINIO_SECRET_KEY
      done
done

# kind: Application — storage.buckets uses <name>-minio; a backed-up database uses <name>-db-backup-creds
# (scoped user bkp-<ns>-<name>, source key sk).
kubectl get xapplications.openinfra.dev -o json 2>/dev/null \
  | jq -r '.items[] | [.metadata.labels["crossplane.io/claim-namespace"], .metadata.labels["crossplane.io/claim-name"], ((.spec.storage.buckets // []) | length), (if .spec.database then 1 else 0 end)] | @tsv' \
  | while IFS=$'\t' read -r ns name nbuckets hasdb; do
      [ -n "$ns" ] && [ -n "$name" ] || continue
      [ "$nbuckets" -gt 0 ] 2>/dev/null && emit "$(app_user Application "$ns" "$name")" "$ns" "${name}-minio" MINIO_SECRET_KEY
      [ "$hasdb" = 1 ] && emit "bkp-${ns}-${name}" "$ns" "${name}-db-backup-creds" sk
    done
