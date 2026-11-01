# One-time migration: scoped bucket credentials (#347)

This moves existing bucket/ML/Application claims onto the scoped-credentials model **without rotating
any MinIO key, flipping any claim NotReady, or an outage**. It is a one-shot operator step, not part of
the GitOps tree (this directory is outside the root-app include glob).

## Why it is needed

Before #347, a claim's scoped MinIO key was written only into the claim's own Secret
(`<name>-minio` / `<name>-db-backup-creds`) by a setup Job that held cluster-wide secret access. The new
model keeps the key in a **platform-side Secret** `openinfra-bucket-creds/<user>`; a provider Object in
the composition copies it into the claim Secret and garbage-collects it with the claim, and the setup
Job's ServiceAccount is scoped to the `openinfra-bucket-creds` namespace only.

A **legacy** claim therefore has a claim Secret but no platform Secret yet, and its key lives only in the
claim Secret — which the newly-scoped setup Job can no longer read. So the Job deliberately **never
rotates** a legacy user (it leaves the password untouched). This migration seeds the platform Secret from
the claim Secret, using the Crossplane provider's own credentials (no new broad RBAC), after which the
composition adopts the claim Secret with the same key.

## State machine (per claim)

| state | platform Secret | claim Secret | setup Job | composition copy Object | this migration Object |
|-------|-----------------|--------------|-----------|-------------------------|-----------------------|
| **new** | written by Job (mint) | created by copy Object | mints key, writes platform Secret, `user add` | renders (platform observed) → creates claim Secret | no-op (platform Secret present → skipped by the generator) |
| **legacy, pre-migration** | absent | exists (old key) | sees user exists + platform absent → **leaves password unchanged** | not rendered (platform not observed) → claim keeps its existing Secret, stays Ready via its gate | seeds platform Secret from claim Secret |
| **legacy, migrated** | seeded (= old key) | exists (old key) | `user add` with the same key (idempotent, no rotation) | renders → **adopts** the claim Secret (same key → no change), now GC'd with the claim | idempotent no-op; safe to retire |

The copy Object renders **only once the platform Secret is observed**, and the Object that observes the
platform Secret is marked ready, so a legacy claim stays Ready before it is migrated.

**Owner records move too.** The ownership check now reads `bucket-owner-<bucket>` from
`openinfra-bucket-creds`; records written earlier are in `minio`. Until they are copied, a claim whose
bucket predates the claim fails its setup Job with "has no owner record and predates …" (the Job
retries; the claim's app keeps its existing Secret and keeps working). The generator emits a copy for
each record, so run this migration right after the composition sync.

## Run it

```sh
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

# 1. Generate (read-only). It lists every live Bucket/StaticSite/ML/Application claim, computes the
#    scoped user name the composition uses, and emits a seed Object only where the claim Secret exists
#    and the platform Secret does not. Skips are printed to stderr.
./gen-seed-objects.sh > seed-objects.yaml

# 2. Review seed-objects.yaml. Each seed-creds-* Object copies data.MINIO_SECRET_KEY (or data.sk for a
#    db-backup Secret) from the named claim Secret into openinfra-bucket-creds/<user>; each seed-owner-*
#    Object copies an owner record from minio. None has a Delete management policy, so retiring them
#    later never deletes what they seeded.

# 3. Apply.
kubectl apply -f seed-objects.yaml

# 4. Verify each platform Secret now exists and carries a key, and that the composition adopted the
#    claim Secret. This compares a HASH of each claim Secret's data before/after — it must be UNCHANGED
#    (no rotation). Do the hashing yourself; do not print key values.
kubectl -n openinfra-bucket-creds get secret -l '!openinfra.dev/bucket-owner' -o name
#   for each claim: before = sha256 of (kubectl -n <ns> get secret <name>-minio -o jsonpath='{.data}')
#                   after  = same, after the composition reconciles — they MUST match.

# 5. Confirm the claim Secret is now provider-managed (has the provider's last-applied annotation),
#    i.e. it will be GC'd with the claim:
kubectl -n <ns> get secret <name>-minio -o jsonpath='{.metadata.annotations.kubectl\.kubernetes\.io/last-applied-configuration}' | head -c 1

# 6. Retire the migration once every claim shows the platform Secret and an adopted claim Secret. The
#    No-Delete policy means this leaves the platform Secrets in place:
kubectl delete objects.kubernetes.crossplane.io -l openinfra.dev/one-time-migration=bucket-creds-scoped
```

## Rollback

Deleting the seed Objects (step 6) leaves the platform Secrets, so the system stays on the new model. To
genuinely revert, restore the previous composition revision; the legacy claim Secrets were never changed,
so apps keep working throughout.
