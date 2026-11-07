# Encryption with customer-owned keys

Encryption at rest keyed by **keys the customer owns and controls** (NIST SP 800-53 **SC-12**,
**SC-13**, **SC-28**, **SC-28(1)**). The key lives in a KMS the operator runs — open-infra never
sees key material — and the operator can rotate, disable, or **destroy** it. Destroying it
crypto-erases everything wrapped by it (the basis for [`crypto-erase`](destruction.md), SP 800-88).

> **Opt-in, off by default.** This is the `encryption` component. Enable it with
> `components.encryption: true` and re-run `install.sh`. It is shipped built + reviewed **and
> live-verified** on a running cluster by [`probe/encryption-vault.sh`](../probe/encryption-vault.sh)
> (a re-runnable gate: `kind: EncryptionKey` provisions a real Transit key, a value round-trips
> byte-identical through it, and `kind: Destruction` crypto-erases it to unrecoverable). It remains
> **operator-gated** — the customer holds the Vault unseal keys (open-infra cannot unseal your KMS) —
> and, per design, it does not rewire your live etcd / MinIO / Longhorn for you: the storage-layer
> wiring below is an **operator runbook**.

## The pieces

| Piece | What it is | State |
|---|---|---|
| **Vault (Transit)** | the KMS holding customer keys (`platform/security/vault.yaml`) | shipped, opt-in |
| **OpenBao** | the key service replacing Vault: three members, unsealed from outside the cluster ([`openbao.md`](openbao.md)) | built, opt-in; holds no keys yet |
| **`kind: EncryptionKey`** | a customer-owned KEK = a Vault Transit key | shipped, opt-in |
| **encryptionkey-reconciler** | provisions/rotates the Transit key per EncryptionKey | shipped, opt-in |
| **`longhorn-encrypted` StorageClass** | LUKS volumes (SC-28); additive, not the default | shipped, opt-in |
| **volume-crypto reconciler** | keys each encrypted volume's LUKS passphrase from its EncryptionKey | shipped, opt-in |
| **MinIO object encryption** | every new bucket encrypted by default, with the platform MinIO's own key (`storage/minio-kms.yaml`) | shipped, opt-in |
| **MinIO KES → Vault** | an optional keystore for customer-held object keys (crypto-erase) | shipped, opt-in, not wired |
| **etcd KMS provider** | Kubernetes Secrets encrypted at rest with a customer key | runbook below |

## `kind: EncryptionKey`

```yaml
apiVersion: openinfra.dev/v1
kind: EncryptionKey
metadata: { name: tenant-a, namespace: platform }
spec:
  description: "Customer-owned KEK for tenant A"
  keyType: aes256-gcm96     # or chacha20-poly1305, rsa-4096
  rotationDays: 90          # optional: reconciler adds a new key version on this cadence
```

The reconciler creates `transit/keys/ek_platform_tenant-a` in Vault and reflects its state
(provisioned, version, last rotation) into the console's **Security & Identity → Encryption Keys**
page. The Transit key's name is **namespace-qualified** — `ek_<namespace>_<name>` — so
`EncryptionKey tenant-a` in another namespace is a different Transit key, never the same one. The
path is recorded once on the key (`status.vaultKeyPath`) and never changes; every consumer — the
reconciler, encrypted volumes, `kind: Destruction` — resolves a key name **only within its own
namespace**, through that record. (A key created before namespacing keeps `transit/keys/<name>`.) It
authenticates to Vault with **its own Kubernetes ServiceAccount token** (Vault Kubernetes auth) — no
Vault credential is ever stored in a k8s Secret, so nothing with cluster-wide secret read can steal
Vault access. Its policy is scoped to **create / read / rotate** Transit keys only: it cannot
`delete`, cannot touch `transit/keys/<name>/config` or `/trim` (where `min_decryption_version` /
`deletion_allowed` — i.e. crypto-erase of old versions — live), and has no datakey/encrypt/export.
Destruction is withheld from the reconciler and gated behind `kind: Destruction`, which uses a
separately-authorized token — that is what makes crypto-erase a deliberate act.

### Who may USE a key (the AWS "key policy" equivalent)

`kind: EncryptionKey` has **no resource-attached key-policy field**, by design. AWS controls who may use
a CMK with a key policy stapled to the key; open-infra governs the same thing through its one
**identity-based** authorization authority (Cedar), at key granularity — never a second, resource-attached
policy engine running in parallel (which could become a divergent authority that silently ignores a
supplied document). When the KMS front door (`docs/aws-shim.md`) is enabled, a request to use a key is
authorized by a `kind: Policy` `spec.dataPlane` statement:

```yaml
# "alice may encrypt/decrypt with key tenant-a, and nothing else may" — the open-infra key policy.
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: tenant-a-key-access, namespace: open-infra-console }
spec:
  dataPlane:
    appliesTo: ["User::alice"]            # the key-policy Principal
    statements:
      - { effect: Allow, actions: ["kms:Encrypt", "kms:Decrypt"], resources: ["Key::<keyId>"] }
```

An AWS key-policy statement *"Principal P may `kms:X` on this key"* maps directly to this
(`appliesTo: [P]`, `Allow kms:X on Key::<keyId>`); the default key-policy root statement (which just
delegates to IAM) is the absence of a key-scoped restriction. The grant is enforced **per key** —
`probe/aws-shim-kms-keypolicy.sh` proves a grant on one key does not leak to another. Importing a supplied
AWS key-policy JSON into this shape (`CreateKey`'s `Policy` / `PutKeyPolicy`) is a scoped follow-on
; today, author the `kind: Policy` directly.

## Bringing Vault up (operator, one-time)

The whole point of customer-owned keys is that open-infra can't unseal your KMS for you.

```sh
# 1. Enable + sync the component
#    (config.yaml) components.encryption: true ; then ./install.sh

# 2. Initialize + unseal Vault (keep the unseal keys + root token safe, off-cluster)
kubectl -n vault exec -it vault-0 -- vault operator init      # → unseal keys + root token
kubectl -n vault exec -it vault-0 -- vault operator unseal    # x3 with different keys

# 3. Give the setup Job a SHORT-LIVED bootstrap token so it can enable Transit + Kubernetes auth
kubectl -n vault create secret generic vault-bootstrap --from-literal=token=<root-or-admin-token>
```

The `vault-transit-setup` Job then enables the Transit engine and Kubernetes auth, creates each
component's role (bound to its ServiceAccount), turns on Vault's audit device (every request, with
sensitive fields HMAC'd, to the Vault pod's log), and writes `vault-config`: Vault's configuration
administrator, a Kubernetes-auth role bound to the setup Job's own ServiceAccount with short-lived tokens.
Every later run of the Job (each sync) logs in as `vault-config`, so the root token is needed exactly once.
No standing Vault secret is written anywhere.

```sh
# 4. The bootstrap token is a root token and was ONLY needed for the first run — REVOKE and DELETE it
#    once the setup Job has completed (as AWS has an account's root credentials put away and its
#    automation use a role), so it can't be stolen later. The script revokes every other root token
#    (found by accessor, so none copied from an earlier bootstrap survives), then the bootstrap token
#    with itself, and shows a call made with it is refused — inside the cluster, printing counts only:
./scripts/vault-revoke-root.sh
kubectl -n vault delete secret vault-bootstrap
```

A root token can be generated again from the unseal keys (`vault operator generate-root`) should one be
needed for recovery.

After that, create `EncryptionKey`s. Because the reconciler uses Kubernetes auth, there is no
`encryptionkey-reconciler-vault` Secret to guard — a console compromise cannot reach Vault through it.

## Storage-layer wiring (operator runbook)

These change how data at rest is encrypted; apply them deliberately (they are hard to reverse). Take
a snapshot first.

**Why these are operator runbooks, not shipped manifests** (a deliberate choice, not a gap):
- **etcd KMS** is an API-server flag (`--encryption-provider-config`) plus a KMS-plugin static pod on the
  control-plane node — node/control-plane configuration that a GitOps controller cannot apply (k3s/RKE2
  serve it from a file on the server node). It is inherently an operator step.
- **MinIO object encryption** ships as a manifest (`components.objectEncryption`, below): it never
  re-encrypts existing objects, and it restarts MinIO once, deliberately, to load the key.
- **Longhorn** is the one layer that already ships as a manifest (the `longhorn-encrypted` StorageClass
  below) — because it is per-PVC and never touches a shared, live system.

### Longhorn volumes (shipped SC — just use it)

An encrypted `kind: Volume` (`spec.encrypted: true` + `spec.encryptionKey`), an encrypted VM data disk
(`dataDisks[].encrypted`) or root disk (`rootDisk.encrypted`, the OS image copied onto it before first
boot; see [virtual-machines.md](virtual-machines.md)), and an encrypted database (`storageEncrypted`) all land on the
`longhorn-encrypted` StorageClass and are keyed for you:

- **Keying.** The **volume-crypto reconciler** finds each claim on `longhorn-encrypted` that carries the
  annotation `openinfra.dev/encryption-key: <EncryptionKey name>`, generates a Vault Transit **data
  key** under the EncryptionKey of that name **in the claim's own namespace** (a claim cannot be keyed
  under another namespace's key — with no key of that name beside it, it waits), and writes the claim's
  LUKS passphrase Secret `<pvc-name>-crypto` in its namespace: the data key's plaintext is the passphrase, its wrapped form is stored alongside.
  Longhorn reads the plaintext whenever it opens the volume, so destroying the key alone would not
  erase the volume. A `kind: Destruction` of the EncryptionKey therefore also deletes the passphrase
  Secret of every volume under it, and those volumes are never keyed again: they are crypto-erased
  (see [`destruction.md`](destruction.md)). An existing passphrase Secret is never replaced, and
  passphrase Secrets are excluded from the Velero backups.
- **Ready means usable.** A claim on this class binds only once its passphrase Secret exists, and a
  `kind: Volume` reports **Ready only once its claim is Bound** — the point at which EBS reports a
  volume `available`. A CloudFormation `AWS::EC2::Volume` therefore completes when the disk can be
  attached, not when the request is accepted. Both reconcilers (EncryptionKey and volume-crypto) run
  every 5 minutes and, between runs, keep watching for new work every few seconds, so a new encrypted
  volume — and a new EncryptionKey it depends on — is normally keyed and bound within seconds of
  creation (up to about half a minute when it lands in the short gap between runs).
- **The passphrase lives exactly as long as its claim.** The Secret is owned by the claim
  (`ownerReference` by UID), so deleting the volume deletes its passphrase and crypto-erases whatever
  remains of it on disk; a claim already being deleted is never keyed. Passphrase Secrets that predate
  ownership are removed once their claim and any PersistentVolume bound to it are gone. Deleting the
  passphrase does not block deleting the volume — Longhorn needs it to open a volume, not to remove one.
- **Least privilege.** The reconciler's Vault role can only *generate* data keys — it cannot read,
  rotate, decrypt with, or destroy the EncryptionKey. Its Kubernetes Secret writes are confined by a
  `ValidatingAdmissionPolicy` to creating Opaque, labeled `<pvc-name>-crypto` Secrets and deleting
  Secrets that carry its label — it cannot write any other Secret (e.g. a service-account token).

To key a PVC of your own the same way, set `storageClassName: longhorn-encrypted` and annotate it with
`openinfra.dev/encryption-key`. To manage the passphrase yourself instead, omit the annotation and
provide the `<pvc-name>-crypto` Secret (key `CRYPTO_KEY_VALUE`) before creating the PVC.

**Limits.** Snapshots and backups of an encrypted volume are encrypted under its passphrase, which is
deleted with the volume — they are not readable once the volume is gone. Restoring a snapshot into a
new encrypted volume is not supported: the new volume is keyed with its own passphrase.

### MinIO objects (default bucket encryption)

Set `components.objectEncryption: true` and re-run `./install.sh` (or sync). This turns on object
encryption at rest for the platform MinIO with a **static 256-bit key that MinIO holds itself**
(`MINIO_KMS_SECRET_KEY`, in `secret/minio-kms` in ns `minio`). It has no availability dependency: no
Vault to unseal, no KES to reach. What it does:

- **Every new bucket is encrypted by default** (AES256, i.e. SSE-S3, under that key; what AWS gives every
  new bucket). `kind: Bucket`'s setup Job sets it on a bucket it creates, or one that is still empty.
  Buckets that already hold objects, including the backups and the audit WORM chain, are not touched,
  and existing objects are never re-encrypted.
- **`GetBucketEncryption` answers it**, and `GetObject`/`HeadObject` carry `x-amz-server-side-encryption`.
- **CloudFormation `BucketEncryption` deploys**: the aws-shim's front door accepts it with a caveat (an
  `aws:kms` key is not used; the platform key is). Off, it refuses the template rather than create an
  unencrypted bucket it asked to encrypt. The offline `cfn` CLI can't vouch for the cluster and always
  refuses.

**How it turns on.** One Job, `minio-kms-enable` (an Argo PostSync hook in ns `minio`), does it in an
order that keeps every MinIO server on one configuration:

1. waits until MinIO mounts the (optional) key Secret and has finished rolling out;
2. creates the key if there is none. It never overwrites one, and once encryption has been on it
   refuses to create a replacement (a new key could decrypt nothing);
3. if any server started before the key existed, **restarts all MinIO servers at once**. MinIO needs one
   configuration across servers, so a rolling restart would leave them disagreeing. Expect about a
   minute without object storage, once;
4. checks the key encrypts and decrypts (`mc admin kms key status`), and only then writes
   `configmap/openinfra-object-encryption` (`enabled: "true"`, `default: AES256`) in ns `minio` (read by the
   bucket setup) and ns `open-infra-aws-shim` (read live by the shim; no restart).

**Back up the key.** `secret/minio-kms` is the only copy. Lose it and every object written under it, and
MinIO's own IAM data written since (the per-bucket users), is unreadable. Copy it off the cluster as soon
as it exists, and restore it before MinIO starts if you rebuild:

```sh
kubectl -n minio get secret minio-kms -o yaml > minio-kms.backup.yaml   # store offline, like a root key
```

**Turning it off** is not a flag flip: objects written while it was on stay encrypted under the key, so
keep the key mounted. Removing the Secret makes them, and IAM entries written since, unreadable.

**Customer-held keys (KES → Vault).** `components.objectEncryptionKes: true` ships
[MinIO KES](https://github.com/minio/kes) with a **Vault KV** keystore (KES stores and wraps its own keys
there; it uses Vault's **KV** engine, not Transit), its `minio-kes` Kubernetes-auth identity and self-signed
KES↔MinIO mTLS. It is not wired to the platform MinIO: switching MinIO's key source to KES is an operator
step, and it makes object storage depend on Vault being unsealed (Vault needs a person to unseal it after
every restart). With KES, destroying a key crypto-erases its objects (reads fail `failed to decrypt
ciphertext`). `probe/sse-kms.sh` validates that flow (round-trip + crypto-erase) against a throwaway
MinIO, never the live one. NIST SC-28(1).

### etcd (Kubernetes Secrets at rest)

Configure the API server's `--encryption-provider-config` with a `kms` v2 provider backed by a Vault
KMS plugin, then `kubectl get secrets -A -o json | kubectl replace -f -` to re-encrypt existing
Secrets. On k3s this is a server flag + a static pod / config change — an operator action on the
control-plane node, intentionally not automated here.

## Data residency

Residency is enforced by **placement**: pin encrypted resources to nodes carrying a residency label
(e.g. `openinfra.dev/residency=<region>`) via `nodeSelector`, and require it through a
[`DataClassification`](data-classification.md)'s `residencyNodeLabel` — the classification auditor
reports any classified workload not pinned to the required nodes.

## Control mapping

- **SC-12 / SC-13** cryptographic key establishment & management — Vault Transit; `kind: EncryptionKey`.
- **SC-28 / SC-28(1)** protection of information at rest, **with customer-managed keys** — the KEK is
  the customer's; open-infra never holds key material.
- **MP-6 / crypto-erase** — destroying the key is media sanitization; see [`destruction.md`](destruction.md).
