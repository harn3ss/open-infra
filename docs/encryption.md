# Encryption with customer-owned keys

Encryption at rest keyed by **keys the customer owns and controls** (NIST SP 800-53 **SC-12**,
**SC-13**, **SC-28**, **SC-28(1)**). The key lives in a KMS the operator runs — open-infra never
sees key material — and the operator can rotate, disable, or **destroy** it. Destroying it
crypto-erases everything wrapped by it (the basis for [`crypto-erase`](destruction.md), SP 800-88).

> **Opt-in, off by default, experimental.** This is the `encryption` component. Enable it with
> `components.encryption: true` and re-run `install.sh`. It is shipped built + reviewed but **not**
> live-verified in this repo's reference environment, and — per design — it does not rewire your
> live etcd / MinIO / Longhorn for you. The storage-layer wiring below is an **operator runbook**.

## The pieces

| Piece | What it is | State |
|---|---|---|
| **Vault (Transit)** | the KMS holding customer keys (`platform/security/vault.yaml`) | shipped, opt-in |
| **`kind: EncryptionKey`** | a customer-owned KEK = a Vault Transit key | shipped, opt-in |
| **encryptionkey-reconciler** | provisions/rotates the Transit key per EncryptionKey | shipped, opt-in |
| **`longhorn-encrypted` StorageClass** | LUKS volumes (SC-28); additive, not the default | shipped, opt-in |
| **MinIO SSE-KMS (KES → Vault)** | object encryption with customer keys | runbook below |
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

The reconciler creates `transit/keys/tenant-a` in Vault and reflects its state (provisioned,
version, last rotation) into the console's **Security & Identity → Encryption Keys** page. It
authenticates to Vault with **its own Kubernetes ServiceAccount token** (Vault Kubernetes auth) — no
Vault credential is ever stored in a k8s Secret, so nothing with cluster-wide secret read can steal
Vault access. Its policy is scoped to **create / read / rotate** Transit keys only: it cannot
`delete`, cannot touch `transit/keys/<name>/config` or `/trim` (where `min_decryption_version` /
`deletion_allowed` — i.e. crypto-erase of old versions — live), and has no datakey/encrypt/export.
Destruction is withheld from the reconciler and gated behind `kind: Destruction`, which uses a
separately-authorized token — that is what makes crypto-erase a deliberate act.

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

The `vault-transit-setup` Job then enables the Transit engine and Kubernetes auth, and creates the
reconciler's role (bound to its ServiceAccount). No standing Vault secret is written anywhere.

```sh
# 4. The bootstrap token is a root/admin token and was ONLY needed for setup — REVOKE and DELETE it
#    once the setup Job has completed, so it can't be stolen later.
kubectl -n vault exec -it vault-0 -- vault token revoke <the-bootstrap-token>
kubectl -n vault delete secret vault-bootstrap
```

After that, create `EncryptionKey`s. Because the reconciler uses Kubernetes auth, there is no
`encryptionkey-reconciler-vault` Secret to guard — a console compromise cannot reach Vault through it.

## Storage-layer wiring (operator runbook)

These change how data at rest is encrypted; apply them deliberately (they are hard to reverse). Take
a snapshot first.

### Longhorn volumes (shipped SC — just use it)

Set `storageClassName: longhorn-encrypted` on a PVC and provide its LUKS passphrase in a Secret named
`<pvc-name>-crypto` (key `CRYPTO_KEY_VALUE`) in the PVC's namespace. For customer-owned keys, source
that passphrase from a `kind: EncryptionKey` — e.g. Vault Agent / external-secrets writes the Secret
from a Transit **datakey** (`vault write transit/datakey/plaintext/<key>`). Destroying the
EncryptionKey then makes the LUKS master key unrecoverable → the volume is crypto-erased.

### MinIO objects (SSE-KMS via KES)

Run [MinIO KES](https://github.com/minio/kes) pointing at Vault Transit, and point MinIO at KES:

```
# KES config → Vault Transit (keystore: vault, endpoint: http://vault.vault:8200, approle)
# MinIO:  MINIO_KMS_KES_ENDPOINT / MINIO_KMS_KES_KEY_NAME=<EncryptionKey name> / KES certs
mc encrypt set sse-kms <EncryptionKey-name> myminio/<bucket>
```

New objects in that bucket are then wrapped by the customer's Transit key.

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
