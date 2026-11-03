# Crypto-erase — `kind: Destruction`

Sanitizing data at rest by overwriting terabytes is slow and, on replicated/again-copied storage,
never quite certain. **Cryptographic erase** (NIST SP 800-88, MP-6) is the fast, provable
alternative: if the data was only ever stored encrypted, destroying the key makes every copy —
primary, replica, backup, snapshot — permanently unrecoverable in one irreversible act.

open-infra builds this on [customer-owned keys](encryption.md): a `kind: EncryptionKey` is a Vault
Transit key, and `kind: Destruction` destroys it.

```yaml
apiVersion: openinfra.dev/v1
kind: Destruction
metadata: { name: erase-tenant-a, namespace: platform }
spec:
  encryptionKey: tenant-a
  confirm: tenant-a          # must EQUAL encryptionKey — a typo-guard; destruction is irreversible
  reason: "contract ended 2026-08; customer data must be destroyed"
```

## What happens

A dedicated **destroyer** (separate from the key reconciler, which deliberately *cannot* destroy —
see [`encryption.md`](encryption.md)) picks up the request and:

1. **Verifies the typo-guard** — `confirm` must equal `encryptionKey`, else it is `Refused`, untouched.
   `encryptionKey` names an EncryptionKey **in the Destruction's own namespace** — the destroyer
   destroys exactly the Transit key that key records (`ek_<namespace>_<name>`), so a Destruction can
   never erase another namespace's key by naming it. With no such key it records `Error` and destroys
   nothing. (A key whose EncryptionKey was already deleted is still found, through the key
   reconciler's record of that namespace + name.) A Transit key that another namespace is also on —
   possible only for same-named keys created before namespacing, which shared one — is refused
   (`Error`): destroying it would erase that namespace's data too. Two things count: any other
   EncryptionKey that records the key, and any encrypted volume in another namespace keyed under it,
   including one whose own EncryptionKey has since been deleted (data outlives the key object). If the
   volume list cannot be read, the run destroys nothing.
2. **Crypto-erases** — records what it observes (the key's version count) as `InProgress` *before*
   deleting, then sets `deletion_allowed` and deletes the Vault Transit key. Every DEK/volume/object
   wrapped by it is now undecryptable, and the key is never re-created for that EncryptionKey (a new
   EncryptionKey of the same name, created later, gets a new key). If the key is **absent and no destruction was in progress**
   (e.g. a typo'd or never-existent key name), it does **not** proceed — it records `Error` and issues
   **no certificate**, because a certificate attesting to an erasure that never happened is worse than
   none. A crash between delete and certify resumes from the `InProgress` record (true count, no
   duplicate).
3. **Erases the volumes under the key.** Longhorn reads an encrypted volume's LUKS passphrase from its
   `<pvc>-crypto` Secret every time it opens the volume, so that Secret holds the passphrase in plain
   text, and destroying the key alone would leave the volume readable. Once the key is gone, the
   volume-crypto reconciler deletes the passphrase Secret of every volume in the Destruction's
   namespace that was keyed under it, and never keys those volumes again. The Destruction stays
   `InProgress` until that is confirmed: the passphrases go within seconds, and the destroyer
   certifies on its next pass, within 5 minutes.
   A volume attached at that moment keeps working until it detaches, because the kernel holds its key
   (an attached EBS volume behaves the same after its KMS key is deleted). It can never be opened
   again, and neither can its Longhorn snapshots and backups, which are under the same passphrase.
4. **Writes a destruction certificate** — a JSON record (key, its namespace and exact Transit path,
   versions destroyed, how many volume passphrases were erased, reason, time, SP 800-88 method) to the **WORM audit store** under
   `certificates/<namespace>/`, with COMPLIANCE retention. The
   certificate's original version cannot be deleted or overwritten until retention expires. Its
   **sha256 is anchored in the Kubernetes state** (a different trust domain than the bucket): S3
   versioning still lets a bucket-writer lay a *newer* version over it at "latest", but the locked
   original survives and can be verified against the anchored hash — the same shadowing caveat as
   [audit off-siting](audit-offsite.md#immutability-worm-vs-tamper-evidence-chain--stated-precisely).
5. **Records the outcome** — phase (`Destroyed`/`Refused`/`Error`), the certificate path + sha256, and
   the time, shown on the console **Security & Identity → Encryption Keys** page. The privileged
   destroyer writes this to a single-writer **state ConfigMap**, which the console reads — it does **not**
   write back onto the `Destruction` CR, so the CR's own `status.phase` stays `Pending` even after a
   successful erase. Read completion from the **console** or the **WORM destruction certificate** (the
   authoritative evidence), not from `kubectl get destruction`. (The async destroyer runs with least
   privilege — Vault + the state ConfigMap + the WORM store — and deliberately has no write access to the
   CR's status.)

The `Destruction` object's own create/complete lifecycle is captured in the API-server audit log,
which [audit off-siting](audit-offsite.md) makes tamper-evident — so **who** requested the erase and
**when** is independently anchored, beyond the certificate itself.

## Why it's safe to have

Destroying a key is irreversible, so the power is fenced hard:

- **Opt-in** (`components.encryption`), off by default.
- **Who can request one.** For users, only administrators: a `kind: Policy` cannot grant
  `destructions`. For Kubernetes identities, anyone whose role covers `destructions` in a namespace:
  cluster administrators, the console's ServiceAccount, and any role that covers every open-infra kind
  there. Crossplane's generated `crossplane-edit` and `crossplane-admin` roles are such roles (Crossplane
  adds every claim kind to them), so binding them in a namespace grants Destruction too. Whoever creates
  it, a Destruction reaches only its own namespace's keys, much like an AWS principal allowed
  `kms:ScheduleKeyDeletion` on its own account's keys. Unlike KMS, there is no waiting period: the
  erase runs on the destroyer's next pass, within 5 minutes. The `confirm` field is the guard.
- **Typo-guard** — the `confirm` field must repeat the key name.
- **Separated privilege** — only the destroyer's Vault role can delete a key; day-to-day key
  management (the reconciler) cannot. The destroyer can delete keys but cannot read/export their
  material — it can destroy, not exfiltrate.

## Requirements & honesty

- Requires the **encryption** component (Vault) and **audit off-siting** (the certificate's WORM
  sink) to be enabled.
- Crypto-erase only sanitizes data that was **encrypted with that key**. Plaintext copies, or data
  encrypted under a different/again-wrapped key, are out of scope — classify and encrypt data (see
  [`data-classification.md`](data-classification.md), [`encryption.md`](encryption.md)) for the
  guarantee to hold.
- **Copies made outside the key.** The daily cluster backup (Velero, kept 7 days) copies each volume's
  *files*, which it reads decrypted, into its own repository under Velero's key; a Destruction does not
  reach those. (Passphrase Secrets are excluded from these backups.) etcd snapshots hold every Secret,
  the passphrases included, until they rotate. For a complete erase of a volume, delete the backups that cover its namespace and
  let the etcd snapshots taken while it existed age out, or wait out their retention.
- **Live-verified** end-to-end by [`probe/encryption-vault.sh`](../probe/encryption-vault.sh) — a
  re-runnable gate: provision a real Transit key → byte-identical round-trip → crypto-erase to
  unrecoverable + destruction certificate. Remains **opt-in + operator-gated** (the customer holds the
  Vault unseal keys). The at-rest *storage wiring* it protects (etcd KMS / MinIO SSE / Longhorn LUKS)
  is a separate operator runbook, not part of this verification — see [`encryption.md`](encryption.md).

## Control mapping

- **MP-6 / MP-6(1)** Media Sanitization — cryptographic erase with a record of destruction.
- **SP 800-88** — the cryptographic-erase technique.
- **AU** — the destruction certificate + the tamper-evident `Destruction` lifecycle.
