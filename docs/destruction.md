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
2. **Crypto-erases** — records what it observes (the key's version count) as `InProgress` *before*
   deleting, then sets `deletion_allowed` and deletes the Vault Transit key. Every DEK/volume/object
   wrapped by it is now undecryptable. If the key is **absent and no destruction was in progress**
   (e.g. a typo'd or never-existent key name), it does **not** proceed — it records `Error` and issues
   **no certificate**, because a certificate attesting to an erasure that never happened is worse than
   none. A crash between delete and certify resumes from the `InProgress` record (true count, no
   duplicate).
3. **Writes a destruction certificate** — a JSON record (key, versions destroyed, reason, time,
   SP 800-88 method) to the **WORM audit store** under `certificates/`, with COMPLIANCE retention. The
   certificate's original version cannot be deleted or overwritten until retention expires. Its
   **sha256 is anchored in the Kubernetes state** (a different trust domain than the bucket): S3
   versioning still lets a bucket-writer lay a *newer* version over it at "latest", but the locked
   original survives and can be verified against the anchored hash — the same shadowing caveat as
   [audit off-siting](audit-offsite.md#immutability-worm-vs-tamper-evidence-chain--stated-precisely).
4. **Records the outcome** — `status.phase` and the certificate path + sha256, shown on the console
   **Security & Identity → Encryption Keys** page.

The `Destruction` object's own create/complete lifecycle is captured in the API-server audit log,
which [audit off-siting](audit-offsite.md) makes tamper-evident — so **who** requested the erase and
**when** is independently anchored, beyond the certificate itself.

## Why it's safe to have

Destroying a key is irreversible, so the power is fenced hard:

- **Opt-in** (`components.encryption`), off by default.
- **Admin-only** — `destructions` is excluded from what a `kind: Policy` can grant; only the console
  ServiceAccount can create one.
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
- **Experimental**: shipped built + reviewed, not live-verified in the reference environment.

## Control mapping

- **MP-6 / MP-6(1)** Media Sanitization — cryptographic erase with a record of destruction.
- **SP 800-88** — the cryptographic-erase technique.
- **AU** — the destruction certificate + the tamper-evident `Destruction` lifecycle.
