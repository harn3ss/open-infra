# Audit off-siting — a tamper-evident, immutable copy of the audit trail

The Kubernetes API-server audit log is open-infra's authoritative "who did what" record: it carries
`impersonatedUser`, so console, `kubectl`, Terraform, and Argo actions all attribute to a person.
[`iam.md`](iam.md) and the console **Audit** view make it *readable*. This document is about making
it *trustworthy* — copied off the machine that writes it, protected from modification, and provably
un-altered — which is what NIST SP 800-53 asks of audit records:

| Control | What it wants | How open-infra meets it |
|---|---|---|
| **AU-9** Protection of Audit Information | Audit records protected from unauthorized modification/deletion | WORM object lock + hash chain (below) |
| **AU-9(2)** Store on a separate system | A copy on a different physical/logical system | Off-site S3 sink (operator-configured) |
| **AU-9(3)** Cryptographic protection | Detect modification cryptographically | SHA-256 hash chain, re-verified from contents |
| **AU-11** Retention | Retain audit records for a defined period | COMPLIANCE retention, default ~7 years |

## How it works

`audit-offsite` (a small Go program, `console-api/cmd/audit-offsite`, sharing
`internal/auditchain` with the console) runs as two CronJobs in the `monitoring` namespace:

- **ship** (every 5 min) reads the audit log **at its source** — the file on the k3s server node,
  read-only, not from Loki — so off-siting does not depend on the integrity of the in-cluster log
  store. It appends the new records as the next **segment** in a hash chain and writes that segment
  to a MinIO bucket under **Object Lock in COMPLIANCE mode**, so that object *version* cannot be
  deleted, overwritten in place, or have its retention shortened by anyone — including the MinIO
  root user or a cluster admin — until retention expires. ship resumes from the **bucket head** (the
  WORM record of truth), not a mutable side cursor, so a crash between writes can never fork the
  chain; rotation is detected by file **inode**, not size, so a rotated-then-regrown log can't cause
  a silent gap. If an external sink is configured, it writes there too.
- **verify** (hourly) reads every segment's **locked original version** back and re-derives the whole
  chain **from the segments' own contents**, trusting nothing it is told, then records the verified
  head (seq + hash) in a Kubernetes **ConfigMap anchor** — a different trust domain than the object
  bucket — and publishes the result for the console.

### The hash chain (tamper-evidence)

Each segment carries its records, the SHA-256 of the previous segment (`prevHash`), and its own
hash over all of that. So:

- **editing a record** changes the segment hash → the next segment's `prevHash` no longer matches;
- **deleting a segment** leaves a gap in the contiguous sequence numbers;
- **reordering** breaks the `prevHash` links.

`Verify` detects all three and reports the first break (`brokenAt` + a reason). It is a *pure*
function with a table of unit tests covering edit / reforge / delete / reorder / front-truncation.
Front-truncation (old segments aging past retention and dropping off the front) is allowed and
distinguished from a mid-chain hole by a non-zero base sequence.

### Immutability (WORM) vs. tamper-evidence (chain) — stated precisely

These are two independent guarantees, and it is worth being exact about what each does and does not
cover, because the interesting adversary here is a *privileged insider* (AU-9's whole point):

- **Immutability** is the object store's, and it protects a specific object **version**:
  COMPLIANCE-mode Object Lock means a shipped segment version cannot be deleted, overwritten in
  place, or have its retention shortened until retention expires — not even by MinIO root. The
  exporter's identity is further scoped to *put and set-retention, never delete*.
  - What lock does **not** prevent: S3 versioning still lets a bucket-writer lay down a *newer*
    version, or a delete marker, that shadows the locked original at the "latest" layer. So a naive
    "read latest" would be fooled even though the original survives.
- **Tamper-evidence** is this system's, and it is built to see through exactly that:
  - `verify` reads each segment's **oldest (locked) version**, never "latest", so a shadowing
    overwrite cannot change what is verified; and it **counts** any delete marker or
    content-differing newer version as a detected tamper attempt.
  - the chain links each segment to the previous by hash, so an edit/reorder/mid-chain deletion of
    the locked originals (were it even possible) breaks it.
  - the verified head (seq + hash) is anchored in a Kubernetes ConfigMap — a **different trust
    domain** than the bucket — and the console requires the bucket's reported head to match the
    anchor and be fresh before it shows green. Forging the record undetectably would require
    compromising **both** the object bucket and Kubernetes RBAC. The strongest anchor is the
    optional external off-site bucket (AU-9(2)): a copy the cluster cannot reach at all.

Neither makes tampering *impossible*. Together they make already-shipped record versions undeletable
for the retention window and make any tampering **detectable** — including by a bucket-privileged
insider, which is the case that matters.

## Seeing it in the console

The **Audit** page shows a banner from `/api/audit/integrity` (admin-gated). It does **not** trust
the bucket's published status on its own — it cross-checks the reported head against the ConfigMap
anchor (a different trust domain) and requires the verification to be fresh. Green means: chain
verified, no shadowing versions, anchor agrees, recent. Red names the reason — a chain break, a
shadowing attempt, an anchor mismatch, or a stale verification.

## Configuration

Provisioning (`platform/security/audit-offsite.yaml`) creates the locked bucket
(`openinfra-audit`) and a scoped `openinfra-audit-offsite` MinIO identity automatically. Tunables
on the `audit-offsite-ship` CronJob:

- `RETENTION_DAYS` — per-segment COMPLIANCE retention (default `2555`, ~7 years). Cannot be
  shortened after a segment is written.
- **External off-site copy (AU-9(2))** — set `OFFSITE_ENDPOINT` / `OFFSITE_BUCKET` /
  `OFFSITE_ACCESS_KEY` / `OFFSITE_SECRET_KEY` (and `OFFSITE_SECURE=true`) to also write each
  segment to an operator-controlled S3 outside the cluster. When set, the cursor does not advance
  until the off-site write succeeds, so a copy on a separate system is not silently skipped.

## Limits (stated plainly)

- The ship job needs to read a `0600` root-owned file on the server node, so it runs as root,
  read-only, with every capability dropped — the same access `promtail` already has.
- **Restricted-PSA caveat.** Because it needs root + a `hostPath`, the ship job is inherently not
  `restricted`-Pod-Security-compliant, and no image change fixes that (reading the `0600` audit file
  requires it). On a substrate that enforces `restricted` PSA **cluster-wide** (RKE2 `profile: cis`,
  OpenShift/OKD), grant the `monitoring` namespace a PSA exemption —
  `pod-security.kubernetes.io/enforce=privileged` — or the ship job is rejected at admission and the WORM
  copy silently stops. On non-cluster-wide substrates (the default, and open-infra's own hardened profile,
  which enforces restricted only on the console namespace) it runs unchanged. A future substrate that
  forbids `hostPath` entirely (e.g. OKD) needs a different collection mechanism (a log-forwarder), not
  this job.
- Between a segment being shipped and the next run, records live only on the node and in Loki; keep
  the interval short. A log rotation restarts at offset 0 of the new file and is a bounded coverage
  gap (logged), not an integrity gap — the chain stays contiguous.
- **Scope of the immutable copy.** The off-sited, tamper-evident record is the **k3s API-server
  audit log**. It records every mutation, and for impersonated calls (console/kubectl/Terraform/Argo)
  it carries `impersonatedUser`, so those attribute to a **person** even in the WORM copy. The
  console's extra `iam:` person-attribution for *BFF-native* IAM actions lives only in Loki and is
  **not** in the WORM copy — there, such an action attributes to the console ServiceAccount (the
  action itself is still captured). AU-10 person-level non-repudiation therefore holds for
  impersonated k8s actions; treat the Loki `iam:` stream as enrichment, not as tamper-evident.
- The queryable **Audit** view is still Loki; off-siting protects the *record of truth*, it does
  not change day-to-day querying.
