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
  to a MinIO bucket under **Object Lock in COMPLIANCE mode**: the object cannot be deleted or
  overwritten by anyone — including the MinIO root user or a cluster admin — until its retention
  expires. If an external sink is configured, it writes there too before advancing.
- **verify** (hourly) reads every segment back and re-derives the whole chain **from the segments'
  own contents**, trusting nothing it is told, and publishes the result for the console.

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

### Immutability (WORM) vs. tamper-evidence (chain)

These are two independent guarantees, deliberately:

- **Immutability** is the object store's: COMPLIANCE-mode Object Lock physically prevents deletion
  or overwrite of a shipped segment until retention expires. The exporter's MinIO identity is
  further scoped to *put and set retention, never delete* — least privilege on top of the lock.
- **Tamper-evidence** is the chain's: even if someone with full control of the bucket managed to
  remove or forge segments, `Verify` — run by the CronJob, by the console, or by anyone with read
  access — recomputes the chain and surfaces the break.

Neither claims to make tampering *impossible*; together they make already-shipped records
undeletable for the retention window and make any tampering **detectable**.

## Seeing it in the console

The **Audit** page shows a banner from `/api/audit/integrity` (admin-gated): green when the last
automated verification found the chain intact (with segment/record counts and the head sequence),
red with the break location if not, muted until the off-siter has run once.

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
- Between a segment being shipped and the next run, records live only on the node and in Loki; keep
  the interval short. A log rotation restarts the cursor and is a bounded coverage gap (logged),
  not an integrity gap — the chain stays contiguous.
- The queryable **Audit** view is still Loki; off-siting protects the *record of truth*, it does
  not change day-to-day querying.
