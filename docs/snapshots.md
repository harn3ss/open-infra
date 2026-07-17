# Snapshots (final snapshot before deprovision)

> AWS equivalent: an **RDS final snapshot** — take one last snapshot of a database before
> you delete it, and restore it into a new database later.

Under **Backup → Snapshots** in the console, on a database's **Snapshots** tab, and as a
checkbox in its **Danger Zone**. A snapshot is decoupled from the database — it **survives the
database's deletion** and can be restored into a new one — and lands in **MinIO** either way.

## The snapshot primitive depends on where the data lives

open-infra has two storage tiers under databases, so it uses two snapshot mechanisms — picked
automatically by engine:

| Engine | Storage | Snapshot | Why |
|---|---|---|---|
| **Postgres** (CloudNativePG) | `local-path` NVMe | **logical `pg_dump -Fc` → MinIO** | local-path has **no CSI snapshot** support; a logical dump sidesteps that and is engine-portable |
| **Babelfish / MySQL / Mongo** | **Longhorn** | **CSI `VolumeSnapshot` (`longhorn-backup`) → MinIO** | physically consistent whole-disk backup; a `pg_dump` is *wrong* for babelfish — it drags in the babelfish extensions + `sys`/`master_`/`msdb_` catalog schemas |
| **VMs** | Longhorn | same `longhorn-backup` CSI path | (next) |

The `longhorn-backup` class (`type: bak`) uploads the snapshot to the Longhorn **backup target**
(the same MinIO), so it survives full deletion of the source PVC — verified: back up → delete the
source entirely → restore into a new volume → data returned. (The in-volume `longhorn-snapshot`
class would die with the PVC — it is not used here.)

## Flow

1. **Take a snapshot** — from a database's **Danger Zone**, tick *"Take a final snapshot
   before deleting"* (default on): the delete **waits for the snapshot to complete**, then
   removes the database. Or take one anytime; it lands in **Snapshots**.
2. **Deprovision** — delete the database. The snapshot remains.
3. **Restore** — create a new (empty) database, then **Restore** the snapshot into it from
   the Snapshots page. Restore is a *new* resource, AWS-style — it never resurrects the old one.

## How it works (Postgres)

The console-api orchestrates it (no new `kind:`, same pattern as Volume snapshots): it reads
the database's connection secret and the MinIO credentials, and runs a throwaway Job:

- **snapshot:** `pg_dump -Fc "$URI" | mc pipe s3://db-snapshots/<ns>/<db>/<id>/dump.pgc`
- **restore:** waits for the target DB, then `mc cat … | pg_restore --clean --if-exists`

`GET /api/snapshots` lists them (status computed from the dump object's presence + size).

## How it works (managed engines)

The console-api creates a durable `VolumeSnapshot` of the database's **data PVC**
(`data-<db>-babelfish-0`, `<db>-docdb-data`, …), tagged with the source + engine so the
Snapshots list can render it. The engine is detected from which connection secret exists — no
CRD read. Delete removes the `VolumeSnapshot` (and, via the backup deletion policy, its MinIO
backup). The **final-snapshot-before-delete** checkbox waits for the backup to *finish uploading*
before it removes the database — otherwise the snapshot wouldn't outlive it.

## Honest limits

- **In-cluster durability, not DR.** Snapshots live in MinIO — they survive the database's
  deletion, but not a total cluster / MinIO loss. Not an off-cluster backup.
- **Restore state:** Postgres (logical) restore is built; managed-engine (CSI) **create + delete**
  are built and validated — **restore-as-new** for managed engines (pre-seed the target PVC from
  the snapshot + reconcile the generated password) is the next step.
- **MinIO credentials are the root creds** for now; scoping to a snapshots-only MinIO user is a
  tracked follow-up (as was done for `kind: Query`). The Longhorn backup target reuses MinIO's
  root creds, kept fresh by a self-healing refresh CronJob (they had gone stale on a MinIO
  reprovision, which silently breaks all backups — see `platform/storage/longhorn-backup-setup.yaml`).
- **VMs** (KubeVirt, Longhorn-backed) will reuse this same `longhorn-backup` CSI path — next.

## See also

- [`databases.md`](databases.md) — managed databases.
- [`console.md`](console.md) — the console UI.
