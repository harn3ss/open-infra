# Snapshots (final snapshot before deprovision)

> AWS equivalent: an **RDS final snapshot** — take one last snapshot of a database before
> you delete it, and restore it into a new database later.

Under **Backup → Snapshots** in the console, and as a checkbox in a database's **Danger
Zone**. A snapshot is a **logical dump (`pg_dump -Fc`) stored in MinIO**, decoupled from the
database — so it **survives the database's deletion** and can be restored into a new one.

## Why a logical dump (not a volume snapshot)

Managed database data lives on the `local-path` storage class, which has **no CSI volume-
snapshot support**. A logical dump sidesteps that, is **engine-portable**, and the artifact
is a plain object you can see in the bucket — it obviously outlives the resource. (VMs, whose
disks are on Longhorn, use a CSI/KubeVirt snapshot instead — see below.)

## Flow

1. **Take a snapshot** — from a database's **Danger Zone**, tick *"Take a final snapshot
   before deleting"* (default on): the delete **waits for the snapshot to complete**, then
   removes the database. Or take one anytime; it lands in **Snapshots**.
2. **Deprovision** — delete the database. The snapshot remains.
3. **Restore** — create a new (empty) database, then **Restore** the snapshot into it from
   the Snapshots page. Restore is a *new* resource, AWS-style — it never resurrects the old one.

## How it works

The console-api orchestrates it (no new `kind:`, same pattern as Volume snapshots): it reads
the database's connection secret and the MinIO credentials, and runs a throwaway Job:

- **snapshot:** `pg_dump -Fc "$URI" | mc pipe s3://db-snapshots/<ns>/<db>/<id>/dump.pgc`
- **restore:** waits for the target DB, then `mc cat … | pg_restore --clean --if-exists`

`GET /api/snapshots` lists them (status computed from the dump object's presence + size).

## Honest limits

- **In-cluster durability, not DR.** Snapshots live in MinIO — they survive the database's
  deletion, but not a total cluster / MinIO loss. Not an off-cluster backup. (The Longhorn
  backup target to an external store is a separate, still-open item.)
- **v1 is Postgres.** MySQL / Mongo / Babelfish use different dump tools — tracked follow-ups.
- **MinIO credentials are the root creds** for now; scoping the snapshot Job to a
  `db-snapshots`-only MinIO user is a tracked follow-up (as was done for `kind: Query`).
- **VMs** (KubeVirt, Longhorn-backed) will snapshot via a CSI/KubeVirt volume snapshot — a
  separate path, next on the list.

## See also

- [`databases.md`](databases.md) — managed databases.
- [`console.md`](console.md) — the console UI.
