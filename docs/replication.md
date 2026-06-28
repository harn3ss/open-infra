# Replication (bidirectional / multi-master)

> **Part of [Data Flows](dataflow.md).** This is one mode of open-infra's data-movement
> layer — the same engine, surfaced on its own. The console's **Data Flows** canvas is the
> unified place to build and observe these visually.

`kind: Replication` keeps **two database sites in sync both ways** — each is
source *and* target — like a SymmetricDS / AWS-DMS bidirectional task. Sites may
be **different engines** (e.g. **SQL Server ↔ PostgreSQL ↔ MySQL**). It runs on
open-infra's own engine (Debezium + NATS JetStream + the [apply-sink](../apply-sink/)).

```
siteA ⇄ Debezium ⇄ NATS JetStream ⇄ apply-sink ⇄ siteB
```

Per site a Debezium connector captures changes onto a capped JetStream stream;
per direction an apply-sink applies the peer's changes with:

- **Loop prevention** — an origin-marker column. Every write carries the site it
  originated at; a sink drops events that originated at the peer, so a change
  never echoes back and loops.
- **Conflict resolution** — last-write-wins on a **Hybrid Logical Clock (HLC)**
  version column. The HLC advances when a node observes a remote timestamp, so a
  causally-later write wins **even if the writer's wall-clock is skewed**. Ties
  break deterministically on the origin marker. Applied via each engine's native
  upsert: Postgres `ON CONFLICT … WHERE`, SQL Server `MERGE … WHEN MATCHED AND`,
  MySQL `ON DUPLICATE KEY UPDATE … IF(…)`.
- **Safety** — capped streams + dead-lettering in the apply-sink (a row that keeps
  failing is parked in a DLQ, not retried forever, and never blocks other rows).

## Spec

```yaml
apiVersion: openinfra.dev/v1
kind: Replication
metadata: { name: east-west, namespace: data }
spec:
  siteA:
    name: east                # origin marker (unique in the pair)
    engine: postgres
    host: pg-east-rw.data.svc
    database: app
    username: repl
    passwordSecretRef: { name: east-creds }
  siteB:
    name: west
    engine: sqlserver
    host: mssql-west.data.svc
    port: 1433
    database: app
    username: sa
    passwordSecretRef: { name: west-creds }
  tables: ["customers", "orders"]   # must exist on both sites, same PK
```

## How a site is prepared (`mm-prep`)

An `mm-prep` Job per site adds the version + origin columns and installs the
per-site **stamping trigger** that records `(version, origin)` on every *native*
write, and **skips replication-applied writes** (the apply path sets a session
flag) so replicated rows keep the original site's `(version, origin)`:

| Engine | Trigger | Skip flag |
|--------|---------|-----------|
| PostgreSQL | `BEFORE INSERT/UPDATE` + a Hybrid Logical Clock | `app.replication` GUC (DSN `options=-c`) |
| SQL Server | `AFTER INSERT/UPDATE` (no `BEFORE`-row triggers) with a `TRIGGER_NESTLEVEL` recursion guard, HLC | `SESSION_CONTEXT('app_replication')` |
| MySQL / MariaDB | `BEFORE INSERT/UPDATE`, ms-clock version | `@app_replication` session var |

So a write to **any** engine is auto-stamped — no application changes required.
(Postgres and SQL Server advance a true HLC, including on apply; MySQL uses a
millisecond wall-clock version, comparable for cross-engine LWW.)

## Topology

`kind: Replication` is a **pairwise, bidirectional** link (two sites). For three
or more nodes, compose pairwise links:

- **Mesh** — one `Replication` per pair (A↔B, B↔C, C↔A). A write reaches every node
  by multiple paths; the HLC version-guard makes the redundant deliveries no-ops,
  so it converges without looping.
- **Ring (round-robin)** — A→B→C→A. Lighter (one connector + one sink per node);
  each hop forwards a change until it returns to its origin, where the origin
  filter drops it. (A native N-node topology kind is a possible future addition.)

A 3-way **PostgreSQL + SQL Server + MySQL** ring has been validated end-to-end: a
write on any engine reaches the other two, and a concurrent 3-way conflict
converges to the newest write on all three.

## Observability

There's no separate status to wire up — open the resource in the console
(**Data → Replication → a replication**) to see **both directions**, each with its
replication **lag** (events captured but not yet applied), **per-table** event
counts, and a **dead-letter** panel. (Same view as a Migration; backed by
`GET /api/replications/{ns}/{name}/status`, which reads JetStream lag + DLQ.)

## Notes & limits

- **CDC prerequisites** (same as [Migrations](migrations.md)): Postgres
  `wal_level=logical`; MySQL `binlog_format=ROW` (default on MySQL 8); SQL Server
  CDC enabled + the SQL Server Agent running.
- **Tables must already exist on both sites** with the same primary key (unlike
  Migration, which auto-creates the target schema). `mm-prep` only adds the
  version/origin columns + triggers.
- **Delete-vs-concurrent-update** is an inherent multi-master ambiguity (a delete
  can race an update and "resurrect" the row). For delete-heavy workloads use
  soft-deletes/tombstones, which ride the normal update + LWW path.
- **Teardown leaves external state.** Deleting a `Replication` removes its
  Kubernetes objects, but the JetStream streams (`repl-<name>-<site>`) and the
  Postgres replication slots (`mm_<name>_<site>`) are NATS/DB objects that outlive
  the namespace. Until an automatic GC (finalizer) lands, clean them up manually:
  `nats stream rm repl-<name>-<site>` and drop the slot on the source Postgres.
- Requires the `nats` component.
```
