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
| MySQL / MariaDB | `BEFORE INSERT/UPDATE` + a Hybrid Logical Clock (`mm_hlc_state`) | `@app_replication` session var |

So a write to **any** engine is auto-stamped — no application changes required.
**All** engines advance a true, *monotonic* HLC (a shared `mm_hlc_state` row: the version is
`max(stored, wall-clock)` with a logical counter, and apply-side writes *observe* the remote
version) — so a backwards wall-clock (NTP step / skew) can never make a version go backwards
and silently lose last-write-wins. (This was hardened after a clock-skew chaos experiment caught
MySQL/MariaDB lacking the guard; see [`chaos.md`](chaos.md).)

## Topology

`kind: Replication` is a **pairwise, bidirectional** link (two sites). For three
or more nodes, compose pairwise links:

- **Mesh** — one `Replication` per pair (A↔B, B↔C, C↔A). A write reaches every node
  by multiple paths; the HLC version-guard makes the redundant deliveries no-ops,
  so it converges without looping.
- **Ring (round-robin)** — A→B→C→A. Lighter (one connector + one sink per node);
  each hop forwards a change until it returns to its origin, where the origin
  filter drops it. (A native N-node topology kind is a possible future addition.)

> **Resource cost of a mesh.** A mesh links *every* pair, so a node in an N-node
> mesh runs N−1 capture connectors **and** N−1 apply sinks — the engine-pod count
> grows ~N² (a 3-node mesh is ~12 capture/sink pods plus the 3 databases; a ring is
> ~2 per node). Size the cluster — and any namespace `ResourceQuota` — for that
> footprint: if capture/sink pods are rejected for lack of headroom, the affected
> links silently stop replicating and the mesh diverges even though each node looks
> healthy. A ring trades some redundancy for a much smaller footprint.

A 3-way **PostgreSQL + SQL Server + MySQL** ring has been validated end-to-end: a
write on any engine reaches the other two, and a concurrent 3-way conflict
converges to the newest write on all three.

## Observability

There's no separate status to wire up — open the resource in the console
(**Data → Replication → a replication**) to see **both directions**, each with its
replication **lag** (events captured but not yet applied), **per-table** event
counts, and a **dead-letter** panel. (Same view as a Migration; backed by
`GET /api/replications/{ns}/{name}/status`, which reads JetStream lag + DLQ.)

## Changing a table under multi-master (runbook)

A schema change that is trivial on a single database can silently corrupt a
multi-master mesh, because every member **applies remote rows to its own copy** of the
table. Three failure modes drive the whole runbook:

- **A member missing the column/table dead-letters.** If site A writes a row using a new
  column before site B has it, B's apply-sink can't land the row → it goes to the
  dead-letter queue and the sites diverge.
- **A per-site default diverges.** A `DEFAULT now()` / sequence / `AUTO_INCREMENT` is
  evaluated *independently on each member*, so the "same" replicated row gets a different
  value on every site — permanent divergence that LWW can't reconcile.
- **A lost stamping trigger freezes a row.** `mm-prep` installs `mm_stamp_trg`, which
  advances `_mm_version` on every native write. Some DDL (a table rewrite) drops the
  trigger; a write with a NULL `_mm_version` is *never* `>` an incoming version, so the row
  freezes under last-write-wins and drifts.

### The three rules

1. **Receivers before writers.** Apply the change to **every** member and verify it, *then*
   let any member write rows that use it. Never write the new shape before all members can
   receive it.
2. **Deterministic literal defaults only.** `DEFAULT 'active'`, `DEFAULT 0` — never
   `now()`, `CURRENT_TIMESTAMP`, `nextval`/sequences, `AUTO_INCREMENT`, or
   `uuid_generate_v4()` on a replicated table. Generate the value **once** in the
   application (or on a single member) so the concrete value replicates identically.
3. **Re-verify the stamping trigger last.** After the DDL, confirm `mm_stamp_trg` still
   exists on the table (and the `_mm_version`/`_mm_origin` columns). `mm-prep` is
   idempotent — re-run it if there's any doubt; a missing trigger is a silent diverger.

### Add a `NOT NULL` column

Do it in four ordered steps — the classic **nullable → backfill → default → NOT NULL** —
so no member ever sees a NULL it can't satisfy or a row it can't apply:

1. **Add it `NULL`able on every member.** A nullable column tolerates replicated inserts
   from a not-yet-migrated writer (the column arrives absent → NULL). A `NOT NULL` add with
   no default here would reject those inserts.
2. **Backfill on one member** with a deterministic value and let it replicate (the stamping
   trigger versions the backfill; LWW carries it to the others). Don't backfill the same
   rows on multiple members concurrently — that's a needless conflict storm.
3. **Add a literal default** for future inserts (`DEFAULT '<value>'`) — deterministic only.
4. **Set `NOT NULL` on every member** — only once the backfill has fully propagated (lag at
   zero, no dead letters), so no member still holds a NULL.

Then verify `mm_stamp_trg` (rule 3) and resume writes.

### Add a table

- **`kind: Replication`** does *not* auto-create tables. Create the table on **all** members
  with the **same primary key**, run `mm-prep` against each (or writes won't be stamped),
  then begin writing.
- **`kind: DataFlow` with `spec.autoSyncTables`** does this for you: the reconciler
  auto-creates the table cross-engine and `mm-prep`s it on every member. Caveat: a table
  that already holds rows on one member needs an **incremental snapshot** to backfill those
  pre-existing rows to the others — `autoSyncTables` wires up new writes, not history.

### Drop a column / rename

- **Drop:** reverse the order — stop writing *and* reading the column on all members first,
  then drop it everywhere. Dropping while a remote row in flight still carries that column
  makes the apply fail.
- **Rename:** don't rename in place (to CDC it's an incompatible drop+add, and it disturbs
  the trigger/columns). Instead: add the new column → backfill → switch the app → drop the
  old one, each step following the rules above.

### Cross-engine

On a heterogeneous mesh (e.g. Postgres + MySQL + SQL Server), only add columns whose type
has a clean cross-engine mapping, and mind the `DATE`/`timestamp` coercion rules (see
[`convergence-harness.md`](convergence-harness.md)). Never hand-edit `_mm_version` /
`_mm_origin` — they are owned by `mm-prep` and the stamping trigger.

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
