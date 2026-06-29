# Data Flows (`kind: DataFlow`)

**Data Flows is open-infra's visual data-movement layer** — one drag-and-drop canvas
(and one resource) that unifies what AWS splits across DMS, Glue, Kinesis and Lambda.
You place databases, message topics, transform functions and object-store buckets on a
canvas, connect them, and deploy the whole topology as a single `kind: DataFlow`.

Multi-master **replication**, one-way **migration**, **CDC-to-topic** fan-out, and
**ETL transforms** are not separate products here — they are just *edge types* between
nodes on the same canvas.

> Migrations and Replication still exist as their own kinds ([`migrations.md`](migrations.md),
> [`replication.md`](replication.md)) and as the engine underneath. DataFlow is the
> unifying canvas on top — in the console, **Data Flows** is the single data-movement
> entry point.

---

## The canvas

Console → **Data → Data Flows**. Two ways in:

- **Set up replication** (guided wizard) — add your databases, mark each "already has the
  data" or "empty", and it explains the plan in plain language (seed the empty members
  from a source of truth, merge the rest by last-write-wins, then keep all in sync) and
  deploys a star-topology DataFlow.
- **Blank canvas** — design any topology by hand.

### Node types (the palette)

| Node | What it is |
|---|---|
| **Database** | a Postgres / MySQL / MariaDB / SQL Server endpoint (configured once) |
| **Topic** | a message stream apps/consumers subscribe to (fan-out) |
| **Function** | an HTTP transform applied to events in flight |
| **Bucket** | an object-store (S3/MinIO) sink |

Right-click a node for **Configure properties** (the side inspector) or **Peek metrics**
(see [Observability](#observability)).

### Edge types (inferred from what you connect)

| You connect… | Edge becomes | Behaviour |
|---|---|---|
| database ↔ database | **replication** | bidirectional multi-master (HLC last-write-wins, loop-prevented); optional **bootstrap** to seed an empty target |
| database → database | **migration** | one-way; auto-creates the target schema + cross-engine type mapping |
| database → topic | **stream** | publish the source's CDC as a consumable stream (fan-out to many readers) |
| anything → function / database / bucket | **pipe** | a one-way ETL leg: transform, load, or store |

**Fan-out** is just connecting one source to several targets — each consumer reads the
same stream independently (drop one, the others are unaffected).

A two-node, one-edge DataFlow is exactly a single Migration or Replication; the canvas
scales the same primitive up to arbitrary pipelines.

---

## The resource

```yaml
apiVersion: openinfra.dev/v1
kind: DataFlow
metadata: { name: customers-pipeline, namespace: data }
spec:
  tables: ["customers", "orders"]   # or ["*"] for every table
  nodes:
    - { name: east,  engine: postgres,  host: pg-east,  port: 5432, database: app,
        username: app, passwordSecretRef: { name: flow-creds, key: east-password } }
    - { name: west,  engine: sqlserver, host: mssql,    port: 1433, database: app,
        username: sa,  passwordSecretRef: { name: flow-creds, key: west-password }, schema: dbo }
    - { name: enrich, role: function, functionUrl: "http://enrich.fns.svc.cluster.local:8080" }
    - { name: archive, role: bucket, bucket: cdc-archive, prefix: customers/ }
  edges:
    - { from: east, to: west,    type: replication, bootstrap: true }  # seed empty SQL Server, then sync both ways
    - { from: east, to: enrich,  type: pipe }                          # transform
    - { from: enrich, to: archive, type: pipe }                        # store transformed events
```

Node `x`/`y` (canvas positions) are persisted so the diagram reloads exactly. The
console creates the credential `Secret` for you from the password fields.

### `tables: ["*"]` — all tables

`*` (or an empty list) means **every table**: Debezium captures all tables (excluding
open-infra's own bookkeeping table), and schema-sync / multi-master prep discover the
full table set instead of a fixed list. Tables without a primary key are skipped (a
primary key is required for upsert-style apply).

### `bootstrap` — seed an empty member

A replication edge with `bootstrap: true` creates the target's tables from the source
first, then the initial rows load via the CDC snapshot — so a two-way link can bring an
**empty** database online and keep it in sync, in one step. (This is what lets the wizard
handle "DB A has the data, DB B is empty".)

### `autoSyncTables` — keep the table set in sync automatically

For a multi-master flow, set `spec.autoSyncTables: true` and you never manage tables by
hand: a table created on **any** member is automatically created on every other member
(cross-engine, with type mapping) and made multi-master-ready (version/origin columns +
stamping trigger). A per-flow `reconcile` worker holds connections to all members, diffs
their table sets every ~20s, and reconciles; it also enables SQL Server CDC on new tables.
Enabling it implies **capture-all CDC** so new tables are picked up without a spec edit.

Caveat: a table created **already full of data** won't back-load its existing rows until a
Debezium incremental snapshot runs — the common *create-then-insert* flow syncs fully (the
table is created on peers and new rows replicate). Tables without a primary key are skipped.

---

## How the engine works

DataFlow compiles onto the same Debezium + NATS JetStream + apply-sink engine as Migration,
Replication and Stream:

- **Per source node** → a Debezium connector captures changes onto a capped JetStream
  stream `flow-<name>-<node>` (subjects `f.<name>.<node>.>`). Both database nodes *and*
  function nodes publish such a stream, so stages compose.
- **Per replication node** → an `mm-prep` job installs the version + origin columns and a
  per-site stamping trigger (Hybrid Logical Clock; see [`replication.md`](replication.md)).
- **Per replication edge** → two `apply-sink` workers (one each way) with origin-marker
  loop prevention and HLC last-write-wins.
- **Per migration / pipe-load edge** → a `schema-sync` job (auto-create target tables) +
  one `apply-sink`.
- **Per function node** → a **pump** (`apply-sink` in `MODE=pump`): it consumes the upstream
  stream, POSTs each change event to the function over HTTP, and publishes the returned
  event to the function's own stream for the next stage. A `204`/empty response drops the
  event (a filter).
- **Per stream edge** → nothing extra: the source's stream *is* the topic; consumers read
  `f.<name>.<node>.>`.

### Function contract

A transform function is any HTTP endpoint (or a `kind: Function`). It receives one change
event as JSON (the unwrapped row + `op`), and returns the transformed event JSON. Return
`204`/empty to drop the event.

---

## Observability

- **Live edge overlay** — open a deployed flow and each replication/migration edge shows
  its health with a live lag number. State is encoded **without relying on colour** (WCAG
  1.4.1, colour-blind-safe): the line **pattern** is the primary cue — solid = in sync,
  dashed = lagging, dotted = dead-letters, sparse dots = not provisioned — alongside a shape
  glyph (✓ / ▲ / ✕ / ○) and an Okabe-Ito palette. Refreshes every 4s from JetStream (the
  browser can't read NATS, so the BFF aggregates it).
- **Peek** — right-click any node → **Peek metrics** for that step:
  - *Outbound* (sources): captured messages, buffered size, per-table throughput, and each
    downstream consumer's lag / in-flight / retries / dead-letters.
  - *Inbound* (sinks/targets): backlog, applying, retries and dead-letters for what's being
    written into the step.

Served by `POST /api/dataflows/{ns}/{name}/status` in the console BFF.

---

## Prerequisites

- **CDC enabled** on every source database: Postgres `wal_level=logical`; MySQL/MariaDB
  binlog (ROW); SQL Server needs the SQL Agent running and a sysadmin login — per-table CDC
  is then enabled automatically (by `mm-prep` / the auto-sync reconciler), so no manual
  `sys.sp_cdc_enable_table` is required for managed flows.
- **A primary key** on every table that's replicated/loaded (required for upsert apply).
- For replication, participating tables must exist (or use `bootstrap`) and share the same
  primary key across members.

## Operational notes (learned from load testing)

- **Throughput:** apply-sinks batch each fetched group into one transaction (one commit per
  batch, not per row) — large gains over single-row apply.
- **Deadlocks:** each batch is applied in a deterministic `(table, primary key)` order so
  concurrent sinks lock rows in the same order (deadlocks become benign waits), with a
  retry backstop.
- **Topology under sustained load:** prefer a **star / spanning topology** (the wizard's
  default) over a fully-connected mesh. In a full mesh every write propagates via multiple
  paths and amplifies; a star gives each write a single path and converges cleanly.
- **Keeping the table set in sync:** with `autoSyncTables` a table added on one member is
  created + prepared everywhere automatically. Without it, `*` across a mesh requires the
  *same* tables on every member — a table present on only one node stalls that leg.
- **Durability:** Debezium offsets + schema history live on a per-node Longhorn PVC, so a
  capture-pod restart resumes from its position instead of re-snapshotting the whole source.
- **Apply safety:** consumers use `AckWait` 2m (a slow batch isn't redelivered mid-
  transaction); `mm-prep` backfills version/origin on pre-existing rows (a `NULL` version
  can never win last-write-wins); unchanged TOASTed Postgres columns are never overwritten
  with Debezium's unavailable-value placeholder.
- Each capture/transform stream reserves 512 MB (`discard=old`); size JetStream storage for
  the number of streams (one per source/function node). A garbage-collector reaps the
  streams/DLQ of deleted flows.

## See also

- [`migrations.md`](migrations.md) — one-way DB migration (`kind: Migration`)
- [`replication.md`](replication.md) — multi-master internals (HLC, loop prevention)
- [`streaming.md`](streaming.md) — CDC → JetStream (`kind: Stream`)
- [`console.md`](console.md) — the console UI
