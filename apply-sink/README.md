# apply-sink

The generic CDC **apply engine** behind `kind: Migration` and `kind: Replication`.
It is the "load" half of open-infra's data-movement path: [Debezium
Server](https://debezium.io) captures a source database's changes and publishes
them to NATS JetStream, and `apply-sink` consumes those change events and writes
them to the target SQL database. It replaces the previous Airbyte engine.

One static Go binary, four modes (selected by `MODE`):

### `MODE=schema-sync` (Migration init step)
Connects to **both** source and target, introspects the source tables, and
auto-creates the equivalent tables on the target — including **cross-engine type
mapping** (e.g. SQL Server `NVARCHAR(MAX)` → Postgres `text`, `DATETIME2` →
`timestamp`). Runs once before streaming.

| env | meaning |
|-----|---------|
| `SOURCE_ENGINE` / `SOURCE_DSN` | source engine + DSN |
| `TARGET_ENGINE` / `TARGET_DSN` | target engine + DSN |
| `TABLES` | comma-separated `schema.table` list; empty or `*` = discover all tables |

### `MODE=mm-prep` (Replication init step)
Installs the multi-master machinery on one site: adds the version + origin columns
to each table and a **per-site stamping trigger** that records `(version, origin)`
on native writes and **skips replication-applied writes** (the apply path sets a
session flag). Per engine: Postgres a `BEFORE` trigger + a Hybrid Logical Clock;
SQL Server an `AFTER` trigger with a `TRIGGER_NESTLEVEL` guard + HLC (no
`BEFORE`-row triggers exist); MySQL a `BEFORE` trigger (ms-clock version).

| env | default | meaning |
|-----|---------|---------|
| `PREP_ENGINE` / `PREP_DSN` | `postgres` / — | the site's engine + DSN |
| `SITE` | — | short site id, stamped as the origin marker |
| `VERSION_COLUMN` | `_mm_version` | HLC version column |
| `ORIGIN_COLUMN` | `_mm_origin` | origin-marker column |
| `TABLES` | — | comma-separated `schema.table` list; `*` = all tables (PK-less tables skipped) |

### `MODE=stream` (default, long-running)
Consumes Debezium-unwrapped JSON change events from a JetStream stream and applies
them to the target as **idempotent upserts/deletes**. The target table comes from
the subject's last two segments; columns and primary key are discovered by
introspecting the target. Three upsert dialects: Postgres `ON CONFLICT`, MySQL
`ON DUPLICATE KEY UPDATE`, SQL Server `MERGE`. Failed messages are retried
`MAX_DELIVER` times then dead-lettered to `dlq.<subject>` (no poison loops).

For throughput, each fetched batch is applied in **one transaction** (one commit
per batch, not per row), and rows are applied in a deterministic `(table, primary
key)` order so concurrent sinks lock rows in the same order — deadlocks/serialization
failures are retried (not dead-lettered). On any batch error it falls back to
per-message apply so a single bad row is isolated.

| env | default | meaning |
|-----|---------|---------|
| `TARGET_ENGINE` / `TARGET_DSN` | `postgres` / — | target engine + DSN |
| `NATS_URL` | `nats://nats:4222` | NATS server |
| `STREAM` | `CDC` | JetStream stream to consume |
| `SUBJECT` | `cdc.>` | subject filter |
| `DURABLE` | `gosink` | durable consumer name |
| `MAX_DELIVER` | `5` | attempts before dead-letter |
| `TARGET_SCHEMA` | (per-engine) | override target schema/namespace |

**Multi-master mode** (set by `kind: Replication`) adds:

| env | meaning |
|-----|---------|
| `ORIGIN_COLUMN` | origin-marker column; drop events whose origin == `SKIP_ORIGIN` (loop prevention) |
| `SKIP_ORIGIN` | the peer/target site id whose changes must not be echoed back |
| `CONFLICT_COLUMN` | version column for last-write-wins (only overwrite when the incoming version is newer; origin breaks ties) |
| `REPL_APPLY` | `on` → set the per-engine session flag so this sink's writes skip the stamping trigger |

`${VAR}` in a DSN is expanded from the environment (e.g. `${TARGET_PASSWORD}` from
a Secret), so passwords are never baked into manifests.

Engines: `postgres`, `mysql`/`mariadb`, `sqlserver`.

### `MODE=pump` (the Transform stage of a Data Flow)
The ETL "transform" step of a `kind: DataFlow` function node: consume change events
from an upstream JetStream stream, **POST each event to an HTTP function**, and publish
the returned (transformed) event to a downstream stream — preserving the
`<schema>.<table>` tail so the next stage routes it. A `204`/empty response drops the
event (a filter). No database connection; it only moves + transforms events.

| env | default | meaning |
|-----|---------|---------|
| `NATS_URL` | `nats://nats:4222` | NATS server |
| `STREAM` / `SUBJECT` | — | upstream stream + subject filter to consume |
| `DURABLE` | `pump` | durable consumer name |
| `FUNCTION_URL` | — | HTTP endpoint that receives an event JSON and returns the transformed one |
| `OUTPUT_SUBJECT` | — | downstream subject prefix (the table tail is appended) |
