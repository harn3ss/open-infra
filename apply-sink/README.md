# apply-sink

The generic CDC **apply engine** behind `kind: Migration`. It is the "load" half of
open-infra's database-migration path: [Debezium Server](https://debezium.io)
captures a source database's changes and publishes them to NATS JetStream, and
`apply-sink` consumes those change events and writes them to the target SQL
database. It replaces the previous Airbyte engine.

One static Go binary, two modes (selected by `MODE`):

### `MODE=schema-sync` (init step)
Connects to **both** source and target, introspects the source tables, and
auto-creates the equivalent tables on the target — including **cross-engine type
mapping** (e.g. SQL Server `NVARCHAR(MAX)` → Postgres `text`, `DATETIME2` →
`timestamp`). Runs once before streaming.

| env | meaning |
|-----|---------|
| `SOURCE_ENGINE` / `SOURCE_DSN` | source engine + DSN |
| `TARGET_ENGINE` / `TARGET_DSN` | target engine + DSN |
| `TABLES` | comma-separated `schema.table` list (empty = discover all) |

### `MODE=stream` (default, long-running)
Consumes Debezium-unwrapped JSON change events from a JetStream stream and applies
them to the target as **idempotent upserts/deletes**. The target table comes from
the subject; columns and primary key are discovered by introspecting the target.
Three upsert dialects: Postgres `ON CONFLICT`, MySQL `ON DUPLICATE KEY UPDATE`,
SQL Server `MERGE`. Messages that fail to apply are retried `MAX_DELIVER` times
then dead-lettered to `dlq.<subject>` (no poison loops).

| env | default | meaning |
|-----|---------|---------|
| `TARGET_ENGINE` / `TARGET_DSN` | `postgres` / — | target engine + DSN |
| `NATS_URL` | `nats://nats:4222` | NATS server |
| `STREAM` | `CDC` | JetStream stream to consume |
| `SUBJECT` | `cdc.>` | subject filter |
| `DURABLE` | `gosink` | durable consumer name |
| `MAX_DELIVER` | `5` | attempts before dead-letter |
| `TARGET_SCHEMA` | (per-engine) | override target schema/namespace |

Engines: `postgres`, `mysql`/`mariadb`, `sqlserver`.
