# Migrations (DMS)

> **Part of [Data Flows](dataflow.md).** This is one mode of open-infra's data-movement
> layer — the same engine, surfaced on its own. The console's **Data Flows** canvas is the
> unified place to build and observe these visually.

`kind: Migration` is open-infra's Database Migration Service — AWS-DMS-style
replication: **full-load and/or ongoing CDC** from a source database into a target
SQL database. Source and target engines may differ (e.g. **SQL Server → Postgres**).

It runs entirely on open-infra's own engine (no external SaaS):

```
source DB ──▶ Debezium Server ──▶ NATS JetStream ──▶ apply-sink ──▶ target DB
              (CDC capture)        (durable bus)      (upsert/delete + auto-schema)
```

- **Debezium Server** captures the source's change log (Postgres logical decoding,
  MySQL/MariaDB binlog, SQL Server CDC) and publishes each row change to a JetStream
  stream `mig-<name>` on subjects `mig.<name>.<schema>.<table>`.
- **[apply-sink](../apply-sink/)** consumes those events and applies them to the
  target with the engine's native upsert (Postgres `ON CONFLICT`, MySQL
  `ON DUPLICATE KEY UPDATE`, SQL Server `MERGE`). A schema-sync step introspects the
  source and **auto-creates the target tables with cross-engine type mapping**.

The user only ever sees `kind: Migration` / the console.

## Spec

```yaml
apiVersion: openinfra.dev/v1
kind: Migration
metadata:
  name: crm-to-warehouse
  namespace: data
spec:
  mode: full-load-and-cdc          # full-load | cdc | full-load-and-cdc (default)
  source:
    engine: sqlserver              # postgres | mysql | mariadb | sqlserver
    host: mssql.corp.svc
    port: 1433
    database: crm
    username: dms_reader
    passwordSecretRef: { name: crm-creds, key: password }
    schemas: ["dbo"]               # postgres/sqlserver; ignored for mysql
  target:
    engine: postgres               # postgres | mysql | sqlserver
    host: warehouse-rw.data.svc
    port: 5432
    database: analytics
    username: loader
    passwordSecretRef: { name: warehouse-creds, key: password }
  tables: ["customers", "orders"]  # optional; empty = all tables
```

Passwords always come from Secrets — they're injected into the Debezium and
apply-sink pods as env and expanded into the connection DSNs at runtime, never
inlined into manifests.

## Modes

| mode | behaviour |
|------|-----------|
| `full-load` | one-shot snapshot of existing rows |
| `cdc` | ongoing change-data-capture only (no initial snapshot) |
| `full-load-and-cdc` | snapshot, then keep in sync continuously (**default**) |

A Migration is **continuous** — once created it runs on its own (snapshot then
stream). There is no manual "sync" button; status comes from the resource's
conditions.

## Monitoring

Open a Migration in the console for a live **Capture → Buffer → Apply** view: the
headline **replication lag** (events captured but not yet applied to the target),
**per-table** event counts, and a **dead-letter** panel listing rows that failed to
apply. It's backed by `GET /api/migrations/{ns}/{name}/status`, which reads the
JetStream stream + consumer (lag) + DLQ — signals the engine exposes natively, so
there's nothing extra to wire up.

## CDC prerequisites on the source

- **Postgres** — `wal_level=logical`.
- **MySQL / MariaDB** — `binlog_format=ROW` (default on MySQL 8); the user needs
  `REPLICATION SLAVE` + `REPLICATION CLIENT`.
- **SQL Server** — CDC enabled (`sys.sp_cdc_enable_db` / `sp_cdc_enable_table`) and
  the SQL Server Agent running.

## Notes & limits

- **Reliability** — at-least-once delivery with idempotent upserts; messages that
  fail to apply are retried and, if persistently bad, dead-lettered to `dlq.<subject>`
  (no poison loops). The JetStream stream is size-capped.
- **Schema sync** runs at start for the selected tables; new tables added later
  aren't auto-created (re-create the Migration or pre-create them).
- **Type mapping** covers the common types across Postgres/MySQL/SQL Server
  (numeric, text/varchar, temporal, boolean, uuid, bytea). Exotic/vendor-specific
  types may need a pre-created target column.
- Requires the `nats` component (the JetStream bus, shared with `kind: Stream`).

Compare with [`kind: Stream`](streaming.md), which captures the same CDC but
publishes it to NATS for apps/Functions to consume rather than loading a target DB.
