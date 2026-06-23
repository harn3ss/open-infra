# Streaming CDC (`kind: Stream`)

open-infra's **"Kinesis"**: a `Stream` taps a source database's change log
(change-data-capture) and publishes **every row change as a real-time event** onto
**NATS JetStream**, where apps, [Functions](serverless.md), and sinks subscribe. It's
the streaming counterpart to [`kind: Migration`](migrations.md) (which batch/CDC-syncs
into a *managed database*) — a `Stream` emits to the *event bus* for event-driven
consumers.

| Piece | What |
|---|---|
| Capture engine | **Debezium Server** (headless; one Deployment per Stream) |
| Transport | **NATS JetStream** (the platform's existing `kind: Queue` bus) |
| Subjects | `cdc.<name>.<schema>.<table>` (durable stream `cdc-<name>`) |
| Event format | Debezium JSON envelope (`before` / `after` / `op` / `source`) |

You never see Debezium — you declare a `Stream`; the platform runs and wires it.

## Creating a Stream

**Data → Streams → New Stream** in the console: pick the source engine, enter the
endpoint + credentials, optionally name specific tables (blank = all), Create.

Or declaratively:

```yaml
apiVersion: openinfra.dev/v1
kind: Stream
metadata:
  name: orders-cdc
  namespace: myapp
spec:
  source:
    engine: postgres            # postgres | mysql | mariadb | sqlserver | mongodb
    host: myapp-db-rw.myapp.svc
    port: 5432
    database: app
    username: cdc
    passwordSecretRef: { name: orders-cdc-stream-creds, key: password }
    # schemas: [public]         # Postgres (public) / SQL Server (dbo)
    # tables: [orders, customers]   # bare names; omit = all tables/collections
    # ssl: false
```

The password is referenced from a Secret and injected into Debezium as an
environment variable — it is **never** written into the connector ConfigMap.

## Subjects & event format

Each row change is published to `cdc.<name>.<schema>.<table>`. For `orders-cdc`
above, the `orders` table → `cdc.orders-cdc.public.orders`. They land in a durable
JetStream stream named `cdc-<name>` capturing `cdc.<name>.>`.

A change event is the standard Debezium envelope:

```json
{
  "before": null,
  "after":  { "id": 42, "total": 19.99 },
  "op":     "c",                       // c=create  u=update  d=delete  r=read(snapshot)
  "source": { "table": "orders", "lsn": 26639584, "ts_ms": 1782178807733, ... }
}
```

On first start, Debezium **snapshots** the existing rows (`op:"r"`), then streams
live changes (`op:"c"/"u"/"d"`) as they happen.

## Consuming

Anything that speaks NATS can subscribe:

```bash
nats sub 'cdc.orders-cdc.>'                 # tail all changes
nats sub 'cdc.orders-cdc.public.orders'     # just one table
```

A [`Function`](serverless.md) makes a serverless, scale-to-zero processor (the
Lambda-on-Kinesis pattern): subscribe to the subject, transform/enrich/route each
event. The `<name>-stream` connection Secret holds `NATS_URL` / `STREAM` /
`SUBJECTS` for consumers.

## Source CDC prerequisites

CDC reads the source's change log, which the source must be configured for:

- **PostgreSQL:** `wal_level=logical`. Debezium creates the replication slot
  (`dbz_<name>`) + publication itself; the user needs `REPLICATION`.
- **MySQL / MariaDB:** `binlog_format=ROW`; a user with `REPLICATION SLAVE,
  REPLICATION CLIENT`.
- **SQL Server:** CDC enabled (`sys.sp_cdc_enable_db` + per-table) and **SQL Server
  Agent running**.
- **MongoDB:** a **replica set** (change streams require one).

## Engines

PostgreSQL, MySQL, MariaDB, SQL Server, MongoDB — a source may be proprietary
(e.g. SQL Server); we only read its change log. Validated end-to-end (snapshot +
live CDC → JetStream) on **PostgreSQL** (logical replication), **MariaDB** (binlog),
**MongoDB** (change streams), and **SQL Server** (CDC tables); MySQL uses the same
Debezium connector as MariaDB. Note: MariaDB streams cleanly here even though its
DMS *batch* path needs explicit table selection — Debezium reads the binlog
directly, sidestepping that.

## `Stream` vs `Migration`

| | `kind: Migration` | `kind: Stream` |
|---|---|---|
| Engine | Airbyte | Debezium Server |
| Output | a **managed database** (Postgres) | the **event bus** (JetStream) |
| Use when | you want a synced copy / warehouse | you want event-driven consumers, fan-out, real-time processing |
| Style | batch + scheduled CDC | continuous, per-change events |

## Notes

- One Debezium Server Deployment per Stream; offsets + schema history live on a
  small Longhorn PVC so restarts **resume** instead of re-snapshotting.
- NATS JetStream runs single-node by default (file store). For HA, enable the NATS
  cluster (`platform/data/nats.yaml`).
- Deleting a `Stream` removes its Debezium Deployment, config, and PVC; the
  JetStream stream (`cdc-<name>`) and any data already published persist until you
  remove them (`nats stream rm cdc-<name>`).
