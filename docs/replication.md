# Replication (bidirectional / multi-master)

`kind: Replication` keeps **two database sites in sync both ways** — each is
source *and* target — like a SymmetricDS / AWS-DMS bidirectional task. Sites may
be different engines (e.g. **SQL Server ↔ PostgreSQL**). It runs on open-infra's
own engine (Debezium + NATS JetStream + the [apply-sink](../apply-sink/)).

```
siteA ⇄ Debezium ⇄ NATS JetStream ⇄ apply-sink ⇄ siteB
```

Per site a Debezium connector captures changes onto a capped JetStream stream;
per direction an apply-sink applies the peer's changes with:

- **Loop prevention** — an origin-marker column. Every write carries the site it
  originated at; a sink drops events that originated at the peer, so a change
  never echoes back and loops.
- **Conflict resolution** — last-write-wins on a **Hybrid Logical Clock** version
  column. HLC advances when a node observes a remote timestamp, so a causally
  later write always wins **even if the writer's wall-clock is skewed**. Ties
  break deterministically on the origin marker.
- **Safety** — capped streams + dead-lettering in the apply-sink.

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

An `mm-prep` Job per site installs the version + origin columns and the per-site
stamping. **Postgres** gets a Hybrid Logical Clock + a `BEFORE` trigger
automatically. **SQL Server** lacks `BEFORE`-row triggers, so the version/origin
columns are added but writer-side stamping is application-side (or an
`INSTEAD OF` trigger) — see the apply-sink notes. The replication apply path skips
the stamping (a session flag) so replicated rows keep the true origin/version.

## Notes & limits

- CDC prerequisites are the same as [Migrations](migrations.md) (Postgres
  `wal_level=logical`; MySQL `binlog_format=ROW`; SQL Server CDC + Agent).
- Conflict resolution is row-level last-write-wins. For delete-vs-concurrent-update
  (an inherent multi-master ambiguity) use soft-deletes/tombstones.
- HLC LWW is implemented for Postgres; SQL Server uses a comparable version column.
- Requires the `nats` component.
