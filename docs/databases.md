# Managed databases (RDS)

> AWS equivalent: **RDS / Aurora** (relational) and **DocumentDB / DynamoDB** (document).

Databases are provisioned by an **Application**'s `database:` block — you don't create a
database resource directly, you declare what your app needs and the platform runs it. They
show up in the console under **Data → Databases** (`/databases`).

```yaml
apiVersion: openinfra.dev/v1
kind: Application
metadata: { name: shop, namespace: team-a }
spec:
  image: ghcr.io/acme/shop:latest
  database:
    engine: postgres          # postgres | mysql | mongo
    name: shop                # database name (defaults to the app name)
    highAvailability: false   # see "High availability"
    vector: false             # postgres only: enable pgvector (for kind: Model RAG)
    expose: false             # publish on a LAN IP (MetalLB) for direct access
    stopped: false            # RDS-style stop/start (see below)
```

The connection string is injected into the app's pods as `DATABASE_URL` (postgres/mysql) or
`MONGODB_URI` (mongo) — apps never hard-code credentials.

## Engines

| `engine` | Backed by | Wire protocol | Notes |
|----------|-----------|---------------|-------|
| `postgres` | **CloudNativePG** (CNPG) | PostgreSQL | The default. `vector: true` adds pgvector. |
| `mysql` | **MariaDB** | MySQL | `highAvailability` → 3-node Galera (synchronous). |
| `mongo` | **FerretDB** on DocumentDB-Postgres | MongoDB | Document store; stateless proxy over a Postgres backend. |

## High availability

`highAvailability: true` gives a replicated, self-healing topology (needs ≥2 nodes):

- **postgres** → CNPG runs a primary + standby with streaming replication and automatic
  failover (instances spread across nodes via anti-affinity).
- **mysql** → a 3-node Galera cluster (synchronous, multi-primary).
- **mongo** → the stateless FerretDB proxy tier scales out; storage-tier HA is a tracked
  follow-up.

Default (`false`) is a single instance — fine for dev.

## Storage & durability

Database volumes use **local-path** PVs (local NVMe — never CIFS/NFS) for performance, and
replicated engines rely on the DB's own replication for HA rather than the storage layer.
Data persists across pod restarts. Hardening the single-instance/durability story
(node-resilient storage for non-HA DBs, off-cluster backups) is tracked in issue #61.

## Start / Stop

Like RDS stop/start: pause a database to free compute while **keeping its data**. Set
`spec.database.stopped: true` (or click **Stop** on the database detail page):

- **postgres** → CNPG declarative hibernation (`cnpg.io/hibernation`) scales instances to 0.
- **mysql / mongo** → the engine deployments scale to 0.

The PVC(s) are retained; set `stopped: false` (or click **Start**) to resume.

## Peek — live engine internals

The database detail page has a **Peek** tab with live stats, refreshed every 5s:

- **Connections** — active / idle / idle-in-txn / total / max.
- **Replication slots** — CDC/replication lag per slot.
- **Top queries** — from `pg_stat_statements` (Postgres) or `performance_schema` (MySQL).

The console BFF resolves the host + credentials from the database's **own generated Secret**
(namespace-scoped) and connects read-only — the browser never holds credentials, and the
client can't supply an arbitrary host or secret (`POST /api/databases/{ns}/{name}/stats`).

Managed Postgres has **`pg_stat_statements` preloaded and created** (with `pg_read_all_stats`
granted to the app user), so "Top queries" shows real query history out of the box. MongoDB
has no SQL stats, so it has no Peek tab.

> For **DataFlow** source databases (which may be foreign engines we don't control) we can't
> install `pg_stat_statements`; Peek there falls back to the longest **active** queries.

## See also

- [`architecture.md`](architecture.md) — where databases fit in the platform
- [`dataflow.md`](dataflow.md) — moving data between databases (`kind: DataFlow`)
- [`migrations.md`](migrations.md) — one-way migration (`kind: Migration`)
- [`console.md`](console.md) — the console UI
