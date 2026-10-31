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
    # storageClass: longhorn  # optional — override the engine's default PV StorageClass (see "Storage")
```

The connection string is injected into the app's pods as `DATABASE_URL` (postgres/mysql) or
`MONGODB_URI` (mongo) — apps never hard-code credentials.

## Engines

| `engine` | Backed by | Wire protocol | Notes |
|----------|-----------|---------------|-------|
| `postgres` | **CloudNativePG** (CNPG) | PostgreSQL | The default. `vector: true` adds pgvector. |
| `mysql` | **MariaDB** | MySQL | `highAvailability` → 3-node Galera (synchronous). **MariaDB, not MySQL 8** — see the limitation below. |
| `mongo` | **FerretDB** on DocumentDB-Postgres | MongoDB | Document store; stateless proxy over a Postgres backend. |
| `babelfish` | **Babelfish for PostgreSQL** | **TDS (SQL Server)** + PostgreSQL | **Experimental.** SQL-Server-compatible: point unmodified T-SQL apps at TDS `1433`. Single-instance StatefulSet on Longhorn (not CNPG), backed up via Velero. |

### `mysql` is MariaDB — MySQL-8-only features are not supported

`engine: mysql` runs **MariaDB**, which is MySQL-wire-compatible but is **not MySQL 8**. An app that
depends on MySQL-8-only SQL cannot use the managed database — in practice the things that bite are the
`utf8mb4_0900_*` collations (MariaDB has `utf8mb4_general_ci` / `uca1400_*`, not the MySQL-8 `_0900_`
family), expression defaults like `DEFAULT (JSON_OBJECT(...))`, and enforced `CHECK` constraints
(MariaDB parses but historically did not enforce some). Migrations written against MySQL 8 will fail to
apply.

**If you need real MySQL 8, bring your own** — run `mysql:8.0` as a plain `StatefulSet` alongside your
`kind: Application` and point the app at it (open-infra does not yet offer a `mysql8` engine). One gotcha
worth knowing: a freshly-provisioned Longhorn **ext4** volume contains a `lost+found` directory, and MySQL
refuses to initialize into a non-empty data directory — set the data dir to a **subdirectory** of the
mount (e.g. `--datadir=/var/lib/mysql/data`, created on first boot) rather than the mount root.

### `babelfish` — SQL-Server-compatible (experimental)

`engine: babelfish` runs [Babelfish for PostgreSQL](https://babelfishpg.org), which makes
Postgres speak the SQL Server wire protocol (**TDS**, port `1433`) and **T-SQL**, so an
application written for Microsoft SQL Server connects with no code changes. The same data
is also reachable over the native Postgres protocol on `5432`.

The connection secret (`<app>-babelfish`) carries both endpoints — `SQLSERVER_URL`
(`Server=…,1433;…`) for the SQL Server driver and `DATABASE_URL` for Postgres clients.

The TDS + Postgres listeners are **TLS-encrypted** (a cert-manager cert from the LAN CA is
issued + mounted, and the listener enables `ssl`), so clients connect with
`Encrypt=mandatory;TrustServerCertificate=true` — verified with `encrypt_option = TRUE`.

Caveats (why it's experimental): it runs as a **single-instance StatefulSet on Longhorn**, not
under the CloudNativePG operator — there is **no streaming-replication HA** yet (durability is
Longhorn + Velero), and Babelfish covers a large but **not complete** subset of T-SQL (check
your codebase with *Babelfish Compass* first). Start/Stop works (scales the StatefulSet to 0,
keeps the PVC). The image is open-infra's own (`ghcr.io/…/open-infra-babelfish`) — the patched
Postgres + Babelfish extensions **built from source** (`babelfish/Dockerfile`), Trivy-scanned +
cosign-signed by CI, with OS packages patched (`apt upgrade`) so it carries **0 fixable CVEs**.

## Connection pooling — `kind: DatabaseProxy` (RDS Proxy)

> AWS equivalent: **RDS Proxy** (`aws_db_proxy`).

A `DatabaseProxy` puts a pooled, connection-**bounded** endpoint in front of a SQL-Server/Babelfish
database. Clients connect to it instead of the database; it terminates each client's TDS handshake,
borrows a backend connection from a bounded per-credential pool, and hands that backend back for the
next client to reuse whenever the session left no unsharable state — **pinning** (temp tables, explicit
transactions, prepared handles, cursors, …) to a dedicated backend otherwise. The per-key cap means a
client stampede **queues** instead of exhausting the database's connection slots.

```yaml
apiVersion: openinfra.dev/v1
kind: DatabaseProxy
metadata: { name: orders-proxy }
spec:
  targetDatabase: orders   # the database.name to pool in front of (fronts orders-babelfish:1433)
  poolMax: 20              # max backend connections per credential — the connection ceiling
  # engineFamily: babelfish
  # acquireTimeoutMs: 10000
  # replicas: 1
```

Clients then point at `orders-proxy` (its `<name>-proxy` connection Secret carries `HOST` / `TDS_PORT`)
with `encrypt=disable` by default (or `encrypt=on`/`strict` when the proxy terminates client TLS via
`spec.tls`; Babelfish itself is TDS-no-TLS behind the proxy). `/status` on port 9114 reports pool reuse, discards,
and the multiplex-opportunity metric. Backed by open-infra's own `tds-proxy`
(`ghcr.io/…/open-infra-tds-proxy`); see `docs/design/rds-proxy-tds-multiplexing.md`. **Experimental**,
same as the `babelfish` engine it fronts. Today a session holds its backend for its lifetime (reuse is
across sessions); per-transaction multiplexing is an opt-in proxy mode (`-tx-multiplex`),
surfaced as the `DatabaseProxy` spec field `transactionMultiplexing`.

## High availability

`highAvailability: true` gives a replicated, self-healing topology (needs ≥2 nodes):

- **postgres** → CNPG runs a primary + standby with streaming replication and automatic
  failover (instances spread across nodes via anti-affinity). Failover promotes the standby in
  seconds; a LoadBalancer service selecting `cnpg.io/instanceRole=primary` follows the new
  primary, so a stable endpoint keeps working. Replication is **async** by default (a hard
  primary loss can drop the last un-streamed commits); for **zero-data-loss** failover set
  CNPG's `spec.postgresql.synchronous` with `dataDurability: preferred` (needs the operator
  ≥ 1.25, which the platform now ships) — it stays available if a standby is down instead of
  blocking writes.
- **mysql** → a 3-node Galera cluster (synchronous, multi-primary).
- **mongo** → the stateless FerretDB proxy tier scales out; storage-tier HA is a tracked
  follow-up.

Default (`false`) is a single instance — fine for dev.

**Convert on demand:** you can flip `highAvailability` on a *running* database (a toggle on
the detail page) — no recreate. Postgres scales its CNPG instance count live (adds/removes a
streaming-replication standby); Mongo scales the proxy tier; MySQL converts the standalone
MariaDB to a 3-node Galera cluster. (Start the database first if it's stopped.)

### Read scaling (postgres) — the Aurora reader model

Beyond the HA on/off flag, postgres databases can size and autoscale their read capacity:

```yaml
database:
  engine: postgres
  replicas: 3            # 1 primary + 2 hot standbys (overrides highAvailability's implied 2)
  readerEndpoint: true   # inject DATABASE_RO_HOST — a reader endpoint balancing reads across standbys
  autoscaling:           # or autoscale the standbys on load instead of a fixed replicas count
    minReplicas: 2
    maxReplicas: 6
    targetCPUPercent: 70
```

- **`replicas`** — an explicit instance count (the Aurora replica-count knob). Any value `>1`
  turns on streaming replication + cross-node anti-affinity, exactly like `highAvailability`.
- **`readerEndpoint`** — surfaces `DATABASE_RO_HOST` (CNPG's `-ro` service, which load-balances
  across the standbys) alongside the writer `DATABASE_URL`, so the app can send reads off the
  primary — the Aurora **reader endpoint**. Needs standbys (`replicas > 1` or `highAvailability`).
- **`autoscaling`** — a KEDA ScaledObject target-tracks CPU and scales the instance count between
  `minReplicas` and `maxReplicas` (the Aurora **replica autoscaling** analog). The reader pool
  widens automatically as it scales. When set, it owns the count (`replicas` is ignored).

## Storage & durability

Database volumes use **local-path** PVs (local SSD/NVMe — never CIFS/NFS) for performance by
default (babelfish uses **longhorn**), and replicated engines rely on the DB's own replication
for HA rather than the storage layer. Set `spec.database.storageClass` to override this per
database — e.g. `longhorn` to put a non-HA database on replicated storage, or your cluster's
StorageClass on a substrate that doesn't ship `local-path`. Data persists across pod restarts.

Placement is **enforced by measured disk class**, not just documented: a probe labels every node
`openinfra.dev/disk-class` (`nvme`/`sata-ssd`/`hdd`) from its real hardware, and a database only
schedules onto a node measured `nvme` or `sata-ssd`. An unlabeled, HDD, or unmeasured node is
ineligible (fail-closed) — a database can never silently land on spinning disk. (Bulk/sequential
and stateless workloads are free to use HDD.)
Hardening the single-instance/durability story (node-resilient storage for non-HA DBs,
off-cluster backups) is a planned follow-up.

### Sizing, placement & capacity

Storage-capacity-aware scheduling is **off** on this substrate: `local-path` isn't a CSI driver,
and `driver.longhorn.io` reports `storageCapacity: false`. Nothing compares `spec.database.size`
to what a node can hold, so a database pod binds to any node that fits it by CPU and memory — and
a volume larger than that node's free disk only fails later, as `ENOSPC` while the engine is
writing. For a **large database, set `spec.database.placement`** to a node that has the room (use
`openinfra.dev/*` node labels, never hostnames). `local-path` is strictly node-local — it can't
move or grow — so pin it; **`longhorn`** provisions the requested size and backs it up with Velero,
so prefer it for large or movable databases. (A fresh database grows into `size` over time; the
concern is a load that needs the full size up front — see restore below.)

### Restoring a SQL Server `.bak` (`restoreFrom`) — capacity & failure surfacing

A `restoreFrom` restore needs the **whole** database size immediately, and transiently needs room
for both the backup and the restored data (≈2×), so it is where the capacity gap bites hardest.
The engine therefore:

- **stages the `.bak` onto the sized data volume**, not node-ephemeral storage, so an over-large
  backup fails as a clear volume-full error (and can't fill or evict the node), and reclaims the
  staged file once the database is in place;
- runs a **capacity preflight** on the actually-scheduled node that **fails fast with an actionable
  reason** ("INSUFFICIENT STORAGE … set `spec.database.placement` … or reduce `size`") *before* any
  data is written, instead of hitting `ENOSPC` hours into `RESTORE DATABASE`;
- keeps the claim **NotReady until the restore completes**, and a failed restore surfaces as a
  **NotReady claim with the reason** (in the restore container's status/logs) — never a
  silently-healthy claim over a half-restored database.

**Striped (multi-file) backups.** RDS SQL Server's native backup-to-S3 splits a large database into
N files (`@number_of_files`). Point `restoreFrom` at the whole set with **`keys: [k1, k2, …]`** (an
ordered list) or **`prefix: <p>`** (every object under the prefix, sorted) instead of a single `key`
— set exactly one of the three. Each stripe is fetched to an ordered `db_<i>.bak`, and the engine
restores the whole set in one `RESTORE DATABASE … FROM DISK, DISK, …`; a missing stripe fails the
restore loudly, and the capacity guard sizes for the **summed** stripe set plus the restored database.

## Start / Stop

Like RDS stop/start: pause a database to free compute while **keeping its data**. Set
`spec.database.stopped: true` (or click **Stop** on the database detail page):

- **postgres** → CNPG declarative hibernation (`cnpg.io/hibernation`) scales instances to 0.
- **mysql / mongo** → the engine deployments scale to 0.

The PVC(s) are retained; set `stopped: false` (or click **Start**) to resume.

## Point-in-time recovery (postgres) — the backtrack analog

> AWS equivalent: **RDS point-in-time recovery** / **Aurora Backtrack**.

Opt a postgres database into continuous backup and you can restore it to any instant within a
retention window:

```yaml
database:
  engine: postgres
  pointInTimeRecovery: true   # continuously archive WAL to object storage
  backtrackWindow: 7d         # how far back a restore can reach (the WAL-archive retention)
```

When enabled, the database's CNPG cluster streams its write-ahead log continuously to object
storage (MinIO) via the barman-cloud plugin, under a per-database path with its own scoped,
non-root credential (an app's archive is never reachable by another tenant). This adds ongoing
object-storage cost, so it's **off by default**.

To restore, `POST /api/databases/{namespace}/{name}/backtrack` with a target time:

```json
{ "targetTime": "2026-10-10T12:00:00Z", "targetName": "shop-db-recovered" }
```

Postgres has **no in-place rewind**, so (like restoring an RDS instance to a point in time) the
platform recovers into a **new** cluster by replaying the WAL archive up to `targetTime`, then
you cut the application over to the recovered database's endpoint (returned in the response).
The original database is left untouched, so you can compare before switching.

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
