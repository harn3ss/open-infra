# Query (Athena + Glue)

> AWS equivalent: **Athena** (serverless SQL over object storage) + **Glue Data
> Catalog** (the metastore of databases/tables).

`kind: Query` runs SQL over your **data lake** (MinIO — open-infra's S3), with no
database to load into. It's in the console under **Data → Query** as an editor with
query history. There is **one `kind: Query`**; you pick the engine by what you want
to do:

| Engine (`spec.engine`) | Console label | For | Cost |
|---|---|---|---|
| **`duckdb`** (default) | *Lake files — serverless* | ad-hoc SQL over files by path (`read_parquet('s3://…')`) | serverless — a pod per query, **$0 idle** |
| **`trino`** | *Catalog & federation* | `database.table` querying + joins across sources | a coordinator that **idle-stops when unused** |

Both write results to the same place in the same format, so the console reads either
identically.

## How it works

A query is an **execution** (Athena's `StartQueryExecution` model): you submit SQL,
the platform runs it once in a throwaway engine pod, and writes the results (CSV) plus
an `<id>.metadata.json` (state / row count / run time) to the output location. The
console reads those back — the browser never runs SQL itself.

- **DuckDB** (schema-on-read): query bucket paths directly. Parquet, CSV, JSON.
- **Trino** (catalog): query **Iceberg** tables (`iceberg.<schema>.<table>`) managed
  by the shared **Iceberg REST catalog** — open-infra's Glue Data Catalog. Table data
  is Apache Iceberg on MinIO. Trino also federates across other connected sources.
- Results land in the `query-results` bucket under `<namespace>/<name>.csv`.

## Usage

### Console — **Data → Query**

An Athena-style editor: a real SQL code editor (highlighting, gutter, **⌘/Ctrl+Enter**,
run-the-selection-else-all), a left **Data** panel, a resizable results grid (stats
line + Download CSV), tabbed queries, and **Recent queries** history. Per tab, a small
**engine picker** switches DuckDB ↔ Trino:

- **DuckDB** → the Data panel browses **buckets → files**; click a `.parquet`/`.csv`
  to insert `read_parquet('s3://…')`.
- **Trino** → the Data panel browses the **catalog → schemas → tables**; click a table
  to insert `iceberg.<schema>.<table>`. (The tree reads the always-on REST catalog, so
  it works even while Trino is idle-stopped.)

### Declaratively (`kind: Query`)

```yaml
apiVersion: openinfra.dev/v1
kind: Query
metadata: { name: top-regions, namespace: team-a }
spec:
  engine: trino                 # duckdb (default) | trino
  sql: SELECT region, sum(amount) AS total FROM iceberg.demo.sales GROUP BY region
  outputBucket: query-results   # optional (default); created if missing
```

Results are written to `s3://query-results/team-a/top-regions.csv` (+ a
`.metadata.json`).

## The lakehouse (Trino engine)

The Trino side is a small **Iceberg lakehouse**, deployed under the `lakehouse`
namespace:

- **`iceberg-rest`** — an Iceberg REST catalog (the Glue Data Catalog): databases,
  tables, and schemas. Its own metadata persists in SQLite on Longhorn; table data is
  Iceberg on `s3://lakehouse/warehouse` (MinIO).
- **`trino`** — a single-node coordinator wired to that catalog + MinIO. It ships
  **`replicas: 0`** and is **idle-stopped**: the console's autostop reconciler scales
  it to 1 when an `engine: trino` query appears and back to 0 after ~10 min idle, so
  the warehouse engine costs nothing at rest. The first query after idle takes a
  one-time cold-start; DuckDB queries never touch it.

Create tables from data you already have, e.g. via Trino:
`CREATE TABLE iceberg.demo.sales AS SELECT * FROM read_parquet('s3://…')`.

## Notes & limits

- **Security / sandbox.** A query runs untrusted SQL, so the Job is confined like
  Athena — it can touch permitted data and nothing else:
  - **Least-privilege S3, not root.** The Job uses a scoped MinIO identity
    (`query-runner-s3`) that can **read only an allow-list of buckets**
    (`query-data`, `lakehouse`, `query-results` by default) and **write only to
    `query-results`** — never the MinIO root creds. It cannot read or overwrite
    backups, VM images, or other apps' buckets. Add buckets to the allow-list via
    `READ_BUCKETS` in `platform/abstraction/query-runtime.yaml`.
  - **Network-sandboxed.** A NetworkPolicy allows egress only to DNS, MinIO, and
    Trino, so `httpfs` can't reach an external URL and SQL can't SSRF cluster
    services.
  - **Hardened pod.** Non-root, read-only root filesystem, all capabilities dropped,
    no service-account token; the runner also disables DuckDB's local-filesystem
    access for the user SQL (no reading `/etc/passwd` or the pod's env).
  - **Follow-up:** the scoped identity is currently platform-wide, not per-namespace —
    true per-tenant isolation (a workgroup per team) is still to come.
- **Engine images/services** are open-infra's own or pinned upstream, in the platform:
  `open-infra-query` (DuckDB + Trino REST client, Trivy-scanned + cosign-signed),
  `tabulario/iceberg-rest`, `trinodb/trino`.
- **Dialects differ** (DuckDB SQL vs Trino/ANSI) — the engine picker keeps each tab on
  one dialect so a query isn't silently run on the wrong one.

## See also

- [`databases.md`](databases.md) — managed databases (warehousing ≈ managed Postgres).
- [`dataflow.md`](dataflow.md) — moving data into the lake (the "Glue ETL" half).
- [`console.md`](console.md) — the console UI.
