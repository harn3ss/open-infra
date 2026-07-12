# Query (Athena)

> AWS equivalent: **Athena** — serverless, interactive SQL over data in object
> storage, with no database to load into.

`kind: Query` runs SQL over your **data lake** (MinIO — open-infra's S3) and writes
the results to an output location. There's no server to provision and nothing to
ingest first: you point SQL at files in a bucket and get results back. It's in the
console under **Data → Query** as a SQL editor with query history.

## How it works

A query is an **execution** (Athena's `StartQueryExecution` model): you submit SQL,
the platform runs it once in a throwaway engine pod against MinIO, and writes the
results (CSV) plus a small `metadata.json` (state, row count, run time) to the output
location. The console reads those back to show state + results — the browser never
runs SQL itself.

- **Engine (Phase 1): DuckDB** — single-node, schema-on-read. Query bucket paths
  directly, e.g. `read_parquet('s3://bucket/*.parquet')`. Parquet, CSV, and JSON.
- **Serverless per query** — one Kubernetes Job per run; it executes and exits. No
  always-on cluster.
- Results land in the `query-results` bucket (configurable) under the key
  `<namespace>/<name>.csv` (+ `.metadata.json`).

## Usage

### Console — **Data → Query**

An Athena-style three-pane editor:

- Write SQL and **Run** — or **⌘/Ctrl+Enter**. Selecting text runs only the
  selection; otherwise the whole statement runs. A trailing `;` is fine.
- The left **Data** panel browses buckets; click a `.parquet` / `.csv` / `.json`
  file to insert a `read_parquet('s3://…')` snippet at the cursor.
- Results appear below with a stats line (state · run time · rows) and a
  **Download CSV** button. Multiple query tabs are supported.
- **Recent queries** lists past executions; click one to reopen its SQL.

### Declaratively (`kind: Query`)

```yaml
apiVersion: openinfra.dev/v1
kind: Query
metadata: { name: top-regions, namespace: team-a }
spec:
  sql: |
    SELECT region, sum(amount) AS total
    FROM read_parquet('s3://query-data/sales.parquet')
    GROUP BY region ORDER BY total DESC
  outputBucket: query-results   # optional (default); created if missing
```

Results are written to `s3://query-results/team-a/top-regions.csv` (+ a
`.metadata.json` with the state/stats).

## Querying the lake

DuckDB reads directly from MinIO by path — schema-on-read, so there's no catalog to
register tables in Phase 1; you reference files by path:

- `read_parquet('s3://bucket/events/*.parquet')` — Parquet (globs supported)
- `read_csv_auto('s3://bucket/data.csv')` — CSV with schema inference
- `read_json_auto('s3://bucket/data.json')` — JSON

## Notes & limits

- **Phase 1 is single-node DuckDB** — great for interactive analytics over the lake.
  For very large or multi-source federation, **Phase 2** swaps the engine for
  **Trino** and adds a **`kind: Catalog`** (the Glue equivalent) so you can query
  `database.table` with catalog-driven autocomplete — *without changing the
  `kind: Query` contract*.
- **Credentials:** query Jobs run in the `minio` namespace with the MinIO root
  credentials (same pattern as the app bucket-setup). Per-namespace scoped
  credentials / workgroups are a tracked follow-up.
- The engine image (`ghcr.io/…/open-infra-query`) is open-infra's own — a static
  DuckDB + the S3/parquet extensions, Trivy-scanned + cosign-signed by CI.

## See also

- [`databases.md`](databases.md) — managed databases (warehousing ≈ managed Postgres).
- [`dataflow.md`](dataflow.md) — moving data into the lake (the "Glue ETL" half).
- [`console.md`](console.md) — the console UI.
