# Database Migrations (DMS)

open-infra's Database Migration Service — the AWS DMS analog. A `kind: Migration`
does a one-shot **full load** and/or an ongoing **CDC** (change-data-capture) sync
from a source database into a managed PostgreSQL. It's powered by a **headless
Airbyte** engine that the platform runs and drives for you — you never see or
operate Airbyte; you write a `Migration` (or use the console wizard) and the data
flows.

| AWS DMS | open-infra |
|---|---|
| Replication instance | the shared headless Airbyte engine (`airbyte` namespace) |
| Source / target endpoints | `spec.source` / `spec.target` on a `Migration` |
| Replication task | a `Migration` |
| Migration type (full-load / cdc / full-load-and-cdc) | `spec.mode` |
| Table mappings | `spec.tables` (or the wizard's table picker) |
| "Start/Resume task" | **Run sync** (console) / the connection's schedule |

## How it works

```
kind: Migration  →  Crossplane (provider-terraform)  →  Airbyte API
                                                         source + destination + connection
                          the console + BFF  ──────────►  trigger sync / read status
```

A `Migration` is compiled by Crossplane into an Airbyte **source**, **destination**,
and **connection** (via the Airbyte Terraform provider). The console's BFF triggers
syncs and reads status through Airbyte's API. Airbyte has no Ingress and no exposed
UI — it is purely an engine.

## Quick start (console)

**Data → Migrations → New Migration** opens a guided wizard:

1. **Source** — engine (`postgres` / `mysql`), host, port, database, username,
   password (TLS optional; Postgres also takes schemas).
2. **Target** — a managed Postgres endpoint (host/port/database/username/password +
   schema). For a managed DB, use its `<cluster>-rw.<ns>.svc` host.
3. **Task** — a name + namespace, a **task type** (full load / CDC / full load + CDC),
   and a **table picker**: *All tables*, or *Choose tables* to pick individual tables
   from a live list discovered from your source.
4. **Review → Create.**

The wizard creates a `<name>-creds` Secret (holding both endpoint passwords) and the
`Migration`. The row shows **Provisioning** for ~30–60s while Crossplane builds the
Airbyte connection, then **Ready**. Click **▶ Run sync** to start a load.

## The `Migration` resource (kubectl / GitOps)

```yaml
apiVersion: openinfra.dev/v1
kind: Migration
metadata:
  name: legacy-import
  namespace: myapp
spec:
  mode: full-load-and-cdc          # full-load | cdc | full-load-and-cdc
  source:
    engine: mysql                  # postgres | mysql
    host: olddb.example.com
    port: 3306
    database: app
    username: migrator
    passwordSecretRef: { name: src-creds, key: password }
    # schemas: ["public"]          # Postgres only; default ["public"]
    # ssl: false
  target:
    engine: postgres
    host: myapp-db-rw.myapp.svc     # a managed CloudNativePG cluster, or any Postgres
    port: 5432
    database: app
    username: app
    passwordSecretRef: { name: myapp-db-app, key: password }
    schema: public
  tables: ["customers", "orders"]   # optional; omit = all tables
```

Passwords are always referenced from Secrets (`passwordSecretRef`) — never inlined.
Internal targets are easy: a managed DB's connection secret (e.g. CloudNativePG's
`<cluster>-app`) already has a `password` key.

The Airbyte connection id is published to a `<name>-outputs` Secret in the claim
namespace once provisioned.

## Task types

| `spec.mode` | Behaviour | Schedule |
|---|---|---|
| `full-load` | One-shot copy of existing data. | Manual — click **Run sync**. |
| `cdc` | Ongoing change-data-capture only. | Hourly (auto). |
| `full-load-and-cdc` | Initial snapshot, then keep in sync. | Hourly (auto); **Run sync** to kick off the initial load immediately. |

> Full-load uses a *manual* schedule, so nothing moves until you **Run sync**. CDC
> modes sync on an hourly cron; **Run sync** forces an immediate run.

## Source & target engines

- **Sources:** PostgreSQL, MySQL.
- **Target:** PostgreSQL (a managed CloudNativePG cluster, or any reachable Postgres).

Adding more source/target engines is a matter of extending the XRD enum + the
composition's per-engine connector config (Airbyte ships 600+ connectors).

## CDC prerequisites

CDC modes read the source's change log, which the source must be configured for:

- **PostgreSQL:** `wal_level=logical`, plus a replication slot and a publication. The
  composition names them `airbyte_slot_<xr>` / `airbyte_pub_<xr>`; create them on the
  source, and grant the user `REPLICATION`.
- **MySQL:** `binlog_format=ROW` (the default on MySQL 8), `binlog_row_image=FULL`, and
  a user with `REPLICATION SLAVE, REPLICATION CLIENT`.

Full-load mode has no such prerequisites (it reads via plain `SELECT`).

## Running & monitoring syncs

- **Run sync** (console, ▶) triggers a sync immediately. Behind it, the BFF calls
  `POST /api/migrations/{ns}/{name}/sync`.
- Status: the `Migration` row reflects the claim's readiness; live job status is
  available at `GET /api/migrations/{ns}/{name}/sync`.
- `kubectl get migration -A` shows mode, source engine, and the connection id.

## Under the hood

- **Engine:** Airbyte OSS (Helm chart V2), deployed headless (no webapp) and pinned
  to a non-GPU node. See `platform/data/airbyte.yaml`. Toggle with
  `components.airbyte` in `config.yaml`.
- **Compiler:** `platform/abstraction/migration-{xrd,composition}.yaml` — the
  composition renders a `provider-terraform` `Workspace` whose inline module creates
  the Airbyte resources. Each Migration gets an isolated Terraform state (a
  per-Workspace kubernetes backend), so deletes cleanly `terraform destroy` the
  Airbyte resources.
- **Console glue:** `console-api` (the BFF) discovers source tables
  (`POST /api/migrations/discover`), and triggers/reads syncs — reading the connection
  id from `<name>-outputs` and the Airbyte client credentials from the
  `airbyte-auth-secrets` Secret. The browser never talks to Airbyte.

## Performance

Validated on the single-node engine (untuned, default job resources): a 2,097,148-row
MySQL→Postgres **CDC continuity sync** completed in ~140s — **≈15,000 rows/sec**,
~695 MB, with an exact source↔target row-count reconciliation (zero loss). Throughput
scales with row size, parallelism, and Airbyte resource limits.

## Notes & limitations

- Phase-1 deployment uses Airbyte's **bundled** Postgres + MinIO; hardening to the
  platform's CloudNativePG + MinIO is a values change (`global.database` /
  `global.storage`).
- All Migrations currently target Airbyte's **Default Workspace**.
- A `Migration` references password Secrets; the console wizard creates a
  `<name>-creds` Secret for you and removes it on delete.
