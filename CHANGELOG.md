# Changelog

All notable changes to open-infra are recorded here. Versions follow
[semantic versioning](https://semver.org). The `openinfra.dev` resource kinds are
the product's public contract.

## Unreleased

### Reliability
- **Nightly Chaos Suite — the containment foundation.** The road from *"convergence is
  hand-tested"* to *"convergence is proven nightly, or the release is blocked."* This
  lands the safety model first (design §3): a disposable `chaos-sandbox` namespace with a
  `ResourceQuota` + `LimitRange` + a low non-preempting `PriorityClass` (sandbox pods
  evict first under pressure), and a `chaos-runner` ServiceAccount whose write authority
  is scoped to the sandbox **only** — "runner creds = chaos creds", so a fat-fingered
  fault selector is *rejected by the API server*, not merely discouraged. A **pre-flight
  guard** resolves a fault's selector and aborts if it could reach any pod outside the
  sandbox. All **validated live** (RBAC deny-tests pass; the guard aborts a kube-system
  target and an `app=minio` selector). Ships alongside the **Scenario 1**
  (`multimaster-partition`) kit — disposable members, a checked-in multi-master mesh, the
  partition fault, an orchestration script, and a self-hosted nightly workflow.
  **Scenario 1 is validated end-to-end on the live cluster**: baseline convergence in
  13s, and under a real partition the mesh diverges then re-converges byte-identical in
  ~108s (200 keys / 20 conflicts / zero lost writes). The first run also surfaced that
  the mesh is *pod-mediated* (a member↔member partition injects nothing) and drove a
  platform enhancement — `kind: FaultInjection` gained **`partitionPeer`** for
  peer-scoped network-partitions (cut A↔B while both stay reachable by outside clients).
  See [docs/chaos-suite.md](docs/chaos-suite.md).

## v2.4.0 — 2026-07-14

### Billing
- **New Cost Explorer — "what AWS would've charged."** The last unbuilt AWS-equivalent
  ships: a console **Billing → Cost Explorer** page that prices your live cluster
  (node vCPU/memory, GPUs, PVC storage, LoadBalancers) against AWS public on-demand
  list rates and shows the monthly/annual estimate next to your actual cost ($0). A
  read-only BFF endpoint (`/api/cost`) computes it from cluster state — compute at
  Fargate rates, GPU at g4dn class, EBS gp3, ALB base — plus a by-namespace compute
  breakdown. Rates are overridable via `COST_*` env. See [docs/cost.md](docs/cost.md).

### Security
- **`kind: Query` is no longer root over all of object storage (hardening).** The query
  Job previously ran with the **MinIO root** credentials — any user who could submit a
  Query had full read/write to *every* bucket (Velero/Longhorn/CNPG backups, golden VM
  images, every app bucket), with no network sandbox and running as root. Fixed on five
  fronts:
  - **Least-privilege S3 identity.** A new `query-runtime.yaml` mints a scoped MinIO
    user + policy that can **read only an allow-list of buckets** (`query-data`,
    `lakehouse`, `query-results`) and **write only to `query-results`**; the composition
    uses it instead of root. Verified: the query identity reads `query-results` but gets
    `AccessDenied` on `longhorn`/`velero`. The lakehouse (Trino/iceberg) likewise moved
    off a root-copy secret to a user scoped to `s3://lakehouse` only.
  - **Network sandbox.** A `NetworkPolicy` on query pods permits egress only to DNS +
    MinIO + Trino, so `httpfs` can't exfiltrate to an external URL and SQL can't SSRF
    cluster services / the metadata endpoint.
  - **Pod hardening.** Query pods run `runAsNonRoot` (uid 65532), `readOnlyRootFilesystem`,
    all capabilities dropped, `automountServiceAccountToken: false`, seccomp
    `RuntimeDefault`; the image ships a non-root `USER`. iceberg-rest moved off root
    (uid 1000 + `fsGroup`, no chmod-0777 init) — validated Ready as non-root.
  - **DuckDB confinement.** The runner disables local-filesystem access and locks
    configuration for the untrusted user SQL, so a query can't read `/etc/passwd` or
    `/proc/self/environ` (env/cred exfil) or re-enable it via a COPY-wrapper breakout;
    S3 still works.
  - Follow-ups: per-namespace query identities/workgroups, and Trino pod hardening.

### Analytics
- **The lakehouse is now installed by GitOps.** The Trino + Iceberg REST catalog
  manifests moved under `platform/query/manifests/` behind a child Argo `Application`
  (`platform/query/query.yaml`), and `query` was added to the app-of-apps include
  glob — so `install.sh` brings the whole lakehouse up on a fresh cluster instead of
  it needing hand-applied resources. A one-shot `lakehouse-setup` Job (Sync hook,
  earlier sync-wave) creates the `lakehouse` bucket on MinIO and copies the MinIO root
  credentials into `lakehouse/minio-creds` — no secret is committed. Toggle it off with
  `components.lakehouse: false`. Argo `ignoreDifferences` on the Trino Deployment's
  replicas so selfHeal doesn't fight the idle-stop reconciler.

## v2.3.0 — 2026-07-12

### Analytics
- **The lakehouse — Trino + an Iceberg REST catalog (Athena's Glue half).** Phase 2
  of `kind: Query` lands as a second **engine**, not a second kind. The same
  `kind: Query` now takes `spec.engine: duckdb | trino` (default `duckdb`):
  - **`duckdb`** — the serverless, schema-on-read path from v2.2.0: query files by
    path (`read_parquet('s3://…')`), a pod per query, **$0 at idle**.
  - **`trino`** — a single-node **Trino** coordinator wired to a shared **Iceberg
    REST catalog** (open-infra's **Glue Data Catalog**) over MinIO, for
    `database.table` querying and cross-source joins. Both engines write the *same*
    result contract (`<ns>/<name>.csv` + `.metadata.json`), so the console reads
    either identically.
- **Trino idle-stop.** The lakehouse coordinator ships `replicas: 0`; a console
  autostop reconciler scales it 0↔1 based on the newest `engine: trino` query and
  scales back after ~10 min idle — the warehouse engine costs nothing at rest, and
  DuckDB queries never touch it.
- **Engine picker + catalog-aware Data tree in the console.** Each query tab has a
  small engine picker (**DuckDB** *— lake files, serverless* / **Trino** *— catalog &
  federation*). The Data panel follows it: buckets→files for DuckDB (insert
  `read_parquet(...)`), or **catalog → schemas → tables** for Trino (insert
  `iceberg.<schema>.<table>`). The catalog tree reads the always-on REST catalog, so
  it browses even while Trino is idle-stopped. Validated end-to-end (both engines →
  same result contract → console; idle-stop scaled 1→0 automatically).
  See [docs/query.md](docs/query.md).

### Console
- **Databases show *Stopped* when paused, like VMs.** A database whose claim is
  stopped now reports `Stopped` in the Databases list Status column instead of an
  unhealthy/unknown state.

## v2.2.0 — 2026-07-12

### Analytics
- **New `kind: Query` — open-infra's Athena.** Serverless SQL over the data lake
  (MinIO), with no database to load into: point SQL at files in a bucket
  (`read_parquet('s3://…')`) and get results back. Each query is an *execution*
  (Athena's `StartQueryExecution` model) — it runs once in a throwaway **DuckDB** pod
  (a first-party, Trivy-scanned + cosign-signed `open-infra-query` image, extensions
  preloaded) against MinIO and writes the results (CSV) plus an `<id>.metadata.json`
  (state / row count / run time) to an output location; the console reads those back
  (the browser never runs SQL itself). The console **Data → Query** page is an
  Athena-style three-pane editor: a real SQL **code editor** (CodeMirror — syntax
  highlighting, gutter, **⌘/Ctrl+Enter**, run-the-selection-else-all), a left **Data**
  tree that browses buckets/files and inserts `read_parquet(...)` snippets, a
  **resizable results grid** (stats line + Download CSV), tabbed queries, and a
  **Recent queries** history — all rendered in the console's own theme. Phase 2 will
  swap the engine for **Trino** + a **`kind: Catalog`** (Glue equivalent) for
  distributed, `database.table` querying *without changing the `kind: Query`
  contract*. Validated end-to-end (claim → serverless Job → DuckDB → results in
  MinIO → console). See [docs/query.md](docs/query.md).

## v2.1.0 — 2026-07-11

### CI
- **The test suite now gates image build + release** (it was advisory — tests ran but
  nothing consumed the result, so a tag could ship signed images with red tests).
  `test.yml` is now a reusable workflow that `release.yml`, `build-console.yml`, and
  `build-apply-sink.yml` each run as a required `test` job the build/package job
  `needs:` — no image is built, signed, or pushed unless `go test -race` + `vet` pass
  on that ref, regardless of where a tag points (branch protection alone wouldn't
  suffice, since tags can target any commit). Verified with a live red build (a
  deliberately failing test → `build` skipped, no image shipped). See
  [docs/ci.md](docs/ci.md).

### Managed databases
- **New `engine: babelfish`** on an `Application`'s `database:` block — a **SQL-Server-compatible**
  managed database via Babelfish for PostgreSQL (TDS `1433` + T-SQL, backed by PostgreSQL 17). Point
  unmodified SQL Server / T-SQL apps at it with no code changes; the connection secret carries both a
  `SQLSERVER_URL` and a native-Postgres `DATABASE_URL`. The TDS + Postgres listeners are
  **TLS-encrypted** (cert-manager cert; `Encrypt=mandatory`, verified `encrypt_option=TRUE`), it runs
  on **open-infra's own cosign-signed image** (`ghcr.io/…/open-infra-babelfish` — patched Postgres +
  extensions **built from source** via `build-babelfish.yml`, `apt upgrade`d to 0 fixable CVEs), and
  it's a selectable engine in the console's **New
  Database** dialog. **Experimental**: single-instance StatefulSet on Longhorn (not CNPG — no
  streaming HA yet; durability via Longhorn + Velero), and it covers a large-but-incomplete T-SQL
  subset (run *Babelfish Compass* first). Start/Stop supported. Validated end-to-end (T-SQL over
  encrypted TDS via `sqlcmd`, through the composition-generated credentials). See
  [docs/databases.md](docs/databases.md#babelfish--sql-server-compatible-experimental).

### Active Directory (`kind: Directory`)
- **Windows domain join now works end-to-end.** The DC exposes the full standard AD port
  surface — **LDAPS `636`** + **Global Catalog `3268`/`3269`**, **CLDAP `389/UDP`** (the
  DC-locator ping Windows and `samba-tool gpo` require), and the **RPC endpoint mapper `135`
  + a pinned dynamic RPC range `49152-49164`** (machine-account creation) — rather than only
  the TCP LDAP/SMB/Kerberos basics. The RPC range is pinned in Samba (sambacc globals) so it's
  forwardable through the LoadBalancer.
- **The DC advertises its LoadBalancer VIP in AD DNS, not its pod IP.** It previously
  self-registered its ephemeral pod IP (unreachable from the LAN, re-registered on every roll)
  across five zone nodes (`@`, `dc1`, the pod-hostname node, `DomainDnsZones`, `ForestDnsZones`),
  so clients round-robined onto dead addresses. A `dns-vip` sidecar reconciles all of them to
  the VIP, and Samba's `dnsupdate` task is disabled so it never re-registers a pod IP — clients
  resolve the DC to a reachable, stable address with no per-client hosts-file pins.
- **Pod rolls are non-destructive.** The re-provision guard (`/etc/samba/smb.conf`) is persisted
  on the PVC, so a rolled or rescheduled DC serves the existing domain instead of re-provisioning
  a blank one over it (which had silently wiped imported users / OUs / GPOs).

### Console
- **Read-only AD Explorer** for `kind: Directory` — browse the DC's LDAP tree (OUs, groups,
  users, attributes) and search the directory over LDAPS, from the Directory detail page.
- **VM provisioning failures are visible.** The Virtual Machines views read the root disk's
  CDI DataVolume, so a stuck or failed clone shows a red **Disk error** with the reason (or a
  live **Cloning disk 45%** progress) instead of an indefinite "Provisioning" spinner.

### Networking
- **SecurityGroup changes apply to running VMs live — no restart** (matching the EC2 model).
  Editing a VM's `securityGroups` is reconciled onto the running launcher pod within seconds by
  a background reconciler in the console backend; previously the change only took effect on the
  next VM restart, because KubeVirt stamps pod labels only at creation.

### Virtual machines
- **Windows VMs provision reliably.** The fixed Windows root disk is floored above the golden
  image size — CDI refuses to clone a source into a smaller target, which wedged Windows VMs in
  `CloneScheduled` indefinitely. Paired with the console Disk-error surfacing above.

### Security
- Bumped `github.com/Azure/go-ntlmssp` (CVE-2026-32952 — a malicious NTLM challenge could panic
  the process) in the console backend; a transitive dependency of the new LDAP client.

## v2.0.0 — 2026-07-02

Multi-master data movement (`kind: DataFlow`), node-independent VMs with live
migration, and chaos engineering — plus, new in this release, the project's first
**correctness gate** (CI + tests, incl. a multi-master convergence harness) and
**honest maturity tiers**. The major bump reflects the breaking changes below
(chiefly the migration engine re-platform off Airbyte).

### ⚠️ Breaking changes
- **Airbyte and `provider-terraform` are removed; `kind: Migration` is re-platformed**
  onto open-infra's own Debezium + apply-sink engine. Migrations are now **continuous
  by default** (the manual "sync" trigger is gone) and `target.engine` accepts
  `postgres` / `mysql` / `sqlserver` (was Postgres-only). Airbyte-backed Migrations
  from v1.x must be recreated.
- **NATS names are namespace-qualified** (`<ns>-<name>` for streams / subjects /
  durables). Streams and consumers from older flows have different names — recreate
  flows (the orphan GC reaps the old ones); two same-named flows in different
  namespaces no longer share a stream.
- **`kind: DataFlow`: the per-edge `tables` field is removed** (scope is per-flow).
  Move any per-edge `tables` up to the flow level.
- **Console: list pages no longer have inline "fast-delete."** A row opens a detail
  page; destructive actions live in a red **Danger Zone** tab. No API change — a
  muscle-memory change.

### Maturity & guarantees (new — see [README](README.md#maturity--guarantees))
open-infra now states each capability's tier explicitly, because the two audiences it
serves have very different tolerance for failure:
- **Stable:** `Application`, `Model`, `Function`, `VirtualMachine`, `Volume`,
  `FileShare`, `Directory`, and managed databases (Postgres / MySQL / Mongo, incl. HA
  and Start/Stop). Failure here is a restart or rollback.
- **Experimental:** `Replication` (multi-master), cross-engine `Migration`, and
  multi-master `DataFlow` — the Debezium → NATS → apply-sink + HLC last-write-wins
  path. A conflict-resolution bug here is a **silent lost/diverged write**, not a
  crash. Use it, but keep an authoritative source until convergence is automatically
  tested end-to-end (see Known limitations).

### Testing, CI & correctness (new)
- **Stage A CI** (`.github/workflows/test.yml`) — `go vet` + `go test -race` across
  `apply-sink`, `console-api`, and a new `test/render` module, on every push/PR that
  touches Go or the compositions. The correctness gate the project previously lacked.
- **apply-sink unit tests** for the pure CDC logic — driver dialects, cross-engine
  type mapping, and the temporal-coercion buckets behind the cross-engine `DATE` fix.
- **MySQL HLC integration test** (build-tag `integration`) proving the Hybrid Logical
  Clock stays monotonic across a backward wall-clock jump (the T6 fix, now guarded).
- **Composition-render tests** (`test/render`, stdlib only) that assert template logic
  directly — e.g. "Start" always writes `cnpg.io/hibernation: "off"`, and HA renders
  `instances: 2` + required anti-affinity. Proven to catch the hibernation regression
  that once shipped.
- **Multi-master convergence harness** (`apply-sink`, build-tag `convergence`;
  [docs/convergence-harness.md](docs/convergence-harness.md)) — drives concurrent and
  deliberately conflicting writes across a running flow, then asserts every member ends
  byte-identical with zero lost writes. Run it under a `kind: FaultInjection`
  (partition / kill / skew) to prove convergence survives partition and node loss.

### Storage — FileShare node access
- **`spec.nodeIP` on `kind: FileShare`** — also answer SMB 445 on that node's LAN IP
  (Service `externalIPs`), so a masquerade-networked VM (which can't reach a MetalLB
  VIP) can mount `\\<nodeIP>\<name>`. Off unless set; existing shares are unchanged.

### Data Flows — visual data-movement (`kind: DataFlow`)
- **New `kind: DataFlow`** — one resource describing a graph of data-movement nodes
  (databases, message **topics**, transform **functions**, object-store **buckets**) and
  edges. Edge types: `replication` (two-way, optional `bootstrap` to seed an empty
  member), `migration` (one-way, schema auto-create), `stream` (publish CDC to a topic),
  and `pipe` (one-way ETL into a function/database/bucket). `tables: ["*"]` captures
  every table. Compiles onto the existing Debezium + NATS + apply-sink engine.
- **Drag-and-drop console canvas** (Data → Data Flows): palette of engines/topics/
  functions/buckets, edge types inferred from what you connect, fan-out by connecting one
  source to many targets, right-click **Configure** or **Peek metrics**, and a guided
  **Set up replication** wizard that explains the plan and deploys a star topology.
  Migrations and Replication are now modes within Data Flows (folded out of the sidebar).
- **Live observability** — per-edge lag/dead-letter overlay + per-node **Peek**
  (captured / per-table throughput / inbound backlog / retries / dead-letters), via
  `POST /api/dataflows/{ns}/{name}/status`.
- **apply-sink** gains `MODE=pump` (the ETL transform stage: stream → HTTP function →
  stream). Throughput + correctness hardening surfaced by load testing: per-batch
  transactions (one commit per fetch), deterministic `(table, PK)` apply order to avoid
  mesh deadlocks, and a 512 MB per-stream reservation. See [docs/dataflow.md](docs/dataflow.md).
- **Automatic table sync (`spec.autoSyncTables`)** — for multi-master flows, a table
  created on *any* member is auto-created on every other member (cross-engine, with type
  mapping) and made multi-master-ready (version/origin columns + stamping trigger), with no
  spec edit. A per-flow `reconcile` worker drives it; implies capture-all CDC. Verified
  across PostgreSQL + MySQL + MariaDB + SQL Server. Caveat: a table created *already full of
  data* needs a Debezium incremental snapshot to back-load existing rows (create-then-insert
  syncs fully).
- **Durability + correctness hardening** (much found by an adversarial review pass and
  reproduced before fixing): Debezium offsets/schema-history moved from `emptyDir` to a
  per-node **Longhorn PVC** (a capture-pod restart no longer triggers a full re-snapshot);
  mm-prep now **backfills** version/origin on pre-existing rows (a `NULL` version could never
  win last-write-wins → silent divergence); consumer **`AckWait` 2m** (a slow batch is no
  longer redelivered mid-transaction); unchanged **TOASTed** Postgres columns are no longer
  clobbered with Debezium's unavailable-value placeholder; SQL Server **CDC auto-enabled**
  per table for auto-synced sources; injective (length-prefixed) apply sort key; system/CDC
  schemas excluded from discovery; capture pods given resource limits; an orphan
  **stream/DLQ garbage-collector** reaps JetStream resources left by deleted flows.
- **Accessibility** — edge status no longer relies on colour alone (WCAG 1.4.1): line
  **pattern** (solid = in sync, dashed = lagging, dotted = dead-letters, sparse-dots = not
  provisioned) + a shape glyph + a colour-blind-safe (Okabe-Ito) palette.
- Removed the unimplemented per-edge `tables` field from the schema (scope is per-flow).
- **Namespace-qualified NATS names** — streams/subjects/durables are now `<ns>-<name>`-scoped
  (they're cluster-global, unlike k8s objects), so two DataFlows with the same name in different
  namespaces can no longer share streams (cross-tenant cross-feed). Composition + GC + status BFF
  updated in lockstep.
- **Cross-engine DATE coercion** — a Debezium DATE (days since epoch) applied to a column the
  target introspects as `timestamp` is no longer misread as seconds (1970); small temporal
  integers are now treated as days.

### Managed databases (RDS) — console + lifecycle
- **Peek (live engine internals)** on the `/databases` pages — connections, replication-slot
  / CDC lag, and **top queries**, via `POST /api/databases/{ns}/{name}/stats`. The BFF
  resolves host + credentials from the database's own generated Secret (namespace-scoped,
  never client-supplied). PostgreSQL (CNPG) + managed MySQL; MongoDB has no SQL stats.
- **`pg_stat_statements`** is now preloaded and created on managed Postgres (with
  `pg_read_all_stats` granted to the app user) so Peek shows real query history. Foreign
  DataFlow source engines (which we can't modify) gracefully fall back to active queries.
- **Start/Stop (`spec.database.stopped`)** — RDS-style stop/start that retains data: Postgres
  hibernates (CNPG), MySQL/Mongo scale to zero, PVCs are kept. A Start/Stop button on the
  database detail pages toggles it. See [docs/databases.md](docs/databases.md).
- **Convert non-HA ↔ HA on demand** — a High-availability toggle on the database detail pages
  flips `spec.database.highAvailability` on a running DB without a recreate: Postgres (CNPG)
  scales the instance count live (adds/removes a streaming-replication standby — verified
  1→2 in ~30s), Mongo scales the FerretDB proxy tier, MySQL converts to a 3-node Galera.
- **CNPG operator upgraded 1.24.1 → 1.25.1** (Helm chart `0.22.1` → `0.23.2`) — online, no
  Postgres restart. 1.25 unlocks `spec.postgresql.synchronous.dataDurability`, so an HA Postgres
  can run **synchronous** replication that stays available when a standby is down (zero data loss
  while both are up, auto-degrades to async otherwise) instead of the pre-1.25 write-freeze. HA
  failover was validated end-to-end (primary node lost → standby promoted in ~4s, a
  primary-selecting LoadBalancer endpoint follows the new primary; zero data loss).

### Virtual machines — node-independent storage & live migration
- **`spec.highAvailability`** on `kind: VirtualMachine` provisions the root disk on **Longhorn**
  as a migratable RWX block volume (new **`longhorn-migratable`** StorageClass) and sets
  `evictionStrategy: LiveMigrate` — so the VM survives a node loss (reschedule + boot from a
  replica) and **live-migrates** off a drained node with zero downtime. Default stays local-path
  NVMe (faster, but node-pinned). Verified: a Windows VM live-migrated between nodes, running.
- **`spec.cpuModel`** — pin a guest CPU model every node supports so migration/reschedule works on
  a cluster with **heterogeneous CPUs** (`host-model`, the default, ties a VM to its node's exact
  CPU). HA VMs default to `Nehalem`.
- **`spec.existingRootClaim`** — boot from a pre-existing PVC instead of cloning the OS image
  (disk migration / restore); no root DataVolume is provisioned.
- **Golden images now live on Longhorn** (were node-pinned local-path, blocking provisioning when
  that node was down), and **`spec.existingGoldenClaim`** on `kind: VmImage` adopts/clones an
  existing golden so a built image can move to a new storage class without reinstalling. The VM
  Images page shows an adopted (cloned) golden as **Ready** once its PVC binds (no installer VM
  runs). See [docs/virtual-machines.md](docs/virtual-machines.md).

### Chaos engineering (`kind: FaultInjection`) — Fault Injection Simulator
- **Chaos Mesh** installed declaratively (Argo app, k3s containerd socket wired) + a
  **`kind: FaultInjection`** abstraction that compiles a small curated spec to a Chaos Mesh
  experiment with the **blast radius enforced** (always namespace + label-selector scoped,
  time-boxed). Types: pod-kill/pod-failure, network latency/loss/partition, cpu/memory stress,
  clock-skew, io-latency. A **console page** (Observability → Chaos) lists/creates/deletes
  experiments. See [docs/chaos.md](docs/chaos.md).
- **GameDays run** against disposable resources: validated Longhorn volume durability, MariaDB
  stateful recovery, CNPG HA failover, a 9-piece mixed mesh+migration+stream pipeline (converged
  under concurrent capture-kill + partition + sink-kill), and a 4-engine migration relay chain
  (recovered from a mid-chain capture+sink kill).
- **Chaos found a real bug (T6) — now fixed** (commit 2f858fc): a `clock-skew` experiment showed
  MySQL/MariaDB stamping had no monotonic HLC guard, so a backward clock produced a lower
  `_mm_version` → the write lost last-write-wins and silently diverged. MySQL/MariaDB now use a
  monotonic `mm_hlc_state` HLC (+ observe remote versions) like Postgres/SQL Server; re-running
  the same experiment, the version advanced +1 (not backward) and the write converged.

### Security
- Cleared all open Trivy image CVEs: apply-sink Go toolchain 1.22 → 1.26 (43 stdlib CVEs,
  incl. critical) and `jackc/pgx/v5` 5.5.5 → 5.10.0 (2 critical); console-api crypto/net bumps.

### Replication console
- **`kind: Replication` is now a first-class console page** (Data → Replication):
  list, create (both sites + tables), and a detail view showing **both directions**
  of the multi-master pipeline — each with its own lag, per-table throughput, and
  dead-letter panel (shared with the Migration view). Backed by the
  `/api/replications/{ns}/{name}/status` endpoint.

### Observability
- **Migration detail page** with a live apply-pipeline view (SymmetricDS/DMS-style):
  a Capture → Buffer → Apply strip, the headline **replication lag** (events
  captured but not yet applied), **per-table** event counts, and a **dead-letter**
  panel for rows that failed to apply. Backed by a new BFF
  `GET /api/migrations|replications/{ns}/{name}/status` that reads JetStream
  stream/consumer + DLQ info (lag, throughput, errors) the browser can't see.

### Bidirectional / multi-master replication
- **`kind: Replication`** — keep two database sites in sync both ways (each is
  source and target), **across engines** — PostgreSQL, MySQL/MariaDB, and SQL
  Server can each be source *and* target. Built on the same Debezium + NATS +
  apply-sink engine, with **origin-marker loop prevention**, **last-write-wins
  conflict resolution on a Hybrid Logical Clock** (clock-skew-safe; ties broken by
  origin), and capped streams + dead-lettering.
- An `mm-prep` Job installs the version/origin columns + a per-site stamping trigger
  on every engine — Postgres `BEFORE`/HLC, SQL Server `AFTER` (with a nestlevel
  guard, since it has no `BEFORE`-row triggers), MySQL `BEFORE` — so writes to any
  engine are auto-stamped with no application changes. The apply path skips its own
  stamping via a per-engine session flag.
- For 3+ nodes, compose pairwise links into a mesh or a ring; a
  **PostgreSQL + SQL Server + MySQL** round-robin was validated end-to-end (a write
  on any engine reaches the other two; a 3-way conflict converges to the newest).

### Database migration (DMS) — re-platformed off Airbyte
- **`kind: Migration` now runs on open-infra's own engine**: Debezium Server
  captures the source's changes onto NATS JetStream and the new **apply-sink**
  service applies them to the target as idempotent upserts/deletes, auto-creating
  the target schema with **cross-engine type mapping**.
- **Any SQL target** — `target.engine` is now `postgres`, `mysql`, or `sqlserver`
  (was Postgres-only), and the source may differ from the target (e.g. SQL Server →
  Postgres). Source engines: Postgres, MySQL/MariaDB, SQL Server.
- **Continuous by default** — a Migration snapshots then streams CDC; the manual
  "sync" trigger is gone (like AWS DMS continuous tasks).
- **Airbyte and `provider-terraform` are removed entirely** — a much lighter stack
  (no Temporal / workers / second Postgres). The apply-sink image is Trivy-scanned
  and cosign-signed by CI like the console.

### Fixes
- **Buckets page self-heals on MinIO credential rotation** — the console cached its MinIO client
  forever, so a MinIO restart with rotated root credentials 502'd the Buckets page until the
  console was restarted. It now re-reads the secret and rebuilds the client whenever the creds
  change (cache keyed by the credentials).

### Known limitations
- **Multi-master convergence** is verified by a harness, but injecting the fault
  (partition / kill / skew) is still driven by hand — not yet a single-command run.
- **Incremental back-load** — a table added to a flow that is *already full of data*
  needs a Debezium incremental snapshot to back-load existing rows (create-then-insert
  syncs fully).
- **VM `network: bridge` is experimental and not currently working** — a macvlan
  sub-interface can't be a KubeVirt bridge port, so a bridged VM crash-loops. VMs reach
  in-cluster services via `<nodeIP>:<nodePort>` (or a FileShare's `nodeIP`); a working
  bridge (macvtap) is planned. The `install.sh` vmLan block installs this plumbing and
  still carries an over-broad path-remap `sed` to fix.
- **Redis** pins Bitnami's legacy image mirror as a stopgap (Bitnami purged its public
  versioned tags in Aug 2025); migrating off Bitnami is tracked.

## v1.0.0 — 2026-06-23

The first stable release. Since v0.1.0 the platform gained real network security,
streaming + database migration, managed Active Directory, and EBS/FSx-style
storage — and the web console grew to manage all of it. AWS-equivalents are noted
in [`docs/architecture.md`](docs/architecture.md).

### Networking & Security
- **Cilium is now the cluster CNI** (full kube-proxy replacement), replacing
  flannel + the embedded kube-proxy/network-policy controller. This gives real
  `ipBlock`/CIDR NetworkPolicy enforcement. `install.sh` installs it.
- **`kind: SecurityGroup`** — AWS-style, reusable, stateful firewall rule sets,
  enforced by Cilium. Rules use **Type presets** (SSH/RDP/HTTP/… auto-fill
  protocol + port), sources of CIDR / another security group / namespace, and
  optional per-rule descriptions.
- **Dual-surface management in the console, mirroring EC2**: a **Security tab** on
  every VM, Application, Function, and Database (attached groups + aggregated
  read-only inbound/outbound rules + *Change security groups*), and a **security
  group detail page** (Inbound/Outbound/Used-by tabs, edit rules, copy to new).
- New resources get a sensible **default access group** at launch (SSH 22 for
  Linux, RDP 3389 for Windows), like the EC2 launch wizard.

### Data & streaming
- **`kind: Stream`** — change-data-capture from a source database to NATS
  JetStream via Debezium Server (Postgres / MySQL / MariaDB / SQL Server / Mongo).
- **`kind: Function` stream triggers** — event-source mapping: a function
  cold-starts on each CDC event and scales back to zero.

### Database migration (DMS)
- **`kind: Migration`** — Airbyte-backed full-load + CDC into managed Postgres,
  with a console wizard (source → target → table picker → run + monitor). Sources
  include Postgres, MySQL/MariaDB, SQL Server, and MongoDB.

### Identity
- **`kind: Directory`** — managed Active Directory via Samba AD DC, with Windows
  domain-join (and a *Join domain* picker in the New VM dialog).

### Storage
- **`kind: Volume`** (EBS) and **`kind: FileShare`** (FSx-style SMB) with console
  management pages; volume hotplug attach/detach to running VMs.
- MinIO HA and the data plane are pinned by node label, not hostnames.

### Virtual machines
- `spec.ports` publishes extra TCP/UDP ports on the VM's LAN IP; exposure is now
  driven by the attached security groups (`externalTrafficPolicy: Local` so source
  rules can match real clients).
- QEMU guest-agent / virtio fixes (IP reporting, hotplug visibility, snapshots).

### Fixes
- An Application's namespace LimitRange no longer caps co-located VM launcher pods
  (which broke VM launch with "request greater than limit").
- Console: action buttons no longer also open the YAML drawer; long values no
  longer overflow dialogs; assorted RBAC grants for new resource pages.

### Supply chain
- The console image is built, **Trivy-scanned, and cosign-signed** (keyless,
  Sigstore) by CI, and on a `v*` tag is published to GHCR with the version tag.

## v0.1.0 — 2026-06-20

First public release.
