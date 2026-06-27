# Changelog

All notable changes to open-infra are recorded here. Versions follow
[semantic versioning](https://semver.org). The `openinfra.dev` resource kinds are
the product's public contract.

## Unreleased

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
