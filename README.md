# open-infra

[![Release](https://img.shields.io/github/v/release/harn3ss/open-infra?sort=semver)](https://github.com/harn3ss/open-infra/releases)
[![Build console](https://github.com/harn3ss/open-infra/actions/workflows/build-console.yml/badge.svg)](https://github.com/harn3ss/open-infra/actions/workflows/build-console.yml)
[![License: Apache-2.0](https://img.shields.io/github/license/harn3ss/open-infra)](LICENSE)

> A **free, self-hostable mini-cloud**. Drop one simple `infra.yaml` into your app
> repo, `git push`, and get an AWS-like managed experience — autoscaling HTTPS
> services, a Postgres database, object storage, queues — running on your own
> commodity Linux boxes at **zero cloud cost**.

```yaml
# infra.yaml — you write intent, the platform produces infrastructure
apiVersion: openinfra.dev/v1
kind: Application
metadata:
  name: my-api
spec:
  image: ghcr.io/me/my-api
  port: 8080
  scaling: { min: 1, max: 10, targetCPUPercent: 70 }
  domain: my-api.example
  database: { engine: postgres, name: myapidb }
  storage:  { buckets: [uploads] }
  queues:   [jobs]
```

`git push` → GitHub Action builds the image → GitOps controller reconciles the
whole desired state (hosting, DB, storage, queues, DNS, TLS, autoscaling).
The experience feels like AWS; the bill is $0.

---

## Why

The guiding principle: **the user writes intent, the platform produces
infrastructure.** open-infra is *glue + developer experience* on top of proven
CNCF projects — not a reinvention of databases or storage.

| AWS | open-infra | Tool |
|---|---|---|
| EC2 / ECS | container orchestration | k3s |
| ASG | autoscaling | HPA |
| ALB / ELB | ingress + LB | Traefik + MetalLB |
| Route 53 | DNS | sslip.io / Cloudflare |
| ACM | TLS | cert-manager |
| S3 | object storage | MinIO |
| EBS | block volumes (`kind: Volume`) | Longhorn |
| EFS / FSx | shared file storage (`kind: FileShare`) | Samba (SMB) on Longhorn |
| RDS | managed SQL (`engine: postgres`/`mysql`) | CloudNativePG / MariaDB |
| DynamoDB | document store (`engine: mongo`) | FerretDB on DocumentDB-Postgres |
| OpenSearch Vector | vector search (`database.vector: true`) | pgvector |
| DMS | DB migration + CDC (`kind: Migration`) | Debezium + apply-sink + Crossplane |
| DMS (multi-master) | bidirectional replication (`kind: Replication`) | Debezium + apply-sink (HLC last-write-wins) |
| Glue / DMS / Kinesis / Lambda (visual) | data-movement pipelines (`kind: DataFlow`) | drag-and-drop canvas → Debezium + NATS + apply-sink |
| SQS / SNS | queues + pub/sub | NATS JetStream |
| Kinesis | streaming CDC (`kind: Stream`) | Debezium → NATS JetStream |
| ElastiCache | cache | Redis |
| Lambda | serverless (`kind: Function`) | Knative — scale-to-zero |
| Bedrock | managed inference (`kind: Model`) | Ollama on GPU + NVIDIA device plugin |
| EC2 | virtual machines (`kind: VirtualMachine`) | KubeVirt + CDI (Linux + Windows) |
| Directory Service | Active Directory (`kind: Directory`) | Samba AD DC |
| Security Groups | firewall rule sets (`kind: SecurityGroup`) | Cilium NetworkPolicy |
| CloudFormation | the manifest | `infra.yaml` → Crossplane |
| CloudWatch | metrics/logs | Prometheus + Grafana + Loki |
| Secrets Manager | secrets | Sealed Secrets |
| AWS Backup | backup/DR | Velero |
| Fault Injection Simulator | chaos engineering (`kind: FaultInjection`) | Chaos Mesh |

Full mapping and rationale: [`docs/architecture.md`](docs/architecture.md).

---

## Quickstart

> **You need:** one or more Linux boxes (a single box is fine for `dev` mode),
> a non-root user with sudo, and ~10 minutes. See
> [`docs/quickstart.md`](docs/quickstart.md) for the full walkthrough.

```bash
git clone https://github.com/harn3ss/open-infra
cd open-infra
cp config.example.yaml config.yaml     # edit: LAN IP pool, domain, mode
./install.sh                            # installs k3s + Argo CD + the platform
```

Then deploy your first app:

```bash
./cli/open-infra init      # scaffold an infra.yaml in your app repo
./cli/open-infra deploy    # render + commit to the GitOps repo; Argo does the rest
./cli/open-infra status    # see what's running
```

A 15-line `infra.yaml` becomes a running, autoscaling, HTTPS app with a database
and a bucket — with **zero raw Kubernetes** authored by you.

---

## How it works

```
git push infra.yaml ──► GitHub Action (build image, push, bump tag)
                              │
                              ▼
                        GitOps state repo ──► Argo CD reconciles
                              │
   ┌──────────────────── k3s cluster (your boxes) ────────────────────┐
   │  Application CR ──► Crossplane Composition fans out to:           │
   │     Deployment + Service + Ingress + HPA                          │
   │     + CloudNativePG database  + MinIO bucket  + NATS stream       │
   │  cert-manager (TLS) · Traefik+MetalLB (LB) · ExternalDNS (DNS)    │
   │  Prometheus/Grafana/Loki (observability) · Sealed Secrets · Velero│
   └──────────────────────────────────────────────────────────────────┘
```

A **web console** ships with the platform — an AWS-console-style UI over every
resource (Applications, Functions, Models, Virtual Machines, Databases, Volumes,
File Shares, Buckets, Queues, Data Flows, Streams, Active Directory, Nodes/GPUs, Monitoring)
with per-resource detail pages and actions (object browser, model playground, the
drag-and-drop **Data Flows** canvas + guided replication wizard, create/delete). See
[`docs/console.md`](docs/console.md).

See [`docs/architecture.md`](docs/architecture.md) for the full diagram and the
public-edge story (Cloudflare Tunnel + optional Lightsail/WireGuard).

---

## GPU & managed inference ("Bedrock")

Label a GPU node and open-infra advertises its GPUs (shown on the console **Nodes**
panel), scrapes per-GPU metrics into Grafana, and lets you stand up **managed
inference** with one resource:

```yaml
# infra.yaml — a GPU-backed, OpenAI-compatible endpoint gated by an API key
apiVersion: openinfra.dev/v1
kind: Model
metadata:
  name: chat
spec:
  model: llama3.1:8b      # any Ollama model tag
  gpu: 1
```

`open-infra init model` scaffolds this; apps consume it by referencing the
generated `chat-model` secret (`OPENAI_BASE_URL` / `OPENAI_API_KEY` / `MODEL`).
Full setup — host prerequisites, the device plugin, GPU dashboards, and consuming
the endpoint — is in [`docs/gpu.md`](docs/gpu.md).

---

## Status

**Validated on a live 3-node cluster (2 with GPUs).** One `install.sh` stands up
k3s + MetalLB + Argo CD; the app-of-apps reconciles the platform (cert-manager,
MinIO, CloudNativePG, MariaDB, FerretDB, NATS, Redis, Longhorn, kube-prometheus-stack
+ Loki, Sealed Secrets, Knative, Velero, KubeVirt). The eleven public
abstractions are shipped and exercised on that cluster — but **maturity varies by
capability** (see [Maturity & guarantees](#maturity--guarantees)):

- **`Application`** — Deployment/Service/Ingress/HPA, plus managed databases
  (Postgres / MySQL / MongoDB), object storage, and queues — with per-app
  quotas, limits, and NetworkPolicies.
- **`Model`** — GPU-backed, OpenAI-compatible inference (open-infra's "Bedrock").
- **`Function`** — Knative scale-to-zero serverless (open-infra's "Lambda").
- **`VirtualMachine`** — real VMs via KubeVirt (open-infra's "EC2"): an OS
  catalog (Linux + Windows), persistent disk, SSH/RDP. See
  [`docs/virtual-machines.md`](docs/virtual-machines.md).
- **`Volume`** — EBS-style block volumes (Longhorn): create, hotplug-attach to VMs,
  snapshot/restore.
- **`FileShare`** — shared SMB file storage (open-infra's "EFS/FSx"), with a Connect
  helper (Windows `net use` / Linux `mount`).
- **`Directory`** — managed Active Directory (Samba AD DC) for Windows domain join.
- **`FaultInjection`** — chaos engineering (open-infra's "Fault Injection Simulator"):
  declare a fault (pod-kill, network partition/latency/loss, CPU/memory stress, clock skew,
  IO latency) scoped to a namespace + label selector; it compiles to a blast-radius-enforced
  Chaos Mesh experiment. Ships a curated library that validates the platform's own resilience
  (CNPG failover, CDC offset durability, mesh convergence). See [`docs/chaos.md`](docs/chaos.md).
- **Managed databases (RDS)** — declared by an `Application`'s `database:` block:
  PostgreSQL (CloudNativePG), MySQL (MariaDB), or MongoDB (FerretDB), with HA,
  **Start/Stop** (data-retaining hibernation), and a live **Peek** (connections / CDC lag /
  top queries). See [`docs/databases.md`](docs/databases.md).
- **`Migration`** — AWS-DMS-style DB migration + CDC on a Debezium + apply-sink engine:
  full-load or continuous sync into a target SQL database, with a console wizard and
  a live status view (lag, per-table throughput, dead-letter). See
  [`docs/migrations.md`](docs/migrations.md).
- **`Replication`** — bidirectional / multi-master replication (open-infra's
  "SymmetricDS"): keep databases in sync both ways, across engines
  (e.g. SQL Server ⇄ PostgreSQL ⇄ MySQL), with origin-marker loop prevention and
  Hybrid-Logical-Clock last-write-wins conflict resolution. See
  [`docs/replication.md`](docs/replication.md).
- **`Stream`** — Kinesis-style streaming CDC: a headless Debezium Server publishes a
  source database's row changes as real-time events onto NATS JetStream for
  event-driven consumers. See [`docs/streaming.md`](docs/streaming.md).
- **`DataFlow`** — a visual data-movement pipeline (open-infra's "Glue + Step
  Functions for data"): a drag-and-drop console canvas where you chain databases,
  message topics, transform **functions**, and object-store buckets, then deploy the
  whole topology as one resource. Replication, migration, CDC-to-topic, and ETL
  transforms are all just edge types on the same canvas — with a guided setup wizard,
  live per-edge lag/dead-letter overlay (colour-blind-safe), and right-click **Peek**
  per-step metrics. Multi-master flows can **auto-sync their table set** across members
  (`autoSyncTables`). See [`docs/dataflow.md`](docs/dataflow.md).

**Reach anything from the LAN.** Every resource takes `expose: true` to get a
real LAN IP (MetalLB LoadBalancer) — Applications, Models, Databases, VMs;
Functions are LAN-reachable via the Knative gateway (`expose: false` makes them
cluster-local). VMs reach in-cluster services (databases, file shares) through their
host node at `<nodeIP>:<nodePort>`; a fully on-LAN VM mode (`network: bridge`, a real
DHCP lease) is **experimental and not currently working** on the reference cluster —
see [Maturity & guarantees](#maturity--guarantees).

> **Note:** Redis currently pins Bitnami's legacy image mirror as a stopgap
> (Bitnami purged its public versioned tags in Aug 2025); migrating off Bitnami
> is tracked for v1.

---

## Maturity & guarantees

open-infra spans two kinds of thing, and they don't carry the same risk. Read this
before you point it at data you can't afford to lose.

**Stable — the PaaS surface.** `Application` (Deployment/Service/Ingress/HPA),
`Model`, `Function`, `VirtualMachine`, `Volume`, `FileShare`, `Directory`, and
managed databases (Postgres / MySQL / Mongo, including HA and Start/Stop) are the
day-to-day surface. A failure here is a restart or a rollback — the homelab-PaaS
promise. These run continuously on the reference cluster.

**Experimental — the distributed-systems primitives.** `Replication`
(bidirectional / multi-master), cross-engine `Migration`, and multi-master
`DataFlow` ride a change-data-capture engine (Debezium → NATS → apply-sink) with
Hybrid-Logical-Clock last-write-wins conflict resolution. This is the most capable
part of open-infra and the least forgiving: a conflict-resolution bug is not a
crash you notice — it's a **silently lost or diverged write** you may find weeks
later. Correctness here rests today on design + hand testing + a growing automated
suite, including a [convergence harness](docs/convergence-harness.md) that drives
concurrent/conflicting writes and asserts every member ends identical with zero lost
writes — though injecting the fault (partition / node loss) is still driven by hand,
**not yet** a one-command run. Until that's automated: use it, keep an authoritative
source, and don't make multi-master the system of record for data you can't
reconstruct.

**What's tested, concretely** (`.github/workflows/test.yml`, `go test`): the
pure CDC logic (driver dialects, cross-engine type mapping, the temporal-coercion
rules that decide how a `DATE`/`timestamp` value lands in another engine),
composition rendering (so, e.g., "Start" always un-hibernates a database), and the
MySQL HLC's monotonicity under a backward wall clock. **Not yet automated:**
unattended fault orchestration for the convergence harness (partition / kill / skew
are applied by hand today), and incremental-snapshot back-load of rows added to a
table *after* a flow starts (create-then-insert syncs fully; back-loading a
pre-populated, late-added table is a known gap).

**One maintainer, one cluster.** open-infra is built and validated by one person on
one live cluster. The direction of travel is to make correctness *mechanical*
(tests, CI, chaos-as-verification) rather than attention-dependent — calibrate trust
accordingly, especially for the experimental tier.

From **v2.0.0** the changelog states each capability's tier explicitly, and breaking
changes to the stable surface get a major-version bump.

---

## License

[Apache-2.0](LICENSE). Contributions welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md).
