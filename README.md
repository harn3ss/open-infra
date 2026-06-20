# open-infra

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
| ASG | autoscaling | HPA + KEDA |
| ALB / ELB | ingress + LB | Traefik + MetalLB |
| Route 53 | DNS | ExternalDNS / sslip.io / Cloudflare |
| ACM | TLS | cert-manager |
| S3 | object storage | MinIO |
| RDS | managed Postgres | CloudNativePG |
| SQS / SNS | queues + pub/sub | NATS JetStream |
| ElastiCache | cache | Redis |
| Lambda | serverless (`kind: Function`) | Knative — scale-to-zero |
| Bedrock | managed inference (`kind: Model`) | Ollama on GPU + NVIDIA device plugin |
| CloudFormation | the manifest | `infra.yaml` → Crossplane |
| CloudWatch | metrics/logs | Prometheus + Grafana + Loki |
| Secrets Manager | secrets | Sealed Secrets |
| AWS Backup | backup/DR | Velero |

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
resource (Applications, Functions, Models, Databases, Buckets, Queues, Nodes/GPUs,
Monitoring) with per-resource detail pages and actions (object browser, model
playground, create/delete). See [`docs/console.md`](docs/console.md).

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

**Working spine — validated on a live 3-node cluster (2 nodes with GPUs).** Phases (see [`docs/roadmap.md`](docs/roadmap.md)):

- [x] Phase 0 — Cluster foundation (k3s, MetalLB, Traefik, cert-manager) — nginx reachable over HTTPS ✓
- [x] Phase 1 — GitOps engine (Argo CD app-of-apps reconciling from this repo) ✓
- [x] Phase 2 — Platform services (MinIO, CloudNativePG, NATS, Redis) — all Healthy ✓
- [x] Phase 3 — The `Application` abstraction (Crossplane XRD + Composition; live end-to-end demo) ✓
- [x] Phase 4 — Observability — Prometheus/Grafana/Alertmanager + Loki/Promtail; metrics **and** logs in Grafana with no per-app config ✓
- [x] Phase 5 — Serverless — `kind: Function` on Knative (scale-to-zero 0→N→0, incl. GPU functions) ✓
- [x] Phase 6 — DX & packaging (installer, CLI, GitHub Action, and a deployed **web console**) ✓
- [~] Phase 7 — Hardening & multi-tenancy (per-app ResourceQuota + LimitRange + NetworkPolicy shipped; backups + image scanning pending)
- [x] GPU & managed inference — NVIDIA device plugin + DCGM metrics/Grafana, and a Bedrock-like `kind: Model` (GPU-backed, OpenAI-compatible, key-gated) ✓

A one-command `install.sh` stands up k3s + MetalLB + Argo CD, and the app-of-apps
installs cert-manager, MinIO, CloudNativePG, NATS, Redis, and the
kube-prometheus-stack/Loki observability stack. Both abstractions — `Application`
(Deployment/Service/Ingress/HPA + Postgres/bucket/queue) and `Model` (GPU-backed
inference) — are shipped and verified end-to-end on the live cluster.

> **Note:** Redis currently pins Bitnami's legacy image mirror as a stopgap
> (Bitnami purged its public versioned tags in Aug 2025); migrating off Bitnami
> is tracked for v1.

---

## License

[Apache-2.0](LICENSE). Contributions welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md).
