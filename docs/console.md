# Web Console

open-infra ships a single-page **web console** — an AWS-console-style UI for the
whole platform. It's one container: a Go BFF with a React SPA embedded, talking to
the Kubernetes API, MinIO, NATS, and Grafana on your behalf.

## Access

Served behind Traefik/MetalLB at `https://console.<lb-ip>.sslip.io` (self-signed
TLS in dev). The image (`ghcr.io/<owner>/open-infra-console`) is built by CI;
runtime config (cluster name, Grafana URL) is read from the environment at request
time, so the same image runs in any cluster.

## Navigation

The sidebar is grouped like a cloud console:

- **Dashboard** — counts + health for every resource type, plus recent events.
- **Compute** — Applications, Functions, Virtual Machines.
- **Storage** — Volumes, File Shares.
- **Identity** — Active Directory.
- **AI** — Models.
- **Data** — Databases, Migrations, Streams, Buckets, Queues.
- **Cluster** — Workloads (pods/deployments), Nodes (with GPU capacity), Network.
- **Observability** — Monitoring (embedded Grafana dashboards).

## Resource views & detail pages

Every list view is live (server-sent events), filterable, and sortable. Clicking a
row opens a **full-page detail view** with AWS-style tabs and actions:

| Resource | Detail tabs / actions |
|---|---|
| **Application** | spec, attached DB/buckets/queues, conditions, YAML · create / delete |
| **Function** (Lambda) | Overview (image/scaling/URL), Monitoring (Grafana), YAML · create / delete |
| **Virtual Machine** (EC2) | Overview (phase/IP/resources), **VNC console**, **Network** (security groups — the firewall; reachable LAN ports follow the rules), disks (hotplug attach/detach), Start/Stop, YAML · create / delete |
| **Model** (Bedrock) | **Playground** (chat with the model), Overview (endpoint + API key), GPU Monitoring, YAML · create / delete |
| **Database** (RDS) | Overview (phase/instances/storage), Connectivity (host/port/db/user + connection URI), Monitoring, YAML |
| **Migration** (DMS) | **New Migration wizard** (source → target → task type → table picker → review), detail page with a live **Capture → Buffer → Apply** pipeline (replication lag, per-table throughput, dead-letter) · create / delete |
| **Replication** (multi-master) | **New Replication** (two sites + tables), detail page showing **both directions**, each with lag / per-table / dead-letter · create / delete |
| **Stream** (Kinesis) | **New Stream** (source endpoint + tables), JetStream subjects, status · create / delete |
| **Bucket** (S3) | Objects — browse folders, **upload / download / delete** · create / delete bucket |
| **Queue** (SQS) | Overview (messages/size/consumers/subjects), **Publish** a message, **Purge** |
| **Volume** (EBS) | Overview (size/class/attachment), **snapshot / restore**, attach to a VM, YAML · create / delete |
| **File Share** (EFS/FSx) | Overview, **Connect** (Windows `net use` / Linux `mount`), YAML · create / delete |
| **Active Directory** (Directory Service) | Overview (domain/realm/DC), **Join** instructions, YAML · create / delete |
| **Node** | CPU/memory/pod capacity, **GPU** (count + model), conditions, YAML |

## How it works

```
browser ──► console pod (single container)
              ├─ React SPA (embedded via go:embed)
              └─ Go BFF (chi)
                   ├─ /api/k8s/*       reverse proxy to the Kubernetes API (SA RBAC governs)
                   ├─ /api/watch       SSE for live lists
                   ├─ /api/crd-schema  CRD → JSON Schema (drives the create forms)
                   ├─ /api/buckets…    MinIO S3 (list / browse / upload / download / delete)
                   ├─ /api/queues…     NATS JetStream (stats / publish / purge)
                   ├─ /api/models/…/chat   proxy to a Model's gated endpoint (key stays server-side)
                   ├─ /api/migrations/… discover source tables (the DMS engine runs continuously and stays hidden)
                   └─ /grafana/*       same-origin Grafana embed
```

The console runs **read-mostly**: its ServiceAccount has scoped RBAC — read
workloads + CRDs, CRUD on the `openinfra.dev` kinds, `get` + create/manage on
secrets *by name* (connection info, a model's key, and the DMS wizard's credential
secret), and a narrow read of just the MinIO root secret. It is **not** cluster-admin.

## Tech

React 19 + Vite + TypeScript + shadcn/ui + Tailwind + TanStack (Router/Query/Table)
+ rjsf (schema-driven create forms); Go BFF with client-go, minio-go, and nats.go.
Built and pushed as a single image by the `build-console` GitHub Action.
