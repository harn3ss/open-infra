# Architecture

open-infra is **glue + developer experience** on top of proven CNCF projects.
The value is the *workflow and the manifest*, not reimplementing storage/db/queues.

## The flow

```
git push infra.yaml ──► GitHub repo (app code + Dockerfile + infra.yaml)
                              │ GitHub Action: build image → push → bump tag
                              ▼
                        GitOps state repo (desired cluster state)
                              │ Argo CD watches & reconciles
                              ▼
   ┌──────────────────── k3s cluster (your boxes) ─────────────────────┐
   │  Application CR ──► Crossplane Composition compiles into:          │
   │     Deployment + Service + Ingress + HPA                           │
   │     + CloudNativePG database  + MinIO bucket  + NATS stream        │
   │  cert-manager (TLS) · Traefik + MetalLB (LB) · ExternalDNS (DNS)   │
   │  kube-prometheus-stack + Loki (observability)                     │
   │  Sealed Secrets · Velero (backups)                                │
   └────────────────────────────────────────────────────────────────────┘
```

## AWS → open-infra component map

| AWS | open-infra | Tool | Notes |
|---|---|---|---|
| EC2/ECS/Fargate | orchestration | **k3s** | HA = 3 servers w/ embedded etcd |
| Auto Scaling Groups | autoscaling | **HPA** + **KEDA** | node autoscaling on bare metal is manual in v1 |
| ELB/ALB/NLB | ingress + LB | **Traefik** + **MetalLB** | MetalLB needs reserved LAN IPs |
| Route 53 | DNS | **ExternalDNS** / sslip.io / **Cloudflare** | sslip.io = zero-config dev default |
| ACM | TLS | **cert-manager** | LE public, or self-signed LAN CA |
| S3 | object storage | **MinIO** | can reuse an existing NAS data dir |
| RDS/Aurora | managed Postgres | **CloudNativePG** | **local NVMe PVs, never CIFS/NFS** |
| DynamoDB | NoSQL | *(deferred)* | post-v1 if demand |
| ElastiCache | cache | **Redis** | |
| SQS/SNS | queues + pub/sub | **NATS JetStream** | one component, both patterns |
| Lambda | serverless | **Knative** | Phase 5, optional, scale-to-zero |
| ECR | registry | **GHCR** (default) / **Harbor** | Harbor for offline/self-host |
| CloudFormation/CDK | the manifest | **infra.yaml → Crossplane** | the heart of the product |
| CloudWatch | metrics/logs/alerts | **kube-prometheus-stack** + **Loki** | Grafana = the console |
| IAM | authz/isolation | k8s **RBAC** + namespaces + **NetworkPolicy** | one namespace per app |
| Secrets Manager | secrets | **Sealed Secrets** [+ Vault] | encrypted secrets safe in Git |
| VPC | network isolation | namespaces + **Cilium/Calico** policies | |
| AWS Backup | backup/DR | **Velero** → MinIO/NAS | |
| Cost Explorer | usage/billing | **Kubecost** / Grafana | a fun "what AWS would've charged" panel |

## The `Application` abstraction (the product)

The user authors ONE high-level resource; Crossplane compiles it into all the
pieces. The schema lives in [`platform/abstraction/xrd.yaml`](../platform/abstraction/xrd.yaml)
and the compiler in [`platform/abstraction/composition.yaml`](../platform/abstraction/composition.yaml).

**The `infra.yaml` schema is the public API — keep it stable** even if the engine
behind it changes. Crossplane (Compositions) was chosen over a bespoke operator
or KubeVela for v1: declarative, CNCF, and "one claim → many resources" fits
exactly.

## Storage tiering (read this twice)

- **Fast local NVMe (RWO)** via k3s `local-path` for **databases**.
- **NAS-backed RWX** (SMB/NFS subdir provisioner) for shared/bulk volumes only.
- **Never put a database on CIFS/NFS** — corruption and latency hell.

## Public edge & connectivity

The cluster typically runs behind residential NAT with no stable public IP. To
serve the internet without port-forwarding:

```
   public user ──► Cloudflare edge (DNS + TLS + WAF)
                        │  Cloudflare Tunnel (outbound-initiated)
                        ▼
        ┌── cloudflared (in-cluster) ──► Traefik ingress ──► app pods
        │
   Lightsail (public IP, always-on): docs/landing · public demo · WireGuard hub
        │  (WireGuard — only for non-HTTP / raw TCP/UDP)
        ▼
   home k3s nodes (private)
```

- **Primary path — Cloudflare Tunnel (`cloudflared`)**: runs in-cluster, connects
  outbound to Cloudflare. No port-forwarding, no exposed home IP. Cloudflare
  provides DNS, edge TLS, and DDoS protection. Recommended default for going public.
- **cert-manager DNS-01** via the Cloudflare API can mint wildcard
  `*.apps.yourdomain` certs for end-to-end TLS.
- **Lightsail + WireGuard** is the advanced tier for raw TCP/UDP that a tunnel
  won't carry, plus an always-on anchor for the public docs/demo. Keep it thin —
  it's the only paid box.

Two documented paths: **(a)** zero-config local/LAN with magic DNS for trying it
out, and **(b)** the Cloudflare-Tunnel public path for real internet exposure
without a static IP.
