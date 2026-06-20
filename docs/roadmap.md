# Roadmap

Build bottom-up. Each phase produces something testable; **don't start the DX
layer (Phase 3) before the substrate (0–2) is solid.** Each phase has an *exit
test* — the bar for calling it done.

| Phase | Scope | Exit test |
|---|---|---|
| **0 — Foundation** | k3s, MetalLB, Traefik, cert-manager, storage classes, sslip.io DNS | Deploy raw nginx Deployment+Service+Ingress, reach it over HTTPS from another machine |
| **1 — GitOps** | Argo CD + app-of-apps; repo layout | Change a manifest in Git, watch Argo reconcile automatically |
| **2 — Platform services** | MinIO, CloudNativePG, NATS, Redis; registry decision | Manually create a bucket, a Postgres cluster, a NATS stream; connect from a test pod |
| **3 — Abstraction (the product)** | `Application` XRD + Composition; HPA/KEDA wiring | A 15-line `infra.yaml` → running, autoscaling, HTTPS app + DB + bucket, zero raw k8s |
| **4 — Observability** | kube-prometheus-stack + Loki; default per-app dashboards | See an app's metrics + logs in Grafana without per-app config |
| **5 — Serverless (optional)** | Knative Serving (scale-to-zero); `kind: Function` | An HTTP function scales 0→N→0 |
| **6 — DX & packaging** | `install.sh`, `open-infra` CLI, reusable Action, docs site, examples | A newcomer follows the 10-min tutorial successfully on fresh boxes |
| **7 — Hardening & multi-tenancy** | namespace-per-app, RBAC, quotas, NetworkPolicies, Sealed Secrets, Velero, Trivy/cosign, Argo Rollouts | Two tenants isolated; default-deny network; scheduled backups restore cleanly |

## Current state

**Validated on a live 3-node cluster (2 nodes with GPUs).** `install.sh` stands up
k3s + MetalLB + Argo CD, and the app-of-apps reconciles the platform from this
repo: cert-manager, MinIO, CloudNativePG, NATS, Redis, kube-prometheus-stack +
Loki, Sealed Secrets, and Knative all reach Healthy.

**Phases 0–6 are done.** The `Application` abstraction (3); observability with
metrics **and** logs, no per-app config (4); serverless `kind: Function` on Knative
— scale-to-zero 0→N→0 verified (5); and the installer/CLI/Action + a deployed web
console (6). On top of the numbered plan: GPU scheduling + DCGM metrics, a
Bedrock-style `kind: Model` (GPU-backed, OpenAI-compatible, key-gated inference),
and GPU-capable serverless functions. **Phase 7** (hardening) is in progress —
per-app ResourceQuota/LimitRange/NetworkPolicy + Sealed Secrets shipped and
verified; Velero backups and image scanning remain.

Issues surfaced and fixed during live bring-up (kept here so they don't resurface):

- **Loki** — the original SingleBinary values failed `helm template` (scalable
  targets had replicas too), so Loki never deployed and the app sat `Unknown`.
  Fixed: zero read/write/backend, add `schemaConfig`, disable caches/gateway.
  Lesson: an Argo app stuck `Unknown` (ComparisonError) is *broken*, not cosmetic.
- **sealed-secrets** — same `Unknown` symptom: its Helm repo URL 404'd, so it never
  deployed. *Fixed:* the chart moved orgs (`bitnami-labs.github.io` →
  `bitnami.github.io`); bumped to 2.19.0.

- **Argo CD install** must use `--server-side` — the ApplicationSet CRD exceeds
  the 256 KB client-side `last-applied-configuration` annotation limit.
- **CloudNativePG** needs `ServerSideApply` for the same reason (its large
  `Pooler` CRD was silently dropped otherwise).
- **Redis** — Bitnami purged `docker.io/bitnami/*` versioned tags (Aug 2025); the
  chart now pins the `bitnamilegacy` mirror as a stopgap. *Migrate off Bitnami.*
- **NATS** config-reloader needs adequate host `fs.inotify.max_user_instances`
  (default 128 is too low on busy nodes — bump to 512).
- The installer's config reader strips inline `# comments` and quotes.

## Key decisions (don't re-litigate)

- **k3s** over kubeadm — lightweight, single-binary, ideal for commodity hardware.
- **Argo CD** over Flux for v1 — UI aids the AWS-console feel + onboarding.
- **Crossplane Compositions** for the abstraction — declarative, CNCF, one-claim→many.
- **GHCR** default registry — zero infra; Harbor documented for offline.
- **sslip.io** magic DNS for dev; **Cloudflare** for the public path.
- **Cloudflare Tunnel** for public exposure; **Lightsail + WireGuard** edge for
  non-HTTP / fallback (the only paid box — keep it thin).
- **Lean on CNCF**, build glue + DX.

## Open questions for the human

- **Domain name** + a **Cloudflare API token** scoped for DNS-01 + Tunnel (for
  the public path).
- **Node count & specs** available now (affects HA topology + default limits).
- **Spare LAN IP range** for MetalLB (small pool outside DHCP).
- **DynamoDB-style NoSQL** — needed for v1, or defer?
- **Serverless (Lambda)** — v1 scope or v2?
- **Public launch** — repo owner/org, license confirmation (Apache-2.0),
  `open-infra` naming collisions.
