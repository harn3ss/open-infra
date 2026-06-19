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

This repo ships the **scaffold for Phases 0–3 + 6**: installer, app-of-apps,
component manifests, the `Application` schema + a v0 Composition, the CLI, the
reusable Action, and an example app. Components are **wired but not yet validated
on a live cluster** — that's the immediate next step.

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
