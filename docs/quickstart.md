# Quickstart — your first app in ~10 minutes

This gets you from bare Linux box(es) to a running, autoscaling, HTTPS app with
zero raw Kubernetes authored by you.

## 0. Prerequisites

- One or more Linux boxes (a single box is fine for `dev` mode). Commodity
  hardware is the target — a NUC, an old server, a spare desktop.
- A non-root user with `sudo`, and `curl`.
- For **dev mode**: nothing else. DNS is magic (sslip.io) and TLS is self-signed.
- For **prod mode**: a small pool of spare LAN IPs reserved outside DHCP (for
  MetalLB), and optionally a domain on Cloudflare for public access.

## 1. Install the platform

```bash
git clone https://github.com/harn3ss/open-infra
cd open-infra
cp config.example.yaml config.yaml
$EDITOR config.yaml          # at minimum set networking.metallbPool (prod) or leave dev defaults
./install.sh --dry-run       # see exactly what it will do
./install.sh                 # installs k3s + Argo CD + the platform app-of-apps
```

`config.yaml` is **gitignored** — it's the only place your real LAN/domain/secret
references live. Nothing private ever reaches the repo.

Watch the platform converge:

```bash
k3s kubectl -n argocd get applications        # everything should go Healthy/Synced
```

## 1b. Open the console

open-infra ships a **web console** — the AWS-console-style UI for everything you
run (Applications, Functions, Models, Databases, Buckets, Queues, Nodes, GPUs,
Monitoring), with per-resource detail pages and actions (browse/upload objects,
chat with a model, create/delete, publish to a queue). It's served behind Traefik
at `https://console.<lb-ip>.sslip.io`. See [`docs/console.md`](console.md).

For the raw GitOps view, the Argo CD UI is also there:

```bash
k3s kubectl -n argocd get secret argocd-initial-admin-secret \
  -o jsonpath='{.data.password}' | base64 -d; echo
k3s kubectl -n argocd port-forward svc/argocd-server 8080:443
# open https://localhost:8080  (user: admin)
```

## 2. Deploy your first app

In your app repo (or try `examples/hello-web`):

```bash
./cli/open-infra init        # scaffolds infra.yaml (also: init model | init function)
$EDITOR infra.yaml           # set image + port (+ optional db/storage/queues)
./cli/open-infra deploy      # applies the Application; Crossplane fans it out
./cli/open-infra status      # watch it come up
```

A 15-line `infra.yaml` becomes Deployment + Service + Ingress + HPA (+ optional
Postgres/bucket/queue). In dev mode your app is reachable at
`https://<app>.<lb-ip>.sslip.io` with a self-signed cert.

> **GPU / managed inference?** On a GPU node, `open-infra init model` scaffolds a
> `kind: Model` — a GPU-backed, OpenAI-compatible endpoint gated by an API key.
> See [`docs/gpu.md`](gpu.md) for the one-time host setup and how apps consume it.

## 3. Deploy on `git push` (the AWS-like loop)

Add the reusable Action to your app repo (see
[`examples/hello-web/.github/workflows/deploy.yml`](../examples/hello-web/.github/workflows/deploy.yml)),
set the `OPENINFRA_GITOPS_REPO` and `OPENINFRA_TOKEN` secrets, and push. CI builds
the image and commits the rendered `Application` to your GitOps repo; Argo
reconciles it automatically. **You changed the YAML; the infra followed.**

## Troubleshooting

- `LoadBalancer` stuck `<pending>` → `networking.metallbPool` is unset or
  overlaps DHCP. Reserve a range and re-run `./install.sh`.
- App not reachable → check `k3s kubectl describe ingress` and that cert-manager
  issued the cert (`k3s kubectl get certificate -A`).
- DB issues → confirm it's on `local-path` (NVMe), **never** a CIFS/NFS class.
