# Air-gapping

open-infra can run **air-gapped** — front-load everything the cluster needs while on-net, then sever
public-internet egress and keep operating. It is **opt-in and off by default**: a fresh install has
full internet access and no air-gap machinery. You enter the air-gapped posture only by an explicit,
reversible election, in two deliberate phases.

> **The order matters.** Front-load first, cut the internet last. If you cut egress before the mirror
> holds your images and the nodes point at it, image pulls will fail.

## The two phases

| Phase | Toggle | What it does | Reversible |
|---|---|---|---|
| 1. Front-load | `components.airgap: true` | Deploys an in-cluster registry mirror + an image-prefetch Job. Changes no egress — safe on-net. | yes |
| 2. Cut | `airgap.denyPublicEgress: true` | Applies a cluster-wide CNI policy (Cilium *or* Calico/Canal) denying public-internet egress (LAN + cluster preserved). | yes |

Both live in `config.yaml`; `install.sh` wires them into the GitOps app-of-apps.

## Phase 1 — front-load (while the internet is up)

1. **Enable the component** and re-run install:
   ```yaml
   components:
     airgap: true            # deploys the registry mirror + prefetch into namespace openinfra-airgap
   ```
2. **Populate the mirror.** The prefetch Job derives the image set from *what is actually running* on
   the cluster (every container/init/ephemeral image across all pods), unions in anything you list in
   the `airgap-extra-images` ConfigMap (on-demand engines, workloads not currently scheduled, next
   release's images), and copies each into the in-cluster registry with `crane`, preserving the repo
   path. Run it (re-runnable; it skips layers already present):
   ```bash
   kubectl -n openinfra-airgap create job airgap-prefetch-now --from=job/airgap-prefetch   # or re-apply the Job
   kubectl -n openinfra-airgap logs -f job/airgap-prefetch-now
   ```
   The mirror is a durable, PVC-backed OCI registry (`airgap-registry.openinfra-airgap.svc:5000`).
3. **Point the nodes' container runtime at the mirror.** This is **automated**: enabling the component
   deploys the `airgap-node-registries` DaemonSet (kube-system), which writes
   `/etc/rancher/k3s/registries.yaml` on every node — mirroring the public registries to the in-cluster
   registry at `127.0.0.1:30500` (the mirror's NodePort; the host's containerd is outside the pod
   network and can't use cluster DNS) — and restarts the runtime **only when the file actually changes**
   (idempotent, one node at a time, never in a loop). Manifests keep their original image references;
   containerd redirects the pull, falling back to upstream on a miss while still on-net. Edit the
   registry set in the `airgap-node-registries` ConfigMap. (The DaemonSet detects the runtime and writes
   the correct path — `/etc/rancher/k3s/registries.yaml` for k3s, `/etc/rancher/rke2/registries.yaml`
   for RKE2 — and restarts the matching unit; a node running neither logs a warning and you configure
   its runtime yourself.)

## Phase 2 — cut public egress (the election)

Once the mirror is populated and the nodes point at it:
```yaml
airgap:
  denyPublicEgress: true     # apply the cluster-wide public-egress cutoff
```
Re-run `install.sh` (or let GitOps sync). This applies a **CNI-specific** cluster-wide policy that
**denies egress to the public internet** and **preserves** everything the cluster legitimately needs:

- pod-to-pod, node, and `kube-apiserver` traffic;
- DNS;
- the **private LAN and cluster ranges** — RFC1918 (`10/8`, `172.16/12`, `192.168/16`), CGNAT
  (`100.64/10`), and link-local (`169.254/16`). On-prem services on your LAN stay reachable; only
  public (non-private) destinations are severed.

**Requires a policy-capable CNI**, and `install.sh` picks the variant that matches yours:

- **Cilium** — a `CiliumClusterwideNetworkPolicy` `egressDeny` on `0.0.0.0/0 except <private ranges>`.
  Additive: it forbids the public ranges without turning pods into default-deny-egress.
- **Calico / Canal** (e.g. the FIPS-rebuilt RKE2 substrate) — a `GlobalNetworkPolicy` that allows the
  private/cluster ranges and denies everything else (the same public cutoff; Calico is authoritative
  for the direction it selects, so it is expressed as allow-private-then-deny-all).

If the cluster runs neither (no `cilium.io` / `projectcalico.org` policy CRD), install **skips** the
cutoff (front-load only) and logs it rather than hard-failing — add the egress denial in your CNI.
Reverse it any time by setting `denyPublicEgress: false` and re-syncing (or deleting the policy).

## ⚠️ Do not cut yourself off

If you administer the cluster **from outside its LAN over the public internet** — a VPN endpoint, an
SSH bastion, or a tunnel whose path leaves the private ranges — electing the cutoff can sever your own
control channel, because that path is *public* from the cluster's point of view. Before setting
`denyPublicEgress: true`:

- confirm your management path stays within the preserved ranges (same LAN / RFC1918 / a private-routed
  VPN), **or** add its egress explicitly to the policy's `except` set first;
- have out-of-band console access to the nodes to reverse it if needed.

Inbound access (e.g. a Cloudflare Tunnel or ingress) is a separate concern; this policy governs
**egress** only. But note that outbound-tunnel exposure (the tunnel dialing out to a public relay) *is*
egress and will be cut — expected for an air-gapped cluster.

## What this is (and isn't) yet

- **Is:** an opt-in, reversible, two-phase air-gap — an in-cluster registry mirror, running-set image
  prefetch, automated per-node runtime mirror config, and a surgical public-egress cutoff that keeps
  LAN/cluster/DNS intact.
- **Self-service:** enabling `components.airgap` deploys everything, including the node `registries.yaml`
  DaemonSet — no hand-run per-node step. Electing the cutoff is a single config flag.
- **v1 scope:** the mirror is a single-replica, PVC-backed registry over plain HTTP on the cluster
  network. Charts/Helm repos and OS package mirrors are out of scope here — front-load those with your
  own mirror if your workloads pull them at runtime. TLS on the mirror and a full offline drill are
  planned follow-ups.
