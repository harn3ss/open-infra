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
| 2. Cut | `airgap.denyPublicEgress: true` | Applies a cluster-wide Cilium policy denying public-internet egress (LAN + cluster preserved). | yes |

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
3. **Point the nodes' container runtime at the mirror** (operator step, like other node prerequisites).
   On k3s/RKE2, add a registry mirror to `/etc/rancher/k3s/registries.yaml` on **every** node so pulls
   of the public registries resolve to the in-cluster mirror:
   ```yaml
   mirrors:
     docker.io:      { endpoint: ["http://airgap-registry.openinfra-airgap.svc.cluster.local:5000"] }
     ghcr.io:        { endpoint: ["http://airgap-registry.openinfra-airgap.svc.cluster.local:5000"] }
     registry.k8s.io:{ endpoint: ["http://airgap-registry.openinfra-airgap.svc.cluster.local:5000"] }
     gcr.io:         { endpoint: ["http://airgap-registry.openinfra-airgap.svc.cluster.local:5000"] }
     quay.io:        { endpoint: ["http://airgap-registry.openinfra-airgap.svc.cluster.local:5000"] }
   ```
   then restart the agent (`systemctl restart k3s` / `k3s-agent`). The manifests keep their original
   image references; containerd redirects the pull. (This is deliberately a node-config step; a
   DaemonSet that writes `registries.yaml` and restarts the runtime is a candidate future automation.)

## Phase 2 — cut public egress (the election)

Once the mirror is populated and the nodes point at it:
```yaml
airgap:
  denyPublicEgress: true     # apply the cluster-wide public-egress cutoff
```
Re-run `install.sh` (or let GitOps sync). This applies a `CiliumClusterwideNetworkPolicy` that **denies
egress to the public internet** and **preserves** everything the cluster legitimately needs:

- pod-to-pod, node, and `kube-apiserver` traffic (Cilium `cluster`/`host`/`remote-node` entities);
- DNS;
- the **private LAN and cluster ranges** — RFC1918 (`10/8`, `172.16/12`, `192.168/16`), CGNAT
  (`100.64/10`), and link-local (`169.254/16`). On-prem services on your LAN stay reachable; only
  public (non-private) destinations are severed.

It is implemented as a Cilium `egressDeny` on `0.0.0.0/0 except <private ranges>`, so it is *additive*:
it does not turn every pod into default-deny-egress, it only forbids the public ranges. Reverse it by
setting `denyPublicEgress: false` and re-syncing (or `kubectl delete ciliumclusterwidenetworkpolicy
airgap-deny-public-egress`).

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

- **Is:** an opt-in, reversible, two-phase air-gap — an in-cluster registry mirror + running-set image
  prefetch, and a surgical public-egress cutoff that keeps LAN/cluster/DNS intact.
- **Operator steps:** pointing containerd at the mirror (`registries.yaml`) is a per-node step, like
  other node prerequisites (open-iscsi, the GPU toolkit).
- **v1 scope:** the mirror is a single-replica, PVC-backed registry over plain HTTP inside the cluster
  (fronted only on the cluster network). Charts/Helm repos and OS package mirrors are out of scope here
  — front-load those with your own mirror if your workloads pull them at runtime. Tracking: issue #72.
