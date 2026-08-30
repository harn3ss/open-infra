# Substrate portability

open-infra is developed on **k3s** and has also been deployed and chaos-tested on **RKE2**
(SLES 15 SP7, FIPS — see [security-and-compliance.md](security-and-compliance.md)). Most of
the platform is substrate-neutral: it is ordinary Kubernetes objects, Crossplane compositions,
and Argo CD Applications that run on any conformant cluster. This page tracks the places that
are **not** yet neutral, and how to configure them for another distribution.

> **CPU architecture** (amd64 / arm64) is a separate axis from the substrate/distribution covered
> here — see [architecture-support.md](architecture-support.md).

> **Honest scope.** k3s and RKE2 are **both Rancher-family** distributions and share the same
> `/var/lib/rancher/...` layout, so "runs on k3s and RKE2" is narrower evidence than it looks.
> The roadmap below is ordered to break out of that family: **vanilla kubeadm first** (a
> different layout entirely), **Talos second** (immutable, no host paths — forces the
> abstraction properly), then OpenShift/RHCOS, then managed clouds. Portability here means
> "runs correctly," not any certification claim.

## The API-server audit-log path

The one component with a hard, distribution-specific host dependency is the **API-server audit
log**. It is the authoritative "who did what" record and it is consumed two ways:

- **Audit off-siting** ([`audit-offsite.md`](audit-offsite.md)) — a CronJob reads the log file
  from the control-plane node and ships it to a WORM store as a hash chain.
- **The console CloudTrail view** — promtail tails the same file into Loki.

Both read the log from a **host directory** (a `hostPath`), because the file lives on the
control-plane node's disk (`0600`, root-owned), not in the cluster. That directory differs by
distribution:

| Distribution | Audit-log directory |
|---|---|
| **k3s** (default) | `/var/lib/rancher/k3s/server/logs` |
| **RKE2** | `/var/lib/rancher/rke2/server/logs` |
| **kubeadm** | the directory of your `--audit-log-path` (e.g. `/var/log/kubernetes/audit`) |
| **Talos** | the directory your audit policy writes to |

On kubeadm/Talos the API-server audit log is **not enabled by default** — you must set
`--audit-log-path` and `--audit-policy-file` on the API server yourself (open-infra ships a
policy at [`platform/security/apiserver/audit-policy.yaml`](../platform/security/apiserver/audit-policy.yaml)
you can point it at). k3s/RKE2 wire both from the bundled config.

### How it's abstracted

The container side is already substrate-agnostic: the log is mounted at a **fixed internal
path, `/audit`**, so nothing inside the pods hard-codes a distribution. The off-siting shipper
reads `AUDIT_LOG_PATH` (default `/audit/audit.log`) and promtail reads `/audit/audit.log`.
**Only the host directory is distribution-specific**, and it lives in exactly three places:

1. `cluster.auditLogDir` in `config.yaml` — the single declared value. `install.sh` probes the
   control-plane node against it and **warns loudly** if the audit log isn't there (so a wrong
   path fails at install time instead of producing a silently empty audit trail).
2. the `hostPath` in [`platform/observability/promtail.yaml`](../platform/observability/promtail.yaml) (flagged `SUBSTRATE-SPECIFIC`)
3. the `hostPath` in [`platform/security/audit-offsite.yaml`](../platform/security/audit-offsite.yaml) (flagged `SUBSTRATE-SPECIFIC`)

These manifests are synced from git verbatim (not templated), so setting `cluster.auditLogDir`
does not rewrite them for you — change the two flagged `hostPath` lines to the same directory
when you move off k3s. Making these a single templated value is a tracked follow-up.

## Other substrate touch-points

- **`node-role.kubernetes.io/control-plane` selector** — the off-siting shipper pins to the
  control-plane node with this label to reach the log file. kubeadm and RKE2 set it; k3s sets it
  too. Talos uses the same label. Verify it is present on your control-plane nodes.
- **Longhorn host prerequisites** — Longhorn needs `open-iscsi` and a writable `/var/lib` on
  each node; on immutable hosts (Talos, RHCOS) this is a machine-config concern, not an
  in-cluster one.
- **PodSecurity `privileged` exemption for `monitoring`** — under cluster-wide restricted PSA,
  the ship job needs it (root + hostPath to read the `0600` file). See the restricted-PSA
  overlay and [security-and-compliance.md](security-and-compliance.md).

## Repurposing a node between clusters (Cilium/multus residue)

Moving a node from one open-infra cluster to another — the fleet-rebuild / chaos-node-borrow
pattern — leaves **stale CNI state that breaks pod networking on the new cluster** if you only
run `k3s-agent-uninstall`. Two kinds of residue (open-infra's CNI is Cilium + multus — this does
**not** apply to a Canal/RKE2 substrate):

1. A stale `/etc/cni/net.d/00-multus.conf` → the multus shim keeps trying the old delegate and pods
   fail with sandbox-creation timeouts.
2. Stale `OLD_CILIUM_*` iptables chains from the previous Cilium install → **no pod egress** (seen
   concretely as CDI unable to pull an install ISO).

`k3s-agent-uninstall` cleans **neither**, and restarting the new cluster's Cilium pod does **not**
flush the old iptables chains.

**Sanctioned procedure (deterministic): reboot between clusters.**

```sh
# on the node being moved, after draining/removing it from the OLD cluster:
/usr/local/bin/k3s-agent-uninstall.sh      # (or k3s-uninstall.sh for a server)
sudo reboot                                 # clears /etc/cni/net.d/* AND the OLD_CILIUM_* chains
# only AFTER it comes back up: join the NEW cluster (curl … K3S_URL=… agent)
```

The reboot is the one step proven to leave a clean CNI slate. An explicit cleanup — deleting
`/etc/cni/net.d/*` and flushing/deleting the `OLD_CILIUM_*` chains — is a plausible reboot-free
substitute but is **not yet proven** to fully replace the reboot; prefer the reboot until it is.

Reference this from any node-move step. Verified on a real move: during the #45 hybrid-cluster run
`chaos-node-1` was moved out of the main cluster and exhibited exactly this residue (multus timeouts
+ no egress); a reboot restored pod egress and multus health, after which it joined cleanly.

## Roadmap

1. **vanilla kubeadm** — first real break out of the Rancher family.
2. **Talos** — immutable, no arbitrary host paths; forces the audit-source abstraction to its
   proper conclusion (a templated value, not a per-distro `hostPath` edit).
3. **OpenShift / RHCOS** — SCC work is scoped separately.
4. **managed control planes** (EKS/GKE/AKS) — least valuable; the API-server audit log is not a
   readable host file there, so the off-siting shipper would source it from the provider's audit
   pipeline instead.
