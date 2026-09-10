# Auto Scaling Groups

`kind: AutoScalingGroup` runs a **self-healing group of identical VMs** kept at a desired capacity —
the platform's equivalent of an EC2 Auto Scaling Group. Give it a `launchTemplate` (the recipe for one
machine, the same shape as `kind: VirtualMachine`) and a capacity, and the platform keeps that many
members running, replaces unhealthy ones, and rolls a template change through the fleet.

It compiles to a KubeVirt `VirtualMachinePool`: each member is a real VM with its **own persistent root
disk**.

## Quick start

```yaml
apiVersion: openinfra.dev/v1
kind: AutoScalingGroup
metadata:
  name: web-fleet
spec:
  desiredCapacity: 3
  maxSize: 6
  launchTemplate:
    os: ubuntu-24.04
    cpu: 2
    memory: 4Gi
    diskSize: 20Gi
    sshKey: "ssh-ed25519 AAAA..."
    securityGroups: [web-sg]
```

## Capacity

- **`desiredCapacity`** — how many members to run now. Defaults to `minSize`.
- **`minSize`** (default 1) — the floor `desiredCapacity` is held at.
- **`maxSize`** — the ceiling. Omit it and `desiredCapacity` is honored as-is; set it and
  `desiredCapacity` is capped down to it. (In v1, scaling is manual — edit `desiredCapacity`. Metric
  target-tracking autoscaling is a planned addition.)

## Launch template

`launchTemplate` is the per-member machine, identical in shape to `kind: VirtualMachine`: `os` (from the
same curated catalog), `cpu`, `memory`, `diskSize`, `sshKey`, `userData`, `network`
(`masquerade`/`macvtap`), `securityGroups`, `subnet`, `highAvailability`, `cpuModel`. Every member is
provisioned from this template with its own disk.

## Health and rolling updates

- **`healthCheck.replaceUnhealthy`** (default true) — replace a member whose VM stops being ready (the
  EC2 status-check analog). Tune with `startUpFailureThreshold` / `minFailingDuration`.
- **`instanceRefresh.strategy`** — how a `launchTemplate` change reaches existing members:
  `proactive` (default: force a bounded rolling restart) or `opportunistic` (apply on each member's
  next natural restart). **`instanceRefresh.maxUnavailable`** (default `"1"`) bounds how many members
  restart at once — an integer or a percentage (`"25%"`).

## Honest limits

- **Single region.** No Availability-Zone spread; place members in one `kind: Subnet` (kube-ovn) or by
  node affinity. No spot, no mixed instance types — one machine shape per group.
- **Per-member storage cost.** Each member gets its own root disk. A **Windows** fleet clones the
  ~100 GiB golden image *per member*, and HA members replicate on Longhorn — so fleet size is bounded
  by storage. Default (non-HA) roots on local-path keep this cheapest.
- **Windows fleets share one Administrator password** and one OOBE answer file (a single definition
  can't mint a unique credential per member); hostnames are still unique. Use Linux fleets, or a
  domain-join flow, where per-member credentials matter.
- **Instance refresh is a bounded rolling restart**, not AWS's staged/canary refresh with automatic
  rollback. A `cpu`/`memory` change reboots members in place; an `os` change replaces their disks.
- **Health check is status-based** (member readiness), not an app-level (ELB-type) probe.
