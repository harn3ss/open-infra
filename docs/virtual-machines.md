# Virtual Machines (`kind: VirtualMachine`)

open-infra's **EC2**: a real virtual machine on the cluster, backed by
[KubeVirt](https://kubevirt.io) (VMs on Kubernetes) and
[CDI](https://github.com/kubevirt/containerized-data-importer) (disk imaging).
Pick an OS, get a persistent disk, first-boot login, and native access (SSH for
Linux, RDP for Windows).

## Requirements

- **Hardware virtualization** (`/dev/kvm`) on the nodes — Intel VT-x or AMD-V.
  Check: `grep -oE 'vmx|svm' /proc/cpuinfo` on each node should print something.
- `components.virtualization: true` in `config.yaml` (default). `install.sh`
  installs KubeVirt + CDI from the upstream release manifests.

## Quick start

```yaml
# infra.yaml
apiVersion: openinfra.dev/v1
kind: VirtualMachine
metadata:
  name: dev-box
spec:
  os: ubuntu-24.04          # see the catalog below
  cpu: 2
  memory: 4Gi
  diskSize: 30Gi
  sshKey: "ssh-ed25519 AAAA…"   # Linux login (omit -> generated password)
  expose: false             # true -> SSH/RDP on a LAN IP (MetalLB)
```

```sh
./cli/open-infra deploy        # or: create it from the console's "New VM"
```

The platform imports the OS image to a persistent disk (CDI), boots it on
KubeVirt, and creates a connection `Secret` (`<name>-vm`) with the login. The
console's **Virtual Machines** page shows status/IP, the credentials, Start/Stop,
and how to connect.

## The OS catalog

| `os` | Family | Source |
|---|---|---|
| `ubuntu-24.04`, `ubuntu-22.04` | Linux | cloud image (containerdisk), imported by CDI |
| `fedora-40` | Linux | cloud image |
| `debian-12` | Linux | cloud image |
| `centos-stream-9` | Linux | cloud image |
| `windows-server-2019`, `-2022`, `-2025` | Windows | **clones `<os>-golden`** — build it on the VM Images page (see below) |

The catalog lives in two places that must stay in sync: the XRD enum
(`platform/abstraction/vm-xrd.yaml`) and the Composition's `$catalog`
(`platform/abstraction/vm-composition.yaml`). The console mirrors it in
`ui/src/features/vms/vm-shared.ts`.

## High availability & live migration

By default a VM's root disk is `local-path` (local NVMe) — fast, but **pinned to one
node**: if that node dies the VM can't restart elsewhere. Set `highAvailability: true`
to make the VM **node-independent**:

```yaml
spec:
  os: windows-server-2019
  highAvailability: true      # root disk on Longhorn (migratable RWX block) + LiveMigrate
  cpuModel: Broadwell-noTSX   # a CPU model ALL nodes support (see below)
```

What it does:
- Root disk is provisioned on **Longhorn** as a **migratable RWX block** volume (the
  `longhorn-migratable` StorageClass, replicated across nodes) instead of `local-path`.
- The VM gets `evictionStrategy: LiveMigrate`, so:
  - **Node dies** → the VM reschedules onto another node and boots from a Longhorn replica.
  - **Node drained** (planned maintenance) → the running VM **live-migrates** off it with
    zero downtime (`kubectl drain`, or a `VirtualMachineInstanceMigration`).

### `cpuModel` — required for portability on mixed-CPU clusters

Live migration and node-loss reschedule both need a target node whose CPU can run the
guest. The default (`host-model`) pins the VM to its source node's exact CPU — fine on a
uniform cluster, but on a cluster with **different CPUs per node** it blocks all movement.
Set `cpuModel` to the **newest model every node supports**. Find it with:

```sh
# intersection of cpu-model.node.kubevirt.io/* labels across your nodes
kubectl get nodes -o json | jq -r '...'   # newest common model, e.g. Broadwell-noTSX
```

HA VMs default to `Nehalem` (a universally-safe baseline) if `cpuModel` is unset.
Changing a running VM's CPU model requires a reboot, and Windows may re-detect hardware
(possible reactivation) — back up first.

### `existingRootClaim` — adopt a pre-existing disk (migration / restore)

Boot from an existing PVC instead of cloning a fresh disk from the image:

```yaml
spec: { existingRootClaim: my-restored-disk }   # no root DataVolume is provisioned
```

Used to migrate a VM onto a disk cloned to a new storage class (e.g. `local-path` →
Longhorn) without reinstalling. To migrate an existing VM's disk: clone it to a
`longhorn-migratable` block PVC, then set `highAvailability: true` + `existingRootClaim`
+ `cpuModel`. (When adopting a claim-managed VM's disk, orphan the old DataVolume first so
it isn't garbage-collected, and apply the volume swap + template removal atomically —
KubeVirt's webhook rejects a dataVolumeTemplate that's no longer referenced.)

## Access

- **Linux** — SSH as `openinfra`. Your `sshKey` is installed via cloud-init; a
  generated password is also set (revealable on the VM page) as a fallback.
- **Windows** — RDP as `Administrator` with a generated password (revealable on
  the VM page). Connect with `mstsc /v:<host>:3389`.
- **`expose: true`** publishes a `LoadBalancer` (MetalLB) so workstations on the
  LAN can reach SSH (22) / RDP (3389) directly. Otherwise use
  `kubectl port-forward svc/<name> <port>:<port>`.

Power: the console's **Start/Stop** flips `spec.running`, which the Composition
maps to KubeVirt `runStrategy` (`Always`/`Halted`). The disk is retained while
stopped.

Delete: deleting a VM through the console (or `kubectl delete virtualmachines.openinfra.dev
<name>`) removes the whole stack — the KubeVirt VM, the disk (DataVolume/PVC), and any
**LAN `LoadBalancer`**, so the pool IP is released. ⚠️ The kind name `VirtualMachine` exists
in **both** `openinfra.dev` (the claim) and `kubevirt.io` (the composed VM), so a bare
`kubectl delete vm <name>` is ambiguous and may hit the kubevirt.io VM — which Crossplane
then recreates (and the LB is *not* released). Always delete via the console or the
fully-qualified `virtualmachines.openinfra.dev`.

> Web (in-browser) console is intentionally **not** provided — access is native
> SSH / RDP, so there is no extra in-cluster console dependency to run.

## Networking: NAT vs direct-LAN (bridge)

`spec.network` controls how the VM attaches:

- **`masquerade`** (default) — the VM sits behind the pod network (NAT). Reach it
  in-cluster via its `Service`, or from the LAN via `expose: true` (a MetalLB
  LoadBalancer hands it a LAN IP). The pod overlay (`10.42/16`) is **not** routable
  from your LAN, which is why a raw pod IP isn't reachable from a workstation.
- **`bridge`** — the VM joins the **physical LAN directly** (Multus + macvlan) and
  pulls a real **DHCP lease** from your router. It's a first-class LAN host — no
  MetalLB, no NAT.

### Opening extra ports (masquerade)

A masquerade VM is reachable on its access port (SSH 22 / RDP 3389) plus whatever
its **security groups** allow — exposure follows the firewall, so there's a single
place to manage access (see [security-groups.md](security-groups.md)). To expose a
web server on 80, add an inbound `HTTP` rule to a `SecurityGroup` attached to the VM;
the platform publishes the matching LAN listener automatically (same MetalLB LAN IP
as SSH/RDP, no bridge needed). In the console this is the VM's **Network** tab: the
**Reachable ports** list is read-only and follows the rules, and you attach/edit
groups under **Security groups** — there's no separate "publish a port" control.

> Under the hood the LoadBalancer's listeners live in `spec.ports`; the console keeps
> that list in sync with the attached security groups (each specific inbound port
> becomes a listener). The guest must actually be listening on the port. For a *full*
> LAN host (every port, a real DHCP IP), use `network: bridge` instead.

### Enabling bridge mode

Bridge mode needs Multus (a cluster CNI change), so it's opt-in — but it's a
config flag, not a manual step. In `config.yaml`:

```yaml
networking:
  vmLan:
    enabled: true
    interface: eno1     # your LAN NIC
```

then re-run the installer:

```sh
./install.sh            # idempotent
```

`install.sh` installs Multus + the macvlan plugin (k3s paths), creates the
`default/openinfra-lan` NetworkAttachmentDefinition (macvlan, no IPAM → guest
DHCP), and **auto-labels every node that actually has `interface`** with
`openinfra.dev/vm-lan=true` (so bridged VMs schedule only where they can work —
NIC names may differ per node). Once a node is labelled, the console's New VM
dialog enables "Bridged to LAN" on its own. Then:

```yaml
spec:
  os: ubuntu-24.04
  network: bridge        # real LAN IP via DHCP
```

**Caveats**
- **NIC names may differ per node** (e.g. `eno1` vs `enp4s0`); the NAD has one
  `master`, so only nodes that have that NIC can host bridged VMs. `install.sh`
  detects this and labels just those nodes `openinfra.dev/vm-lan=true` (the VM
  carries a matching node affinity) — no manual labelling.
- **macvlan limitation**: the *host node* cannot talk to its own bridged VMs
  (other LAN hosts can) — a kernel macvlan property.
- The VM still keeps a pod NIC (eth0) for in-cluster/Service access; the LAN lease
  lands on eth1.

## Windows: build the golden image (in the console)

Windows has no redistributable cloud image, so you build a reusable **golden
image** once per version, then every `os: windows-server-*` VM clones it (fast).
It's a click — no scripts.

### Licensing (read this)

- **Evaluation editions are free and legal for testing/non-production only.**
  Windows Server eval = 180 days.
  Download is handled for you from the [Microsoft Evaluation Center](https://www.microsoft.com/evalcenter).
- **Production Windows VDI/desktops require Microsoft licensing** (VDA / Windows
  Enterprise E3+ / RDS CALs). open-infra does not and cannot provide that — it is
  not open source. Linux VMs have no such constraint.

### Build it

Console → **Virtual Machines → VM Images** → pick a version (Server 2019 / 2022 /
2025) → **Build**. Or declaratively:

```yaml
apiVersion: openinfra.dev/v1
kind: VmImage
metadata: { name: windows-server-2022, namespace: openinfra-images }
spec:
  os: windows-server-2022       # sourceUrl: <override> if the catalog fwlink ever moves
```

The `VmImage` Composition (`platform/abstraction/vmimage-composition.yaml`):

1. CDI imports the official eval ISO (a verified Microsoft `fwlink`) + virtio-win.
2. A **sysprep ConfigMap** carries the unattended answer file (per-version edition
   + virtio driver path; FirstLogonCommands install virtio guest tools +
   **cloudbase-init** + RDP, then `sysprep /generalize /shutdown`).
3. An **installer VM** (`runStrategy: Once`) writes the golden disk and powers off
   after sysprep. The disk survives as `<os>-golden` in `openinfra-images`.

The VM Images page shows progress (Building → Ready); when Ready, that version
becomes selectable in **New VM** (it's greyed out until then). A build downloads
~5 GB and runs an unattended install — 20–40 minutes.

Goldens are stored on **Longhorn** (replicated), so provisioning a Windows VM —
which clones `<os>-golden` — doesn't depend on any single node being up. To move an
already-built golden to a different storage class without rebuilding, clone it to a
new PVC and set `existingGoldenClaim: <that-pvc>` on the `VmImage` — it adopts the
clone and skips the ISO/installer steps.

## Desktops & workspaces

open-infra's answer to **AWS WorkSpaces** is a VM, not a separate abstraction:

- **Windows desktop** — `os: windows-server-2022` (or 2019/2025) is the *Desktop Experience* edition.
  Connect with `mstsc /v:<host>:3389` as `Administrator` using the generated
  password shown on the VM's page. (Per the licensing note above, eval is
  non-production only.)
- **Linux desktop** — start from any Linux `os` and install a desktop + RDP on
  first boot, e.g. add to `infra.yaml`:
  ```yaml
  # (cloud-init runcmd — Ubuntu example)
  # apt-get install -y xubuntu-desktop xrdp && systemctl enable --now xrdp
  ```
  then RDP in (or just use SSH/X-forwarding).
- **Per-user** — give each person their own VM (one claim each); the disk
  persists across stop/start. Expose on the LAN (`expose: true`) or port-forward.

Access is **native** (RDP/SSH), so there's no in-browser desktop gateway to run.

## Troubleshooting

- **Disk stuck importing** — watch CDI: `kubectl get datavolume -n <ns> <name>-root -w`.
  First import of an OS pulls the cloud image (hundreds of MB); later VMs of the
  same OS reuse the CDI image cache.
- **VM Pending, never Running** — confirm `/dev/kvm` on the node and that
  KubeVirt is `Deployed`: `kubectl get kubevirt -n kubevirt`.
- **No IP shown** — the guest agent reports the IP; Linux installs
  `qemu-guest-agent` via cloud-init on first boot (give it a minute).
- **Windows VM won't boot** — its `<os>-golden` image must be built first (VM
  Images page → Build, wait for Ready).
