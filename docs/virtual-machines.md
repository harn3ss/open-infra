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
| `windows-server-2016`, `-2019`, `-2022`, `-2025` | Windows | **clones `<os>-golden`** — build it on the VM Images page (see below). `-2016` has no auto-fetchable eval ISO, so build it with `kind: VmImage` `spec.sourceUrl` (a supplied ISO) or `spec.existingGoldenClaim` (adopt an imported disk — the migration path) |

The catalog lives in two places that must stay in sync: the XRD enum
(`platform/abstraction/vm-xrd.yaml`) and the Composition's `$catalog`
(`platform/abstraction/vm-composition.yaml`). The console mirrors it in
`ui/src/features/vms/vm-shared.ts`.

> **Architecture:** this catalog is **x86 (amd64)**. VMs therefore do not run on **arm64** nodes
> even though KubeVirt itself is arm64-capable — an arm64 host cannot boot an x86 guest. On an
> arm64-only cluster a `VirtualMachine` claim is refused at admission. See
> [architecture-support.md](architecture-support.md).

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

### `firmware` — boot mode (BIOS vs UEFI / Secure Boot)

By default a VM boots **legacy BIOS** (SeaBIOS/MBR) — the catalog's Linux cloud images and the Windows
golden images are MBR. A disk installed under **UEFI** (GPT boot + an EFI system partition, common for
modern AMIs) will *not* boot under BIOS, so set the firmware explicitly:

```yaml
spec:
  firmware:
    mode: uefi          # bios (default) | uefi (OVMF/EFI)
    secureBoot: true    # optional; requires mode: uefi (enables SMM)
    tpm: true           # optional; ephemeral vTPM 2.0 (some Secure Boot / Windows 11 guests need it)
```

**A migrated disk must declare its boot mode.** When `existingRootClaim` is set, `firmware.mode` is
**required** — the platform refuses to guess, because guessing BIOS for a UEFI-installed disk yields an
unbootable VM. Set it to the mode the disk was actually installed under.

- `secureBoot: true` needs `mode: uefi`; it selects the OVMF secure-boot firmware and enables SMM. The
  guest image must itself be Secure-Boot compatible.
- `tpm` is **ephemeral** — not persisted across recreate (persistent vTPM needs the KubeVirt
  `VMPersistentState` feature gate).
- A **fresh** `windows-server-*` clone can only be `bios` (the golden images are MBR). To run a UEFI
  Windows VM, boot a UEFI disk via `existingRootClaim`, or build a UEFI golden via `kind: VmImage`.
- UEFI/Secure Boot require a KubeVirt build with the OVMF (secure-boot) firmware on your nodes — shipped
  by default.

## AWS workload identity (`instanceRole`) — credentials at boot, no static keys

Give a VM an AWS identity the way EC2 does — a role it assumes — so the AWS SDK inside the guest gets
**rotating, temporary credentials with no static keys on disk**:

```yaml
spec:
  os: ubuntu-24.04
  instanceRole: app-role   # a kind: Role (this namespace) the VM assumes
```

The named `kind: Role` must **trust the `vm` principal** (the analog of an AWS role trusting
`ec2.amazonaws.com`), and carries whatever data-plane Policies the workload needs:

```yaml
apiVersion: iam.openinfra.dev/v1
kind: Role
metadata: { name: app-role }
spec:
  trust: ["vm"]            # opt in to being instance-assumable
  policies: [app-s3-read]  # kind: Policy objects granting the access
```

How it works (the ECS/EKS Pod Identity pattern, not EC2 IMDS — kube-ovn's SNAT makes source-IP IMDS
unworkable): the VM gets a dedicated ServiceAccount whose token KubeVirt projects into the guest;
cloud-init points the AWS SDK's **container-credentials provider** at the aws-shim
(`AWS_CONTAINER_CREDENTIALS_FULL_URI` / `_TOKEN_FILE`); the shim verifies the token, reads the role off
the ServiceAccount, and mints temporary credentials. So inside the VM, `aws s3 cp …` (or any SDK) just
works — `aws sts get-caller-identity` returns `assumed-role/<role>/<vm>`. Linux only (Windows is a
follow-on). The role's permissions are enforced at the aws-shim exactly as for any assumed-role session.

## Extra data disks (`dataDisks`) — the EC2 BlockDeviceMapping analog

Attach additional persistent disks at boot, beyond the root — e.g. a dedicated disk for a database:

```yaml
spec:
  diskSize: 20Gi
  dataDisks:
    - { name: pgdata, size: 100Gi }
```

Each is a blank block volume attached as a virtio device in order — `/dev/vdb`, `/dev/vdc`, … (**not**
the AWS `/dev/sdf` or Nitro `/dev/nvme1n1` names; reference them by filesystem UUID/label, or in your
`userData`). Each follows the root's storage policy (`highAvailability` → longhorn-migratable RWX block
so they live-migrate with the VM, else local-path) and is retained across reboots and stop/start. The
guest partitions/formats/mounts them.

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

## Networking: NAT vs direct-LAN (macvtap)

`spec.network` controls how the VM attaches:

- **`masquerade`** (default) — the VM sits behind the pod network (NAT). Reach it
  in-cluster via its `Service`, or from the LAN via `expose: true` (a MetalLB
  LoadBalancer hands it a LAN IP). The pod overlay (`10.42/16`) is **not** routable
  from your LAN, which is why a raw pod IP isn't reachable from a workstation.
- **`macvtap`** — the VM joins the **physical LAN directly** via a macvtap device on
  the parent NIC and pulls a real **DHCP lease** from your router. It's a first-class
  LAN host — no MetalLB, no NAT — reachable on *every* port (e.g. SMB/445, which is
  outside the NodePort range), keeping a pod NIC (eth0) as well for in-cluster access.
- **`bridge`** — *legacy, does not work on this stack.* It tried to bind a macvlan
  sub-interface with KubeVirt's bridge binding, but a macvlan interface cannot be a
  KubeVirt bridge port (the VMI crash-loops `pod link is missing`). Use `macvtap`.

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
> LAN host (every port, a real DHCP IP), use `network: macvtap` instead.

### Enabling direct-LAN (macvtap) mode

Direct-LAN mode needs Multus (a cluster CNI change), so it's opt-in — but it's a
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

`install.sh` layers **Multus** on as the primary CNI (delegating the default network
to Cilium — this requires Cilium's `cni.exclusive=false`, which the installer sets),
installs the macvlan + **macvtap** plugins into the CNI bin dir, deploys the
**macvtap device plugin** (exposing the LAN NIC as `macvtap.network.kubevirt.io/<iface>`),
registers the **macvtap KubeVirt binding**, creates the
`default/openinfra-lan-macvtap` NetworkAttachmentDefinition, and **auto-labels every
node that actually has `interface`** with `openinfra.dev/vm-lan=true` (so direct-LAN
VMs schedule only where they can work — NIC names may differ per node). Then:

```yaml
spec:
  os: ubuntu-24.04
  network: macvtap       # real LAN IP via DHCP, first-class LAN host
```

> **Cilium note.** Cilium ships `cni.exclusive=true`, which evicts any other CNI
> config so Multus is bypassed and NADs never attach. The installer sets
> `cni.exclusive=false`; on a cluster where Cilium was installed before this, re-run
> `install.sh` (it flips the flag and tells you to `rollout restart ds/cilium`).

**Caveats**
- **NIC names may differ per node** (e.g. `eno1` vs `enp4s0`); the device plugin/NAD
  target one parent NIC, so only nodes that have it can host direct-LAN VMs.
  `install.sh` detects this and labels just those nodes `openinfra.dev/vm-lan=true`
  (the VM carries a matching node affinity) — no manual labelling.
- **macvtap limitation**: the *host node* cannot talk to its own macvtap VMs (other
  LAN hosts can) — a kernel macvtap/macvlan property. Announce MetalLB VIPs from a
  different node than the one hosting the VM if the VM must reach them.
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
