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
| `windows` | Windows | **clones a golden image you build once** (see below) |

The catalog lives in two places that must stay in sync: the XRD enum
(`platform/abstraction/vm-xrd.yaml`) and the Composition's `$catalog`
(`platform/abstraction/vm-composition.yaml`). The console mirrors it in
`ui/src/features/vms/vm-shared.ts`.

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

## Windows: build the golden image once

Windows has no redistributable cloud image, so you build a reusable **golden
image** once from a Microsoft **evaluation ISO**, then every `os: windows` VM
clones it (fast). This is a one-time, operator-run step.

### Licensing (read this)

- **Evaluation editions are free and legal for testing/non-production only.**
  Windows Server eval = 180 days; Windows 10/11 Enterprise eval = 90 days.
  Download from the [Microsoft Evaluation Center](https://www.microsoft.com/evalcenter).
- **Production Windows VDI/desktops require Microsoft licensing** (VDA / Windows
  Enterprise E3+ / RDS CALs). open-infra does not and cannot provide that — it is
  not open source. Linux VMs have no such constraint.

### Build it

```sh
# 1. Get an eval ISO from the Microsoft Evaluation Center (e.g. Windows Server
#    2022) and note its path or a URL the cluster can reach.
# 2. Run the builder (needs genisoimage/mkisofs locally):
scripts/build-windows-image.sh \
  --windows-iso https://software-static.download.../SERVER_EVAL_x64.iso \
  --name windows-golden
```

The script (see `scripts/build-windows-image.sh`):

1. Creates the `openinfra-images` namespace and a blank target `DataVolume`.
2. Imports the Windows ISO and the latest **virtio-win** ISO via CDI.
3. Builds a small `autounattend` ISO from `scripts/windows/autounattend.xml`
   (unattended install + virtio storage driver + `SetupComplete.cmd`).
4. Boots an installer VM that runs Windows Setup unattended; `SetupComplete.cmd`
   installs **cloudbase-init** (consumes the per-VM cloud-init: sets the
   `Administrator` password + enables RDP), installs the **virtio guest tools**
   and **qemu-guest-agent**, then runs `sysprep /generalize /oobe /shutdown`.
5. On shutdown, the target disk is your golden image — kept as the
   `windows-golden` PVC in `openinfra-images`. Delete the installer VM.

After that, `spec.os: windows` works like any other VM (the Composition clones
`windows-golden`).

> The answer file targets **Windows Server 2022**. Other versions
> (Windows 11, Server 2025) may need edition-index or driver-path tweaks in
> `autounattend.xml`.

## Desktops & workspaces

open-infra's answer to **AWS WorkSpaces** is a VM, not a separate abstraction:

- **Windows desktop** — `os: windows` is Server 2022 *Desktop Experience*.
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
- **Windows VM won't boot** — the `windows-golden` PVC must exist in
  `openinfra-images`. Build it first (above).
