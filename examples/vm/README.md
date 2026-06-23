# vm — a virtual machine (open-infra's "EC2")

A one-file example of `kind: VirtualMachine`: the platform imports an OS image to a
persistent disk (CDI), boots it on **KubeVirt**, injects your login, and gives you a
web **VNC** console plus SSH (Linux) / RDP (Windows).

## Deploy

```bash
cd examples/vm
open-infra deploy          # imports the image + boots the VM
open-infra status          # watch it under "Virtual Machines"
```

## What you get

- A curated OS (`ubuntu-24.04` · `ubuntu-22.04` · `fedora-40` · `debian-12` ·
  `centos-stream-9` · `windows-server-2019/-2022/-2025`) on a persistent disk.
- Login via your `sshKey`, or a generated password revealable in the console.
- `expose: true` → a real LAN IP (MetalLB): SSH (22) for Linux, RDP (3389) for
  Windows. Otherwise use the web VNC console or `kubectl port-forward`.
- Start/Stop from the console (flips `spec.running`; the disk is retained).

Edit [`infra.yaml`](infra.yaml) — set the OS, CPU/memory/disk, and your SSH key.
Windows images must be built first (console → **VM Images**, or `kind: VmImage`).
Full guide: [`docs/virtual-machines.md`](../../docs/virtual-machines.md).
