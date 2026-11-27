# GPU instances: operator guide

*This is an operator guide: it speaks of nodes, KubeVirt and Kubernetes resources, which customers never
see. What a customer gets is in [Virtual Machines: GPU instances](virtual-machines.md#gpu-instances-g4dnxlarge-g5xlarge).*

A GPU instance (EC2 `g4dn.xlarge` or `g5.xlarge`: 4 vCPUs, 16 GiB, one GPU) is given a whole GPU card by PCI
passthrough, and runs the card's own driver in its guest. A card set aside for GPU instances is not available
to containers (`kind: Model`, Functions, training jobs): choose per card. Each card runs one instance at a time.

Each GPU instance family is its own pool of one card model: `g4dn` and `g5`. An instance only ever starts on
a card of its type's family, so `DescribeInstanceTypes` can name each type's GPU truthfully and an instance's
guest sees the same model across stop and start. Two different card models go in two families; two cards of
one model can share a family.

## Requirements

- The IOMMU on in the node's firmware (Intel VT-d or AMD-Vi), with hardware virtualization.
- The card alone in its IOMMU group, apart from its own functions (its display and audio). The host script
  refuses a card that shares its group with anything else.
- `components.virtualization` on.

## 1. Prepare the card's node

Drain the node if it runs anything you mind restarting, then on the node, as root:

```bash
lspci -nn | grep -i -E 'vga|3d'          # the card's PCI address and [vendor:device]
sudo scripts/gpu-instance-host.sh 0000:01:00.0          # boot configuration; reboot to apply
sudo scripts/gpu-instance-host.sh 0000:01:00.0 --now    # or also move the card over now, no reboot
```

The script binds the card's IOMMU group to `vfio-pci` at boot (ahead of the GPU and audio drivers), puts
`vfio-pci` in the initramfs, turns the IOMMU on in pass-through mode and leaves the boot framebuffer
unclaimed (`initcall_blacklist=sysfb_init`), so the node's own screen goes dark after boot. It masks
`nvidia-persistenced`. `--now` unloads the card's drivers and rebinds it without a reboot, when nothing on
the node holds the card open. A node whose only display device is the card keeps no desktop: it boots to
`multi-user.target`, and `--now` stops its display manager first. On a node with no other NVIDIA display
device, NVIDIA's udev rule that loads the driver's modules whenever the driver registers is overridden in
`/etc/udev/rules.d` without those lines, since with no card to drive the driver would unload and be loaded
again several times a second.

**A node that does not boot with the card bound early.** Some nodes hang early in boot when the card is
bound to `vfio-pci` from the initramfs: one whose only display device is the card, among them. There the
boot shows nothing and the node never reaches the network. Bind the card late in boot instead:

```bash
sudo scripts/gpu-instance-host.sh 0000:01:00.0 --late          # reboot to apply
sudo scripts/gpu-instance-host.sh 0000:01:00.0 --late --now    # or also move it over now
```

The card's own driver initializes it as usual. Then `openinfra-gpu-instance.service`, ordered before the
node's Kubernetes agent, unloads that driver and hands the card's IOMMU group to `vfio-pci`, as `--now`
does on a running node. `vfio-pci` removes the boot framebuffer itself, so the node's screen works until
then and goes dark when the card is handed over. The udev override is written to `/run/udev/rules.d` at that
point, for that boot only. Nothing of `vfio-pci` is left in the initramfs, and running the script in one mode
undoes the other.

To start a node once with the card on its own driver (to recover a node, or to read its logs), add
`openinfra.gpu-instance=off` to the kernel command line at the boot menu: the service is skipped for that
boot. A node bound early can be started the same way by adding `initcall_blacklist=vfio_pci_init`.

Then take the node out of container GPU scheduling, here and in its k3s `node-label` configuration, so a
re-registration does not put them back:

```bash
kubectl label node <node> openinfra.dev/gpu- openinfra.dev/gpu-model- openinfra.dev/gpu-tier-
```

## 2. Offer the card to instances

In `config.yaml`, the `g4dn` family's card at the top level and the `g5` family's in its own block:

```yaml
gpuInstances:
  pciVendorSelector: "10DE:1EB8"   # the card's vendor:device, as lspci -nn prints it
  name: "T4"                       # as DescribeInstanceTypes names the GPU
  manufacturer: "NVIDIA"
  memoryMiB: "16384"
  g5:                              # optional: a second card model, offered as g5.xlarge
    pciVendorSelector: "10DE:2237"
    name: "A10G"
    manufacturer: "NVIDIA"
    memoryMiB: "24576"
```

and re-run `install.sh`. It permits each family's card in KubeVirt as its own resource,
`openinfra.dev/instance-gpu` (g4dn) and `openinfra.dev/instance-gpu-g5` (g5), and writes the
`openinfra-gpu-instances` ConfigMap the aws-shim reads; restart the aws-shim afterwards. The same two changes
by hand, on a cluster where `install.sh` is not re-run (the patch replaces the whole list, so name every
family's card in it):

```bash
kubectl patch kubevirt kubevirt -n kubevirt --type=merge -p \
  '{"spec":{"configuration":{"permittedHostDevices":{"pciHostDevices":[{"pciVendorSelector":"10DE:1EB8","resourceName":"openinfra.dev/instance-gpu"},{"pciVendorSelector":"10DE:2237","resourceName":"openinfra.dev/instance-gpu-g5"}]}}}}'
kubectl -n open-infra-aws-shim create configmap openinfra-gpu-instances \
  --from-literal=GPU_INSTANCE_GPU_NAME="T4" --from-literal=GPU_INSTANCE_GPU_MANUFACTURER="NVIDIA" \
  --from-literal=GPU_INSTANCE_GPU_MEMORY_MIB="16384" \
  --from-literal=GPU_INSTANCE_G5_GPU_NAME="A10G" --from-literal=GPU_INSTANCE_G5_GPU_MANUFACTURER="NVIDIA" \
  --from-literal=GPU_INSTANCE_G5_GPU_MEMORY_MIB="24576" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n open-infra-aws-shim rollout restart deployment/aws-shim
```

Check that the node offers the card:

```bash
kubectl get node <node> -o jsonpath='{.status.allocatable.openinfra\.dev/instance-gpu-g5}'   # 1
```

One card model per family: every instance of a family draws from that family's pool, and
`DescribeInstanceTypes` reports the family's model for its type. A family without a card is not listed.

## 3. Let an account launch them

An account's `spec.capacity.gpus` limits its GPU instances' cards in each family and, separately, its
pods' GPUs: a quota counts each kind on its own, so `gpus: 1` allows one g4dn instance, one g5 instance and
one container GPU. An account
with `gpus: 0` is refused a GPU instance with `VcpuLimitExceeded`. A GPU instance also counts its
4 vCPUs and 16 GiB (plus the instance's overhead, about 1.5 GiB) against the account's CPU and memory.

## Giving the card back to containers

Delete `/etc/modprobe.d/openinfra-gpu-instance.conf` on the node, and any file in `/etc/udev/rules.d`
that starts `# open-infra (scripts/gpu-instance-host.sh)`. For `--late`, also disable
`openinfra-gpu-instance.service` and delete it and `/usr/local/sbin/openinfra-gpu-instance-bind`. Then run
`update-initramfs -u -k all`, unmask `nvidia-persistenced`, reboot, restore the node's GPU labels, and clear `gpuInstances` in
`config.yaml` (remove the KubeVirt `permittedHostDevices` entry and the ConfigMap by hand if `install.sh`
is not re-run).
