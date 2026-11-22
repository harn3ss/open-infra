# GPU instances: operator guide

*This is an operator guide: it speaks of nodes, KubeVirt and Kubernetes resources, which customers never
see. What a customer gets is in [Virtual Machines: GPU instances](virtual-machines.md#gpu-instances-g4dnxlarge).*

A GPU instance (EC2 `g4dn.xlarge`: 4 vCPUs, 16 GiB, one GPU) is given a whole GPU card by PCI passthrough,
and runs the card's own driver in its guest. A card set aside for GPU instances is not available to
containers (`kind: Model`, Functions, training jobs): choose per card. Each card runs one instance at a time.

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
the node holds the card open.

Then take the node out of container GPU scheduling, here and in its k3s `node-label` configuration, so a
re-registration does not put them back:

```bash
kubectl label node <node> openinfra.dev/gpu- openinfra.dev/gpu-model- openinfra.dev/gpu-tier-
```

## 2. Offer the card to instances

In `config.yaml`:

```yaml
gpuInstances:
  pciVendorSelector: "10DE:1EB8"   # the card's vendor:device, as lspci -nn prints it
  name: "T4"                       # as DescribeInstanceTypes names the GPU
  manufacturer: "NVIDIA"
  memoryMiB: "16384"
```

and re-run `install.sh`. It permits the card in KubeVirt as the `openinfra.dev/instance-gpu` resource and
writes the `openinfra-gpu-instances` ConfigMap the aws-shim reads; restart the aws-shim afterwards. The same
two changes by hand, on a cluster where `install.sh` is not re-run:

```bash
kubectl patch kubevirt kubevirt -n kubevirt --type=merge -p \
  '{"spec":{"configuration":{"permittedHostDevices":{"pciHostDevices":[{"pciVendorSelector":"10DE:1EB8","resourceName":"openinfra.dev/instance-gpu"}]}}}}'
kubectl -n open-infra-aws-shim create configmap openinfra-gpu-instances \
  --from-literal=GPU_INSTANCE_GPU_NAME="T4" --from-literal=GPU_INSTANCE_GPU_MANUFACTURER="NVIDIA" \
  --from-literal=GPU_INSTANCE_GPU_MEMORY_MIB="16384" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n open-infra-aws-shim rollout restart deployment/aws-shim
```

Check that the node offers the card:

```bash
kubectl get node <node> -o jsonpath='{.status.allocatable.openinfra\.dev/instance-gpu}'   # 1
```

One selector and one card model per installation: every GPU instance draws from the same pool of cards,
and `DescribeInstanceTypes` reports the one model.

## 3. Let an account launch them

An account's `spec.capacity.gpus` limits its GPU instances' cards and, separately, its pods' GPUs: a
quota counts each kind on its own, so `gpus: 1` allows one GPU instance and one container GPU. An account
with `gpus: 0` is refused a GPU instance with `VcpuLimitExceeded`. A GPU instance also counts its
4 vCPUs and 16 GiB (plus the instance's overhead, about 1.5 GiB) against the account's CPU and memory.

## Giving the card back to containers

Delete `/etc/modprobe.d/openinfra-gpu-instance.conf` on the node, run `update-initramfs -u -k all`,
unmask `nvidia-persistenced`, reboot, restore the node's GPU labels, and clear `gpuInstances` in
`config.yaml` (remove the KubeVirt `permittedHostDevices` entry and the ConfigMap by hand if `install.sh`
is not re-run).
