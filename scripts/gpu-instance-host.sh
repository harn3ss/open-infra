#!/usr/bin/env bash
# Operator script (run as root ON the GPU's node): prepare a GPU card to be handed whole to GPU instances
# (EC2 g4dn.xlarge, g5.xlarge) by PCI passthrough, instead of to containers. See docs/gpu-instances.md.
#
#   sudo ./gpu-instance-host.sh 0000:01:00.0          # write the boot configuration; reboot to apply
#   sudo ./gpu-instance-host.sh 0000:01:00.0 --now    # ... and move the card to vfio-pci now, no reboot
#
# The card's whole IOMMU group (its display and audio functions) is bound to vfio-pci at boot: the group's
# vendor:device ids go to vfio-pci's ids option, which every GPU and audio driver is made to load after, and
# vfio-pci joins the initramfs. The kernel command line gets the IOMMU on in pass-through mode, and the boot
# framebuffer is left unclaimed (initcall_blacklist=sysfb_init) so the guest can take the card's memory: the
# node's own screen goes dark after boot (SSH is unaffected). nvidia-persistenced is masked. A node with no
# other display device keeps no desktop: it boots to multi-user.target, since a display manager would fail on
# the card and retry at every boot (--now stops it). Idempotent.
#
# Refuses a card whose IOMMU group holds devices other than the card's own functions (they would have to be
# given away with it). After it: remove the node's container-GPU labels (openinfra.dev/gpu, gpu-model,
# gpu-tier) and set config.yaml's gpuInstances, then re-run install.sh.
set -euo pipefail

die() { printf 'gpu-instance-host: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"
ADDR="${1:-}"; NOW="${2:-}"
printf '%s' "$ADDR" | grep -Eq '^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$' || die "usage: $0 <pci address, e.g. 0000:01:00.0> [--now]"
DEV="/sys/bus/pci/devices/$ADDR"
[ -e "$DEV" ] || die "no PCI device $ADDR"
[ -n "$(ls /sys/kernel/iommu_groups 2>/dev/null)" ] || die "the IOMMU is off: enable VT-d (Intel) or AMD-Vi in the firmware, then rerun"
GROUP="$(basename "$(readlink "$DEV/iommu_group")")"
SLOT="${ADDR%.*}"
IDS=()
for d in /sys/kernel/iommu_groups/"$GROUP"/devices/*; do
  a="$(basename "$d")"
  [ "${a%.*}" = "$SLOT" ] || die "IOMMU group $GROUP also holds $a, which is not the card's: it would be given away with the card"
  IDS+=("$(sed 's/^0x//' "$d/vendor"):$(sed 's/^0x//' "$d/device")")
done
ID_LIST="$(IFS=,; echo "${IDS[*]}")"
echo "card $ADDR, IOMMU group $GROUP, functions $ID_LIST"

cat > /etc/modprobe.d/openinfra-gpu-instance.conf <<EOF
# open-infra: this node's GPU is given whole to GPU instances (PCI passthrough), not to containers.
# Written by scripts/gpu-instance-host.sh; delete this file (and rebuild the initramfs) to give it back.
options vfio-pci ids=$ID_LIST disable_vga=1
softdep nvidia pre: vfio-pci
softdep nvidia_drm pre: vfio-pci
softdep nouveau pre: vfio-pci
softdep amdgpu pre: vfio-pci
softdep snd_hda_intel pre: vfio-pci
EOF
for m in vfio vfio_iommu_type1 vfio_pci; do
  grep -qx "$m" /etc/initramfs-tools/modules 2>/dev/null || echo "$m" >> /etc/initramfs-tools/modules
done
update-initramfs -u -k all >/dev/null

if grep -q '^GenuineIntel' <(grep -m1 vendor_id /proc/cpuinfo | awk '{print $3}'); then IOMMU=intel_iommu=on; else IOMMU=amd_iommu=on; fi
cmdline="$(sed -n 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"$/\1/p' /etc/default/grub)"
for p in "$IOMMU" iommu=pt initcall_blacklist=sysfb_init; do
  case " $cmdline " in *" $p "*) ;; *) cmdline="${cmdline:+$cmdline }$p" ;; esac
done
sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"$cmdline\"|" /etc/default/grub
update-grub >/dev/null 2>&1
echo "boot: vfio-pci claims $ID_LIST; kernel command line: $cmdline"

if systemctl list-unit-files nvidia-persistenced.service >/dev/null 2>&1; then
  systemctl stop nvidia-persistenced 2>/dev/null || true
  systemctl mask nvidia-persistenced >/dev/null 2>&1 || true
fi

# Is the card the node's only display device? Then the node keeps no desktop.
ONLY_DISPLAY=1
for d in /sys/bus/pci/devices/*; do
  case "$(cat "$d/class")" in
    0x03*) g="$(readlink "$d/iommu_group" 2>/dev/null || true)"; [ "${g##*/}" = "$GROUP" ] || ONLY_DISPLAY="" ;;
  esac
done
if [ -n "$ONLY_DISPLAY" ] && [ "$(systemctl get-default)" = graphical.target ]; then
  systemctl set-default multi-user.target >/dev/null 2>&1
  echo "boot: the card is the node's only display, so it boots to multi-user.target (no desktop)"
fi

if [ "$NOW" = "--now" ]; then
  # A desktop on the card holds its driver open: stop it (the node has no other screen to draw on).
  if [ -n "$ONLY_DISPLAY" ] && systemctl is-active --quiet display-manager 2>/dev/null; then
    systemctl stop display-manager
    echo "stopped the display manager (the card is the node's only display)"
  fi
  # Release the console from the card's framebuffer, unload its drivers, and hand its functions to vfio-pci.
  for v in /sys/class/vtconsole/vtcon*; do grep -qi "frame buffer" "$v/name" && echo 0 > "$v/bind"; done
  for m in nvidia_drm nvidia_modeset nvidia_uvm nvidia nouveau; do
    grep -q "^$m " /proc/modules && { modprobe -r "$m" || die "could not unload $m (in use?): reboot instead"; }
  done
  modprobe vfio-pci
  for d in /sys/kernel/iommu_groups/"$GROUP"/devices/*; do
    a="$(basename "$d")"
    [ -e "$d/driver" ] && [ "$(basename "$(readlink "$d/driver")")" != vfio-pci ] && echo "$a" > "$d/driver/unbind"
    echo vfio-pci > "$d/driver_override"
    [ -e "$d/driver" ] || echo "$a" > /sys/bus/pci/drivers_probe
    echo "$a: $(basename "$(readlink "$d/driver")")"
  done
else
  echo "reboot the node to apply (drain it first)"
fi
