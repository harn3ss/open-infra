#!/usr/bin/env bash
# Operator script (run as root ON the GPU's node): prepare a GPU card to be handed whole to GPU instances
# (EC2 g4dn.xlarge, g5.xlarge) by PCI passthrough, instead of to containers. See docs/gpu-instances.md.
#
#   sudo ./gpu-instance-host.sh 0000:01:00.0               # write the boot configuration; reboot to apply
#   sudo ./gpu-instance-host.sh 0000:01:00.0 --now         # ... and move the card to vfio-pci now, no reboot
#   sudo ./gpu-instance-host.sh 0000:01:00.0 --late [--now] # bind it late in boot instead (see below)
#
# By default the card's whole IOMMU group (its display and audio functions) is bound to vfio-pci at boot: the
# group's vendor:device ids go to vfio-pci's ids option, which every GPU and audio driver is made to load
# after, and vfio-pci joins the initramfs. The kernel command line gets the IOMMU on in pass-through mode,
# and the boot framebuffer is left unclaimed (initcall_blacklist=sysfb_init) so the guest can take the card's
# memory: the node's own screen goes dark after boot (SSH is unaffected).
#
# --late binds it late in boot instead, the way --now moves it on a running node: the card's own driver
# initializes it as usual, then openinfra-gpu-instance.service, ordered before the node's Kubernetes agent,
# unloads that driver and hands the group to vfio-pci (which removes the boot framebuffer itself). For a node
# that does not boot with the card bound early, as one whose only display device is the card can hang. Adding
# openinfra.gpu-instance=off to the kernel command line at the boot menu skips the service for that boot,
# leaving the card with its own driver.
#
# Either way nvidia-persistenced is masked, and a node with no other display device keeps no desktop: it
# boots to multi-user.target, since a display manager would fail on the card and retry at every boot (--now
# stops it). On a node with no other NVIDIA display device, NVIDIA's udev rule that loads the driver's modules
# whenever it registers is overridden without those lines, since with no card to drive it would reload the
# driver several times a second: in /etc/udev/rules.d, or for --late in /run/udev/rules.d once the card is
# handed over at each boot. Idempotent; running it in one mode undoes the other.
#
# Refuses a card whose IOMMU group holds devices other than the card's own functions (they would have to be
# given away with it). After it: remove the node's container-GPU labels (openinfra.dev/gpu, gpu-model,
# gpu-tier) and set config.yaml's gpuInstances, then re-run install.sh.
set -euo pipefail

die() { printf 'gpu-instance-host: %s\n' "$*" >&2; exit 1; }
USAGE="usage: $0 <pci address, e.g. 0000:01:00.0> [--late] [--now]"
[ "$(id -u)" = 0 ] || die "run as root"
ADDR="${1:-}"; [ $# -gt 0 ] && shift
NOW=""; LATE=""
for a in "$@"; do
  case "$a" in --now) NOW=1 ;; --late) LATE=1 ;; *) die "$USAGE" ;; esac
done
printf '%s' "$ADDR" | grep -Eq '^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$' || die "$USAGE"
DEV="/sys/bus/pci/devices/$ADDR"
[ -e "$DEV" ] || die "no PCI device $ADDR"
[ -n "$(ls /sys/kernel/iommu_groups 2>/dev/null)" ] || die "the IOMMU is off: enable VT-d (Intel) or AMD-Vi in the firmware, then rerun"
GROUP="$(basename "$(readlink "$DEV/iommu_group")")"
SLOT="${ADDR%.*}"
IDS=(); FUNCS=()
for d in /sys/kernel/iommu_groups/"$GROUP"/devices/*; do
  a="$(basename "$d")"
  [ "${a%.*}" = "$SLOT" ] || die "IOMMU group $GROUP also holds $a, which is not the card's: it would be given away with the card"
  IDS+=("$(sed 's/^0x//' "$d/vendor"):$(sed 's/^0x//' "$d/device")")
  FUNCS+=("$a")
done
ID_LIST="$(IFS=,; echo "${IDS[*]}")"
echo "card $ADDR, IOMMU group $GROUP, functions $ID_LIST"

# Is the card the node's only display device? Then the node keeps no desktop.
ONLY_DISPLAY=1
for d in /sys/bus/pci/devices/*; do
  case "$(cat "$d/class")" in
    0x03*) g="$(readlink "$d/iommu_group" 2>/dev/null || true)"; [ "${g##*/}" = "$GROUP" ] || ONLY_DISPLAY="" ;;
  esac
done

# NVIDIA's driver package has a udev rule that loads the driver's other modules whenever the driver registers.
# With the node's only NVIDIA display device on vfio-pci the driver finds no card and unloads, and loading it
# fires the rule again: a loop of several loads a second, flooding the kernel log. So when the card is the
# node's only NVIDIA display device, the rule is overridden by name without those lines (the rest, such as its
# runtime power management, stays). Overrides this script wrote carry NV_MARK.
NV_MARK="# open-infra (scripts/gpu-instance-host.sh):"
NV_RULES=(); OTHER_NVIDIA=""
for d in /sys/bus/pci/devices/*; do
  [ "$(cat "$d/vendor")" = 0x10de ] || continue
  case "$(cat "$d/class")" in
    0x03*) g="$(readlink "$d/iommu_group" 2>/dev/null || true)"; [ "${g##*/}" = "$GROUP" ] || OTHER_NVIDIA=1 ;;
  esac
done
if [ -z "$OTHER_NVIDIA" ]; then
  for f in /usr/lib/udev/rules.d/*.rules /lib/udev/rules.d/*.rules; do
    [ -f "$f" ] || continue
    grep -q 'DEVPATH=="/bus/pci/drivers/nvidia"' "$f" || continue
    case " ${NV_RULES[*]-} " in *"/$(basename "$f") "*) ;; *) NV_RULES+=("$f") ;; esac
  done
fi
for o in /etc/udev/rules.d/*.rules; do
  if [ -f "$o" ] && grep -qF "$NV_MARK" "$o"; then rm -f "$o"; fi
done
# nv_override <dir> <note>: write those overrides into <dir> and have udev reread its rules.
nv_override() {
  local f
  [ ${#NV_RULES[@]} -gt 0 ] || return 0
  mkdir -p "$1"
  for f in "${NV_RULES[@]}"; do
    { echo "$NV_MARK NVIDIA's rule of this name, without its lines that"
      echo "# load the driver's modules when it registers: the card is on vfio-pci. $2"
      grep -v 'DEVPATH=="/bus/pci/drivers/nvidia"' "$f" || true; } > "$1/$(basename "$f")"
    echo "udev: $(basename "$f") overridden in $1, without its driver-loading lines"
  done
  udevadm control --reload 2>/dev/null || true
}

UNIT=/etc/systemd/system/openinfra-gpu-instance.service
BIND=/usr/local/sbin/openinfra-gpu-instance-bind
if [ -n "$LATE" ]; then
  cat > /etc/modprobe.d/openinfra-gpu-instance.conf <<EOF
# open-infra: this node's GPU is given whole to GPU instances (PCI passthrough), not to containers.
# It is bound to vfio-pci late in boot by openinfra-gpu-instance.service (scripts/gpu-instance-host.sh
# --late), not by this file; delete the file, the service and $BIND to give it back.
EOF
  cat > "$BIND" <<EOF
#!/bin/sh
# open-infra (scripts/gpu-instance-host.sh --late): hand the GPU's IOMMU group to vfio-pci, late in boot.
set -u
log() { echo "openinfra-gpu-instance: \$*"; }
# Let the card's own driver initialize it first (up to a minute), as on a node whose card was moved live.
i=0
while [ \$i -lt 60 ] && [ ! -e /sys/bus/pci/devices/$ADDR/driver ]; do sleep 1; i=\$((i + 1)); done
# Before the driver unloads: NVIDIA's udev rule, for this boot without the lines that load the driver's modules
# when it registers, which with the card on vfio-pci would load it again and again.
NV_RULES="${NV_RULES[*]-}"
if [ -n "\$NV_RULES" ]; then
  mkdir -p /run/udev/rules.d
  for f in \$NV_RULES; do
    [ -f "\$f" ] || continue
    { echo "$NV_MARK NVIDIA's rule of this name, for this boot without its lines"
      echo "# that load the driver's modules when it registers: the card is on vfio-pci (--late)."
      grep -v 'DEVPATH=="/bus/pci/drivers/nvidia"' "\$f"; } > "/run/udev/rules.d/\$(basename "\$f")"
  done
  udevadm control --reload 2>/dev/null || true
fi
if [ -n "$ONLY_DISPLAY" ] && systemctl is-active --quiet display-manager 2>/dev/null; then
  systemctl stop display-manager
fi
for v in /sys/class/vtconsole/vtcon*; do grep -qi "frame buffer" "\$v/name" && echo 0 > "\$v/bind"; done
for m in nvidia_drm nvidia_modeset nvidia_uvm nvidia nouveau; do
  if grep -q "^\$m " /proc/modules; then modprobe -r "\$m" || { log "could not unload \$m"; exit 1; }; fi
done
modprobe vfio-pci
for a in ${FUNCS[*]}; do
  d=/sys/bus/pci/devices/\$a
  if [ -e "\$d/driver" ] && [ "\$(basename "\$(readlink "\$d/driver")")" != vfio-pci ]; then echo "\$a" > "\$d/driver/unbind"; fi
  echo vfio-pci > "\$d/driver_override"
  [ -e "\$d/driver" ] || echo "\$a" > /sys/bus/pci/drivers_probe
  log "\$a: \$(basename "\$(readlink "\$d/driver")")"
done
EOF
  chmod 0755 "$BIND"
  # Nothing of vfio in the initramfs: the boot runs as a node with the card on its own driver does.
  [ -f /etc/initramfs-tools/modules ] && sed -i '/^vfio$/d; /^vfio_iommu_type1$/d; /^vfio_pci$/d' /etc/initramfs-tools/modules
  cat > "$UNIT" <<EOF
[Unit]
Description=open-infra: give the GPU at $ADDR to GPU instances (vfio-pci), late in boot
Documentation=https://github.com/harn3ss/open-infra/blob/main/docs/gpu-instances.md
After=systemd-modules-load.service
Before=k3s.service k3s-agent.service rke2-server.service rke2-agent.service kubelet.service
# Typed at the boot menu, openinfra.gpu-instance=off leaves the card with its own driver for that boot.
ConditionKernelCommandLine=!openinfra.gpu-instance=off

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$BIND
TimeoutStartSec=180

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable openinfra-gpu-instance.service >/dev/null 2>&1
  echo "boot: openinfra-gpu-instance.service hands $ID_LIST to vfio-pci late in boot"
  # A card already on vfio-pci this boot gets the service's udev overrides now.
  if [ "$(basename "$(readlink "$DEV/driver" 2>/dev/null)")" = vfio-pci ]; then
    nv_override /run/udev/rules.d "For this boot (--late)."
  fi
else
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
  nv_override /etc/udev/rules.d "Delete it to give the card back."
  if [ -e "$UNIT" ]; then
    systemctl disable openinfra-gpu-instance.service >/dev/null 2>&1 || true
    rm -f "$UNIT" "$BIND"; systemctl daemon-reload
  fi
fi
update-initramfs -u -k all >/dev/null

if grep -q '^GenuineIntel' <(grep -m1 vendor_id /proc/cpuinfo | awk '{print $3}'); then IOMMU=intel_iommu=on; else IOMMU=amd_iommu=on; fi
cmdline="$(sed -n 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"$/\1/p' /etc/default/grub)"
want=("$IOMMU" iommu=pt); [ -n "$LATE" ] || want+=(initcall_blacklist=sysfb_init)
for p in "${want[@]}"; do
  case " $cmdline " in *" $p "*) ;; *) cmdline="${cmdline:+$cmdline }$p" ;; esac
done
if [ -n "$LATE" ]; then # late binding keeps the boot framebuffer: vfio-pci removes it when it takes the card
  cmdline="$(printf ' %s ' "$cmdline" | sed 's/ initcall_blacklist=sysfb_init / /g; s/^ *//; s/ *$//')"
fi
sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"$cmdline\"|" /etc/default/grub
update-grub >/dev/null 2>&1
if [ -n "$LATE" ]; then echo "boot: kernel command line: $cmdline"
else echo "boot: vfio-pci claims $ID_LIST; kernel command line: $cmdline"; fi

if systemctl list-unit-files nvidia-persistenced.service >/dev/null 2>&1; then
  systemctl stop nvidia-persistenced 2>/dev/null || true
  systemctl mask nvidia-persistenced >/dev/null 2>&1 || true
fi

if [ -n "$ONLY_DISPLAY" ] && [ "$(systemctl get-default)" = graphical.target ]; then
  systemctl set-default multi-user.target >/dev/null 2>&1
  echo "boot: the card is the node's only display, so it boots to multi-user.target (no desktop)"
fi

if [ -n "$NOW" ] && [ -n "$LATE" ]; then
  systemctl start openinfra-gpu-instance.service || die "openinfra-gpu-instance.service failed: see journalctl -u openinfra-gpu-instance"
  for a in "${FUNCS[@]}"; do echo "$a: $(basename "$(readlink "/sys/bus/pci/devices/$a/driver")")"; done
elif [ -n "$NOW" ]; then
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
