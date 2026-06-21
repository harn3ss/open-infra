#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Build the open-infra Windows golden image (one-time, operator-run).
#
# Produces a generalized Windows disk as the PVC <name> in <namespace>, which the
# kind: VirtualMachine Composition clones for every `os: windows` VM.
#
#   scripts/build-windows-image.sh --windows-iso <url|path> [opts]
#
# Requires: kubectl, virtctl, and genisoimage (or mkisofs) locally; KubeVirt+CDI
# installed; a Windows EVALUATION ISO (Server 2022 by default). Eval editions are
# free for non-production testing only — see docs/virtual-machines.md (licensing).
# ─────────────────────────────────────────────────────────────
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG() { printf '\033[1;36m[win-image]\033[0m %s\n' "$*"; }
DIE() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

WIN_ISO=""
VIRTIO_ISO="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
NAME="windows-golden"
NS="openinfra-images"
DISK_SIZE="64Gi"
RAM="6Gi"
CPU="4"

while [ $# -gt 0 ]; do
  case "$1" in
    --windows-iso) WIN_ISO="$2"; shift 2 ;;
    --virtio-iso)  VIRTIO_ISO="$2"; shift 2 ;;
    --name)        NAME="$2"; shift 2 ;;
    --namespace)   NS="$2"; shift 2 ;;
    --disk-size)   DISK_SIZE="$2"; shift 2 ;;
    -h|--help)     grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -16; exit 0 ;;
    *) DIE "unknown arg: $1" ;;
  esac
done
[ -n "$WIN_ISO" ] || DIE "--windows-iso <url|path> is required (a Windows eval ISO)"
command -v kubectl  >/dev/null || DIE "kubectl is required"
command -v virtctl  >/dev/null || DIE "virtctl is required (CDI image upload)"
ISO_TOOL="$(command -v genisoimage || command -v mkisofs || true)"
[ -n "$ISO_TOOL" ] || DIE "genisoimage or mkisofs is required"

LOG "namespace=$NS golden=$NAME disk=$DISK_SIZE"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# 1. Build the aux ISO (autounattend.xml + setup.ps1 at the root). Windows Setup
#    auto-detects autounattend.xml on attached removable media.
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cp "$HERE/windows/autounattend.xml" "$HERE/windows/setup.ps1" "$TMP/"
"$ISO_TOOL" -quiet -J -r -V OIUNATTEND -o "$TMP/aux.iso" "$TMP" >/dev/null 2>&1 || \
  "$ISO_TOOL" -J -r -V OIUNATTEND -o "$TMP/aux.iso" "$TMP"
LOG "built aux ISO ($(du -h "$TMP/aux.iso" | cut -f1))"

# 2. Import the Windows + virtio ISOs into PVCs via CDI.
import_dv() { # name  source(url|path)
  local n="$1" src="$2"
  if [ -f "$src" ]; then
    LOG "uploading $n from local file $src"
    virtctl image-upload dv "$n" --namespace "$NS" --size=10Gi \
      --image-path="$src" --insecure --force
  else
    LOG "importing $n from $src"
    cat <<EOF | kubectl apply -f -
apiVersion: cdi.kubevirt.io/v1beta1
kind: DataVolume
metadata: { name: $n, namespace: $NS }
spec:
  source: { http: { url: "$src" } }
  storage:
    accessModes: [ReadWriteOnce]
    resources: { requests: { storage: 10Gi } }
    storageClassName: local-path
EOF
  fi
}
import_dv "${NAME}-winiso" "$WIN_ISO"
import_dv "${NAME}-virtio" "$VIRTIO_ISO"

LOG "uploading aux ISO"
virtctl image-upload dv "${NAME}-aux" --namespace "$NS" --size=1Gi \
  --image-path="$TMP/aux.iso" --insecure --force

# 3. The golden disk — STANDALONE DataVolume (not a VM dataVolumeTemplate) so
#    deleting the installer VM later does NOT delete the image.
cat <<EOF | kubectl apply -f -
apiVersion: cdi.kubevirt.io/v1beta1
kind: DataVolume
metadata: { name: $NAME, namespace: $NS }
spec:
  source: { blank: {} }
  storage:
    accessModes: [ReadWriteOnce]
    resources: { requests: { storage: $DISK_SIZE } }
    storageClassName: local-path
EOF

LOG "waiting for ISO imports to finish…"
for dv in "${NAME}-winiso" "${NAME}-virtio"; do
  kubectl wait --for=condition=Ready "datavolume/$dv" -n "$NS" --timeout=1800s || true
done

# 4. Installer VM: boot the Windows ISO, install onto the golden disk (virtio),
#    with the virtio + aux ISOs attached. setup.ps1 finishes + sysprep shuts down.
cat <<EOF | kubectl apply -f -
apiVersion: kubevirt.io/v1
kind: VirtualMachine
metadata: { name: ${NAME}-installer, namespace: $NS }
spec:
  runStrategy: Always
  template:
    spec:
      domain:
        cpu: { cores: $CPU }
        resources: { requests: { memory: $RAM } }
        machine: { type: q35 }
        features: { acpi: {}, apic: {}, smm: {} }
        firmware: { bootloader: { efi: { secureBoot: false } } }
        devices:
          disks:
            - { name: target, disk: { bus: virtio }, bootOrder: 2 }
            - { name: winiso, cdrom: { bus: sata }, bootOrder: 1 }
            - { name: virtio, cdrom: { bus: sata } }
            - { name: aux,    cdrom: { bus: sata } }
          interfaces: [ { name: default, masquerade: {} } ]
        networkInterfaceMultiqueue: true
      networks: [ { name: default, pod: {} } ]
      volumes:
        - { name: target, persistentVolumeClaim: { claimName: $NAME } }
        - { name: winiso, persistentVolumeClaim: { claimName: ${NAME}-winiso } }
        - { name: virtio, persistentVolumeClaim: { claimName: ${NAME}-virtio } }
        - { name: aux,    persistentVolumeClaim: { claimName: ${NAME}-aux } }
EOF

cat <<NEXT

Installer VM '${NAME}-installer' is running in '$NS'.
Watch it:   virtctl vnc ${NAME}-installer -n $NS     (or any VNC client)
            kubectl get vmi ${NAME}-installer -n $NS -w

It installs Windows unattended, runs setup.ps1 (virtio tools + cloudbase-init +
RDP), then sysprep-generalizes and SHUTS DOWN. When the VMI is gone / VM is
Stopped, the build is done. Then clean up (keeps the golden '$NAME'):

  kubectl delete vm ${NAME}-installer -n $NS
  kubectl delete dv ${NAME}-winiso ${NAME}-virtio ${NAME}-aux -n $NS

After that, 'spec.os: windows' VMs clone '$NS/$NAME'.
NEXT
LOG "submitted. (full Windows install can take 20–40 min)"
