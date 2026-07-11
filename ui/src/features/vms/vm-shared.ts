// Shared bits for the Virtual Machines views: the OS catalog (in sync with the
// XRD enum + the Composition $catalog) and status/IP derivation from the claim +
// its KubeVirt VirtualMachineInstance.
import type { StatusTone } from "@/lib/format";
import type { DataVolume, VirtualMachine, Vmi } from "@/types/k8s";

export interface OsEntry {
  value: string;
  label: string;
  family: "linux" | "windows";
}

// KEEP IN SYNC with platform/abstraction/vm-xrd.yaml (os enum).
export const OS_CATALOG: OsEntry[] = [
  { value: "ubuntu-24.04", label: "Ubuntu 24.04 LTS", family: "linux" },
  { value: "ubuntu-22.04", label: "Ubuntu 22.04 LTS", family: "linux" },
  { value: "fedora-40", label: "Fedora 40", family: "linux" },
  { value: "debian-12", label: "Debian 12", family: "linux" },
  { value: "centos-stream-9", label: "CentOS Stream 9", family: "linux" },
  { value: "windows-server-2019", label: "Windows Server 2019", family: "windows" },
  { value: "windows-server-2022", label: "Windows Server 2022", family: "windows" },
  { value: "windows-server-2025", label: "Windows Server 2025", family: "windows" },
];

// Windows versions buildable via kind: VmImage (the "VM Images" page). In sync
// with platform/abstraction/vmimage-xrd.yaml + vmimage-composition.yaml $catalog.
export const WINDOWS_CATALOG = OS_CATALOG.filter((o) => o.family === "windows");

// Where golden images + builders live (cross-namespace clone source).
export const IMAGES_NAMESPACE = "openinfra-images";
// The golden-image PVC a VM clones / a build produces, per os.
export function goldenPvcName(os: string): string {
  return `${os}-golden`;
}

export function osLabel(v?: string): string {
  return OS_CATALOG.find((o) => o.value === v)?.label ?? v ?? "—";
}

export function osFamily(v?: string): "linux" | "windows" {
  return OS_CATALOG.find((o) => o.value === v)?.family ?? "linux";
}

export function vmKey(ns?: string, name?: string): string {
  return `${ns ?? ""}/${name ?? ""}`;
}

// The root disk DataVolume for a VM is always named "<vm>-root" (composition).
export function rootDvName(vmName?: string): string {
  return `${vmName ?? ""}-root`;
}

// Windows root disk is fixed by the composition (not user-selectable) and MUST be
// >= the golden image (~95.4Gi) or CDI can't clone it. KEEP IN SYNC with
// platform/abstraction/vm-composition.yaml ($disk for $isWin).
export const WINDOWS_ROOT_DISK = "100Gi";

// A root disk clone/import that can never succeed leaves the DataVolume wedged
// (e.g. CDI's ErrIncompatiblePVC when the target is smaller than the golden — it
// sits in *Scheduled forever). Detect a hard failure, or a clone that hasn't
// even started progressing after a generous grace period, so the VM shows a real
// error instead of an endless "Provisioning" spinner.
const DV_STALL_MS = 10 * 60 * 1000; // 10 min with zero progress ⇒ treat as stuck

function dvFailure(dv?: DataVolume): string | undefined {
  if (!dv) return undefined;
  const phase = dv.status?.phase;
  if (phase === "Failed")
    return dvErrorMessage(dv) ?? "root disk provisioning failed";
  // CDI reflects clone/import problems on the DV conditions (Status False with an
  // error-ish reason/message), so surface those directly when present.
  const cond = dvErrorMessage(dv);
  if (cond) return cond;
  // No clean condition (ErrIncompatiblePVC just keeps retrying): fall back to a
  // stall heuristic — still in a *Scheduled/Pending phase, no progress, and old.
  const stalledPhase =
    !phase || /scheduled|pending/i.test(phase);
  const noProgress =
    !dv.status?.progress ||
    dv.status.progress === "N/A" ||
    dv.status.progress === "0.0%";
  const created = dv.metadata.creationTimestamp;
  if (stalledPhase && noProgress && created) {
    const ageMs = Date.now() - new Date(created).getTime();
    if (ageMs > DV_STALL_MS)
      return "root disk clone has not started — the target may be smaller than the golden image (check DataVolume events)";
  }
  return undefined;
}

function dvErrorMessage(dv?: DataVolume): string | undefined {
  for (const c of dv?.status?.conditions ?? []) {
    if ((c.type === "Running" || c.type === "Bound") && c.status === "False") {
      const hay = `${c.reason ?? ""} ${c.message ?? ""}`.toLowerCase();
      if (/err|error|incompatible|fail|smaller/.test(hay))
        return c.message || c.reason;
    }
  }
  return undefined;
}

const DV_PHASE_LABEL: Record<string, string> = {
  ImportScheduled: "Importing disk",
  ImportInProgress: "Importing disk",
  CloneScheduled: "Cloning disk",
  CloneInProgress: "Cloning disk",
  SnapshotForSmartCloneInProgress: "Cloning disk",
  Pending: "Provisioning",
};

/**
 * Power/lifecycle status from the claim's spec.running + the live VMI phase, plus
 * the root DataVolume so an unbootable / stuck disk clone shows as an error (and
 * a healthy import shows live progress) instead of a perpetual "Provisioning".
 */
export function vmStatus(
  vm: VirtualMachine,
  vmi?: Vmi,
  rootDv?: DataVolume,
): { label: string; tone: StatusTone; detail?: string } {
  if (vm.metadata.deletionTimestamp)
    return { label: "Terminating", tone: "warning" };
  const running = vm.spec?.running !== false; // default true
  if (!running) return { label: "Stopped", tone: "muted" };
  const phase = vmi?.status?.phase;
  if (phase === "Running") return { label: "Running", tone: "success" };
  if (phase) return { label: phase, tone: "warning" }; // Pending/Scheduling/…
  // No VMI yet — the root disk is still being provisioned by CDI.
  const failure = dvFailure(rootDv);
  if (failure) return { label: "Disk error", tone: "destructive", detail: failure };
  const dvPhase = rootDv?.status?.phase;
  if (dvPhase && dvPhase !== "Succeeded") {
    const base = DV_PHASE_LABEL[dvPhase] ?? "Provisioning";
    const pct = rootDv?.status?.progress;
    const label =
      pct && pct !== "N/A" && pct !== "0.0%" ? `${base} ${pct}` : base;
    return { label, tone: "warning" };
  }
  return { label: "Provisioning", tone: "warning" }; // DV done/absent, VMI booting
}

export function vmIp(vmi?: Vmi): string | undefined {
  return vmi?.status?.interfaces?.find((i) => i.ipAddress)?.ipAddress;
}
