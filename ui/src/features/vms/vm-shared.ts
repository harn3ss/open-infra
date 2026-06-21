// Shared bits for the Virtual Machines views: the OS catalog (in sync with the
// XRD enum + the Composition $catalog) and status/IP derivation from the claim +
// its KubeVirt VirtualMachineInstance.
import type { StatusTone } from "@/lib/format";
import type { VirtualMachine, Vmi } from "@/types/k8s";

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
  { value: "windows", label: "Windows (eval golden image)", family: "windows" },
];

export function osLabel(v?: string): string {
  return OS_CATALOG.find((o) => o.value === v)?.label ?? v ?? "—";
}

export function osFamily(v?: string): "linux" | "windows" {
  return OS_CATALOG.find((o) => o.value === v)?.family ?? "linux";
}

export function vmKey(ns?: string, name?: string): string {
  return `${ns ?? ""}/${name ?? ""}`;
}

/** Power/lifecycle status from the claim's spec.running + the live VMI phase. */
export function vmStatus(
  vm: VirtualMachine,
  vmi?: Vmi,
): { label: string; tone: StatusTone } {
  if (vm.metadata.deletionTimestamp)
    return { label: "Terminating", tone: "warning" };
  const running = vm.spec?.running !== false; // default true
  if (!running) return { label: "Stopped", tone: "muted" };
  const phase = vmi?.status?.phase;
  if (phase === "Running") return { label: "Running", tone: "success" };
  if (phase) return { label: phase, tone: "warning" }; // Pending/Scheduling/…
  return { label: "Provisioning", tone: "warning" }; // no VMI yet (disk import)
}

export function vmIp(vmi?: Vmi): string | undefined {
  return vmi?.status?.interfaces?.find((i) => i.ipAddress)?.ipAddress;
}
