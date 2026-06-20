import type { Node } from "@/types/k8s";
import { parseQuantity, formatBytes, type StatusTone } from "@/lib/format";

export interface NodeReadyState {
  ready: boolean;
  tone: StatusTone;
  label: string;
}

/** A node is "Ready" when its Ready condition is True (and not cordoned). */
export function nodeReady(node: Node): NodeReadyState {
  const ready = node.status?.conditions?.find((c) => c.type === "Ready");
  if (ready?.status === "True") {
    if (node.spec?.unschedulable) {
      return { ready: true, tone: "warning", label: "Ready (cordoned)" };
    }
    return { ready: true, tone: "success", label: "Ready" };
  }
  return { ready: false, tone: "destructive", label: "NotReady" };
}

export interface NodeRole {
  roles: string[];
}

/** Derive node roles from the standard role labels. */
export function nodeRoles(node: Node): string[] {
  const labels = node.metadata.labels ?? {};
  const roles = Object.keys(labels)
    .filter((k) => k.startsWith("node-role.kubernetes.io/"))
    .map((k) => k.slice("node-role.kubernetes.io/".length))
    .filter(Boolean);
  return roles.length ? roles : ["worker"];
}

export interface NodeCapacity {
  cpuCores: number;
  memoryBytes: string;
  pods: number;
  gpus: number;
  gpuModel?: string;
}

export function nodeCapacity(node: Node): NodeCapacity {
  const cap = node.status?.capacity ?? {};
  const model = node.metadata.labels?.["openinfra.dev/gpu-model"];
  return {
    cpuCores: parseQuantity(cap["cpu"]),
    memoryBytes: formatBytes(parseQuantity(cap["memory"])),
    pods: Number(cap["pods"] ?? 0),
    // Advertised by the NVIDIA device plugin; model comes from a node label.
    gpus: Number(cap["nvidia.com/gpu"] ?? 0),
    gpuModel: model ? model.replace(/-/g, " ") : undefined,
  };
}

/** Total GPUs advertised across a set of nodes. */
export function totalGpus(nodes: Node[]): number {
  return nodes.reduce(
    (sum, n) => sum + Number(n.status?.capacity?.["nvidia.com/gpu"] ?? 0),
    0,
  );
}

export function nodeInternalIP(node: Node): string | undefined {
  return node.status?.addresses?.find((a) => a.type === "InternalIP")?.address;
}

/** Non-Ready "abnormal" conditions worth surfacing (pressure/disk/etc). */
export function nodeWarnings(node: Node): string[] {
  const out: string[] = [];
  for (const c of node.status?.conditions ?? []) {
    if (c.type === "Ready") continue;
    // For pressure conditions, "True" is bad.
    if (c.status === "True") out.push(c.type);
  }
  return out;
}
