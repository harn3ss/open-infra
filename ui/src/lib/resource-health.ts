import type { Condition, K8sObject } from "@/types/k8s";
import type { StatusTone } from "@/lib/format";

export interface Health {
  label: string;
  tone: StatusTone;
}

/**
 * Derive a single human status from Crossplane-style claim conditions
 * (Ready / Synced). Works for any open-infra claim (Application / Function /
 * Model) — they all carry standard `Ready` and `Synced` conditions.
 */
export function claimHealth(
  obj: K8sObject<unknown, { conditions?: Condition[] }>,
): Health {
  if (obj.metadata.deletionTimestamp) {
    return { label: "Terminating", tone: "warning" };
  }
  const conditions = obj.status?.conditions ?? [];
  const ready = conditions.find((c) => c.type === "Ready");
  const synced = conditions.find((c) => c.type === "Synced");

  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  if (ready?.status === "False") {
    return { label: ready.reason || "Not ready", tone: "destructive" };
  }
  if (synced?.status === "False") {
    return { label: synced.reason || "Sync error", tone: "destructive" };
  }
  if (conditions.length === 0) return { label: "Pending", tone: "warning" };
  return { label: "Provisioning", tone: "warning" };
}
