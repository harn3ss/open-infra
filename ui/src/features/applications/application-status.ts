import type { Application, Condition } from "@/types/k8s";
import type { StatusTone } from "@/lib/format";

export interface AppHealth {
  label: string;
  tone: StatusTone;
}

/**
 * Derive a single human status for an Application from its Crossplane-style
 * conditions (Ready / Synced). open-infra Applications are Crossplane claims,
 * so they carry standard `Ready` and `Synced` conditions.
 */
export function applicationHealth(app: Application): AppHealth {
  if (app.metadata.deletionTimestamp) {
    return { label: "Terminating", tone: "warning" };
  }
  const conditions = app.status?.conditions ?? [];
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

export function conditionTone(c: Condition): StatusTone {
  if (c.status === "True") return "success";
  if (c.status === "False") return "destructive";
  return "muted";
}
