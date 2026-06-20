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

/**
 * Refine a claim's health with the liveness of the node(s) backing it.
 *
 * A claim keeps reporting `Ready` for a grace period after its node goes
 * NotReady (Kubernetes hasn't evicted its pods yet), so a "Ready" Model/App
 * whose pods all sit on offline nodes is really unreachable. `nodes` are the
 * node names hosting the claim's pods; `offlineNodes` is the set of NotReady
 * nodes. With no scheduled pods or no offline nodes, the base health stands.
 */
export function nodeAwareHealth(
  base: Health,
  nodes: string[],
  offlineNodes: Set<string>,
): Health {
  if (!nodes.length || offlineNodes.size === 0) return base;
  const offline = nodes.filter((n) => offlineNodes.has(n));
  if (offline.length === 0) return base;
  if (offline.length === nodes.length) {
    // Every backing pod is on a dead node — the claim is not actually serving.
    return { label: "Node offline", tone: "destructive" };
  }
  // Some replicas remain on healthy nodes: degraded, not down.
  return { label: "Degraded", tone: "warning" };
}
