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

/**
 * Health for a Model, layering replica availability on top of the node-aware
 * claim health. A highAvailability Model wants 2 replicas; if GPU nodes are
 * scarce the extra one stays Pending, so we surface "Degraded (1/2)" rather
 * than a flat "Ready" — the honest state for graceful HA degradation.
 *
 * `nodes`/`offlineNodes` feed nodeAwareHealth; `ready`/`desired` are the running
 * vs wanted replica counts.
 */
export function modelHealth(
  model: K8sObject<{ highAvailability?: boolean }, { conditions?: Condition[] }>,
  ctx: {
    nodes: string[];
    offlineNodes: Set<string>;
    ready: number;
    desired: number;
  },
): Health {
  const base = nodeAwareHealth(claimHealth(model), ctx.nodes, ctx.offlineNodes);
  if (model.metadata.deletionTimestamp) return base;
  // Only refine when at least one replica is up — zero ready means base health
  // (Node offline / Not ready / Provisioning) is the more accurate story.
  if (ctx.desired > 1 && ctx.ready >= 1 && ctx.ready < ctx.desired) {
    return { label: `Degraded (${ctx.ready}/${ctx.desired})`, tone: "warning" };
  }
  return base;
}

/** Desired replica count for a Model given its HA setting. */
export function modelDesiredReplicas(highAvailability?: boolean): number {
  return highAvailability ? 2 : 1;
}
