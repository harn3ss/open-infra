import type { Condition, K8sObject } from "@/types/k8s";
import type { StatusTone } from "@/lib/format";
import { awsState } from "@/lib/aws-states";

export interface Health {
  label: string;
  tone: StatusTone;
  /** Why it failed or is waiting, when its conditions say. */
  detail?: string;
}

/**
 * A resource's status in AWS's words (lib/aws-states): Available / Creating / Pending / Deleting /
 * Failed, or the service's own (a Lambda function is Active). `service` picks the service's words:
 * "function", "statemachine", "featuregroup", "modelmonitor", "scheduledjob".
 */
export function claimHealth(
  obj: K8sObject<unknown, { conditions?: Condition[] }>,
  service?: string,
): Health {
  const s = awsState(obj, service);
  return { label: s.label, tone: s.tone, detail: s.detail };
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
    // Every backing pod is on a dead node — the claim is not actually serving. AWS calls a resource whose
    // host is down "impaired" (an EC2 status check), not by the host's Kubernetes name.
    return { label: "Impaired", tone: "destructive" };
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
