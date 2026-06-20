import type { Node } from "@/types/k8s";

/**
 * Names of nodes that are not Ready (offline / unreachable).
 *
 * Kubernetes does NOT rewrite the status of pods/claims the moment their node
 * drops off — a pod keeps `phase: Running` and a Crossplane claim keeps
 * `Ready: True` for a grace period (until the node controller evicts the pods).
 * The console reads those objects straight from the API, so without this the UI
 * would faithfully report "Running"/"Ready" for workloads on a dead node. We use
 * this offline set to refine what the user is shown.
 */
export function offlineNodeNames(nodes: Node[]): Set<string> {
  const out = new Set<string>();
  for (const n of nodes) {
    const ready = n.status?.conditions?.find((c) => c.type === "Ready");
    // Ready != "True" means NotReady or Unknown — both are "offline" to a user.
    if (ready?.status !== "True") {
      const name = n.metadata.name;
      if (name) out.add(name);
    }
  }
  return out;
}
