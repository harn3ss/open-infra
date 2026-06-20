import { useMemo } from "react";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { corePaths } from "@/lib/k8s-paths";
import type { Pod } from "@/types/k8s";

/**
 * Standard label every open-infra claim stamps on its backing pods
 * (Application/Model deployments use `app.kubernetes.io/name=<claim-name>`).
 * It's how we map a claim back to the node(s) actually running it.
 */
const APP_LABEL = "app.kubernetes.io/name";

export interface AppStats {
  /** Pods (this app) that are Running with all containers ready. */
  ready: number;
  /** Total pods seen for this app (incl. Pending/unschedulable). */
  total: number;
}

export interface PodNodeIndex {
  /**
   * Node names hosting pods labeled `app.kubernetes.io/name=<name>` in
   * `<namespace>`. Empty when the claim has no scheduled pods (e.g. scaled to
   * zero) or none could be found in the watched scope.
   */
  nodesForApp: (namespace: string | undefined, name: string | undefined) => string[];
  /** Ready/total pod counts for a claim — used to detect degraded HA. */
  statsForApp: (namespace: string | undefined, name: string | undefined) => AppStats;
  loaded: boolean;
}

function podIsReady(p: Pod): boolean {
  if (p.metadata.deletionTimestamp) return false;
  if (p.status?.phase !== "Running") return false;
  const cs = p.status?.containerStatuses ?? [];
  return cs.length > 0 && cs.every((c) => c.ready);
}

interface Entry {
  nodes: Set<string>;
  ready: number;
  total: number;
}

/**
 * Indexes pods in `scope` by their `app.kubernetes.io/name` label so callers can
 * ask "which node(s) is claim X running on?" and "how many replicas are ready?".
 * Pass a concrete namespace to keep the watch small; pass undefined to index the
 * whole cluster.
 */
export function usePodNodeIndex(scope?: string): PodNodeIndex {
  const { items, isLoading } = useK8sWatch<Pod>(corePaths.pods(scope));
  const index = useMemo(() => {
    const m = new Map<string, Entry>();
    for (const p of items) {
      const app = p.metadata.labels?.[APP_LABEL];
      if (!app) continue;
      const key = `${p.metadata.namespace ?? ""}/${app}`;
      const e = m.get(key) ?? { nodes: new Set<string>(), ready: 0, total: 0 };
      e.total += 1;
      if (p.spec?.nodeName) e.nodes.add(p.spec.nodeName);
      if (podIsReady(p)) e.ready += 1;
      m.set(key, e);
    }
    return m;
  }, [items]);

  return useMemo(
    () => ({
      nodesForApp: (ns, name) =>
        name ? [...(index.get(`${ns ?? ""}/${name}`)?.nodes ?? [])] : [],
      statsForApp: (ns, name) => {
        const e = name ? index.get(`${ns ?? ""}/${name}`) : undefined;
        return { ready: e?.ready ?? 0, total: e?.total ?? 0 };
      },
      loaded: !isLoading,
    }),
    [index, isLoading],
  );
}
