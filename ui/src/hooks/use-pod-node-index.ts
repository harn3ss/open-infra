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

export interface PodNodeIndex {
  /**
   * Node names hosting pods labeled `app.kubernetes.io/name=<name>` in
   * `<namespace>`. Empty when the claim has no scheduled pods (e.g. scaled to
   * zero) or none could be found in the watched scope.
   */
  nodesForApp: (namespace: string | undefined, name: string | undefined) => string[];
  loaded: boolean;
}

/**
 * Indexes pods in `scope` by their `app.kubernetes.io/name` label so callers can
 * ask "which node(s) is claim X running on?". Pass a concrete namespace to keep
 * the watch small; pass undefined to index the whole cluster.
 */
export function usePodNodeIndex(scope?: string): PodNodeIndex {
  const { items, isLoading } = useK8sWatch<Pod>(corePaths.pods(scope));
  const index = useMemo(() => {
    const m = new Map<string, Set<string>>();
    for (const p of items) {
      const app = p.metadata.labels?.[APP_LABEL];
      const node = p.spec?.nodeName;
      if (!app || !node) continue;
      const key = `${p.metadata.namespace ?? ""}/${app}`;
      const set = m.get(key) ?? new Set<string>();
      set.add(node);
      m.set(key, set);
    }
    return m;
  }, [items]);

  return useMemo(
    () => ({
      nodesForApp: (ns, name) =>
        name ? [...(index.get(`${ns ?? ""}/${name}`) ?? [])] : [],
      loaded: !isLoading,
    }),
    [index, isLoading],
  );
}
