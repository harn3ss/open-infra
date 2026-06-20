import { useMemo } from "react";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { corePaths } from "@/lib/k8s-paths";
import { offlineNodeNames } from "@/lib/node-health";
import type { Node } from "@/types/k8s";

export interface NodeHealth {
  /** Names of nodes that are NotReady/Unknown. */
  offlineNodes: Set<string>;
  /** True when the given node is offline (false for undefined / unknown nodes). */
  isOffline: (nodeName?: string) => boolean;
  /** False until the first node list has loaded — avoids flagging during load. */
  loaded: boolean;
}

/**
 * Live view of which cluster nodes are offline. Backed by the same node watch
 * the Nodes page uses, so it shares the query cache (no extra API load).
 */
export function useNodeHealth(): NodeHealth {
  const { items, isLoading } = useK8sWatch<Node>(corePaths.nodes());
  const offlineNodes = useMemo(() => offlineNodeNames(items), [items]);
  return useMemo(
    () => ({
      offlineNodes,
      isOffline: (n?: string) => (n ? offlineNodes.has(n) : false),
      loaded: !isLoading,
    }),
    [offlineNodes, isLoading],
  );
}
