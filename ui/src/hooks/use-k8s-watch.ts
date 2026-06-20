import { useEffect, useMemo, useState } from "react";
import {
  useQuery,
  useQueryClient,
  type QueryKey,
} from "@tanstack/react-query";
import { k8sList, watchUrl } from "@/lib/api";
import type { K8sList, K8sObject, WatchEvent } from "@/types/k8s";

export interface UseK8sWatchResult<T extends K8sObject> {
  items: T[];
  isLoading: boolean;
  isError: boolean;
  error: unknown;
  /** True once the live SSE stream is connected. */
  live: boolean;
  refetch: () => void;
}

/** A stable react-query key for a watched list path. */
export function watchQueryKey(path: string): QueryKey {
  return ["k8s-watch", path];
}

function uidOf(obj: K8sObject): string {
  return (
    obj.metadata.uid ??
    `${obj.metadata.namespace ?? ""}/${obj.metadata.name}`
  );
}

/**
 * Live list of a Kubernetes resource.
 *
 * 1. Initial list via react-query (so we get loading/error states + caching).
 * 2. An EventSource (SSE) opened against the BFF /api/watch endpoint, starting
 *    at the list's resourceVersion. ADDED/MODIFIED/DELETED events are merged
 *    into the same query cache entry with queryClient.setQueryData, so every
 *    consumer of this key updates without refetching.
 * 3. On an `expired` event (HTTP 410 / compacted resourceVersion), we relist.
 *
 * `path` is a k8s list path (without the /api/k8s prefix), e.g. /api/v1/pods.
 * Pass `enabled = false` to skip entirely.
 */
export function useK8sWatch<T extends K8sObject = K8sObject>(
  path: string,
  options?: { enabled?: boolean },
): UseK8sWatchResult<T> {
  const enabled = options?.enabled ?? true;
  const queryClient = useQueryClient();
  // Stable across renders for the same path so the watch effect isn't torn
  // down and recreated each render.
  const key = useMemo<QueryKey>(() => watchQueryKey(path), [path]);
  const [live, setLive] = useState(false);

  const query = useQuery<K8sList<T>>({
    queryKey: key,
    queryFn: () => k8sList<T>(path),
    enabled,
  });

  // Gate the watch on *having* an initial list, not on the RV value itself.
  // The RV advances on every event (we write it back into the cache); keying
  // the effect on a boolean keeps the EventSource stable instead of
  // reconnecting on each event.
  const hasInitialList = Boolean(query.data?.metadata?.resourceVersion);

  useEffect(() => {
    if (!enabled || !hasInitialList) return;

    // Read the freshest RV from cache at connect time.
    const initialRv =
      queryClient.getQueryData<K8sList<T>>(key)?.metadata?.resourceVersion;
    if (!initialRv) return;

    let cancelled = false;
    let source: EventSource | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let attempts = 0;

    const applyEvent = (evt: WatchEvent<T>) => {
      queryClient.setQueryData<K8sList<T>>(key, (prev) => {
        if (!prev) return prev;
        const incoming = evt.object;
        const nextRv =
          incoming.metadata?.resourceVersion ?? prev.metadata.resourceVersion;

        // BOOKMARK events (and any payload without a name/uid) are
        // resourceVersion checkpoints, not resources. Advance the RV but never
        // add them to the list — otherwise they render as phantom rows/cards
        // (e.g. a nameless "NotReady" node, or apps that appear to spawn).
        if (
          evt.type === "BOOKMARK" ||
          (!incoming.metadata?.name && !incoming.metadata?.uid)
        ) {
          return {
            ...prev,
            metadata: { ...prev.metadata, resourceVersion: nextRv },
          };
        }

        const incomingUid = uidOf(incoming);
        let items = prev.items;

        if (evt.type === "DELETED") {
          items = items.filter((it) => uidOf(it) !== incomingUid);
        } else {
          // ADDED or MODIFIED — upsert by uid.
          const idx = items.findIndex((it) => uidOf(it) === incomingUid);
          if (idx === -1) {
            items = [...items, incoming];
          } else {
            items = items.slice();
            items[idx] = incoming;
          }
        }

        return {
          ...prev,
          metadata: { ...prev.metadata, resourceVersion: nextRv },
          items,
        };
      });
    };

    const connect = (rv: string) => {
      if (cancelled) return;
      source = new EventSource(watchUrl(path, rv));

      source.onopen = () => {
        attempts = 0;
        setLive(true);
      };

      // The BFF emits a named `expired` event when the RV is too old (k8s 410
      // Gone). Relist from scratch, then reconnect from the fresh RV.
      source.addEventListener("expired", () => {
        setLive(false);
        source?.close();
        void queryClient
          .refetchQueries({ queryKey: key })
          .then(() => {
            if (cancelled) return;
            const fresh =
              queryClient.getQueryData<K8sList<T>>(key)?.metadata
                ?.resourceVersion;
            if (fresh) connect(fresh);
          });
      });

      source.onmessage = (e: MessageEvent<string>) => {
        if (!e.data) return;
        try {
          const evt = JSON.parse(e.data) as WatchEvent<T>;
          if (evt && evt.type && evt.object) applyEvent(evt);
        } catch {
          /* ignore malformed frames */
        }
      };

      source.onerror = () => {
        setLive(false);
        source?.close();
        if (cancelled) return;
        // Exponential-ish backoff, capped.
        attempts += 1;
        const delay = Math.min(1000 * 2 ** Math.min(attempts, 4), 15000);
        reconnectTimer = setTimeout(() => {
          // Reconnect from the latest known RV in cache.
          const latest = queryClient.getQueryData<K8sList<T>>(key);
          connect(latest?.metadata?.resourceVersion ?? rv);
        }, delay);
      };
    };

    connect(initialRv);

    return () => {
      cancelled = true;
      setLive(false);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      source?.close();
    };
  }, [enabled, hasInitialList, path, queryClient, key]);

  return {
    items: query.data?.items ?? [],
    isLoading: query.isLoading,
    isError: query.isError,
    error: query.error,
    live,
    refetch: () => void query.refetch(),
  };
}
