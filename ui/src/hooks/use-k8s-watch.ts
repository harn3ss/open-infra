import { useEffect, useMemo, useState } from "react";
import {
  useQuery,
  useQueryClient,
  type QueryKey,
} from "@tanstack/react-query";
import { k8sList, watchUrl } from "@/lib/api";
import { withAccountScope } from "@/lib/account-scope";
import { applyWatchEvents } from "@/lib/watch-events";
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

/** How long live events gather before they are applied together (see the watch effect). */
const FLUSH_MS = 500;

/** A stable react-query key for a watched list path. */
export function watchQueryKey(path: string): QueryKey {
  return ["k8s-watch", path];
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
 * Pass `enabled = false` to skip entirely. `accountScope` lists an
 * all-namespaces path for the caller's account only (lib/account-scope.ts):
 * what a user view lists.
 */
export function useK8sWatch<T extends K8sObject = K8sObject>(
  path: string,
  options?: { enabled?: boolean; accountScope?: boolean },
): UseK8sWatchResult<T> {
  const enabled = options?.enabled ?? true;
  const accountScope = options?.accountScope ?? false;
  const queryClient = useQueryClient();
  // Stable across renders for the same path so the watch effect isn't torn
  // down and recreated each render. The account-scoped list is its own entry
  // (a create invalidates both: watchQueryKey(path) is a prefix of it).
  const key = useMemo<QueryKey>(
    () => (accountScope ? [...watchQueryKey(path), "account"] : watchQueryKey(path)),
    [path, accountScope],
  );
  const [live, setLive] = useState(false);

  const query = useQuery<K8sList<T>>({
    queryKey: key,
    queryFn: () => k8sList<T>(accountScope ? withAccountScope(path) : path),
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

    // Events are applied in batches (lib/watch-events.ts): a busy list changes many times a second, and
    // applying each event on its own copied the whole list and re-rendered every consumer each time. They
    // queue and are applied together at most every FLUSH_MS, in arrival order.
    let queue: WatchEvent<T>[] = [];
    let flushTimer: ReturnType<typeof setTimeout> | null = null;
    const flush = () => {
      if (flushTimer) clearTimeout(flushTimer);
      flushTimer = null;
      const batch = queue;
      queue = [];
      if (batch.length === 0) return;
      queryClient.setQueryData<K8sList<T>>(key, (prev) => (prev ? applyWatchEvents(prev, batch) : prev));
    };
    const applyEvent = (evt: WatchEvent<T>) => {
      queue.push(evt);
      if (!flushTimer) flushTimer = setTimeout(flush, FLUSH_MS);
    };

    const connect = (rv: string) => {
      if (cancelled) return;
      source = new EventSource(watchUrl(path, rv, { accountScope }));

      source.onopen = () => {
        attempts = 0;
        setLive(true);
      };

      // The BFF emits a named `expired` event when the RV is too old (k8s 410
      // Gone). Relist from scratch, then reconnect from the fresh RV.
      source.addEventListener("expired", () => {
        setLive(false);
        source?.close();
        queue = []; // the relist supersedes them
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
        flush(); // reconnect from the latest resourceVersion received
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
      if (flushTimer) clearTimeout(flushTimer);
      source?.close();
    };
  }, [enabled, hasInitialList, path, queryClient, key, accountScope]);

  return {
    items: query.data?.items ?? [],
    isLoading: query.isLoading,
    isError: query.isError,
    error: query.error,
    live,
    refetch: () => void query.refetch(),
  };
}
