/**
 * Applying live watch events to a cached list, cheaply.
 *
 * A busy list (an account's events, its pods) changes many times a second. useK8sWatch queues the events
 * that arrive and applies them together a few times a second with applyWatchEvents: one pass over the
 * batch with a uid index, one copy of the list, and one re-render of its consumers per batch, where each
 * event used to scan and copy the whole list and re-render everything on the page.
 *
 * Kept free of runtime imports so `npm test` (node --test with type stripping) can load it directly.
 */
import type { K8sList, K8sObject, WatchEvent } from "@/types/k8s";

/** An object's identity in a list: its uid, else namespace/name. */
export function uidOf(obj: K8sObject): string {
  return obj.metadata.uid ?? `${obj.metadata.namespace ?? ""}/${obj.metadata.name}`;
}

/**
 * prev with events applied in order: ADDED/MODIFIED upsert by uid, DELETED removes, and every event
 * advances the list's resourceVersion. A BOOKMARK (or any payload without a name or uid) is a
 * resourceVersion checkpoint, never a row. The items array is the same one when nothing in it changed.
 */
export function applyWatchEvents<T extends K8sObject>(prev: K8sList<T>, events: WatchEvent<T>[]): K8sList<T> {
  let rv = prev.metadata.resourceVersion;
  let items: (T | undefined)[] | null = null; // copied on the first change
  let index: Map<string, number> | null = null;
  let removed = false;
  for (const evt of events) {
    const incoming = evt.object;
    rv = incoming.metadata?.resourceVersion ?? rv;
    if (evt.type === "BOOKMARK" || (!incoming.metadata?.name && !incoming.metadata?.uid)) continue;
    if (items === null || index === null) {
      items = prev.items.slice();
      index = new Map(prev.items.map((it, i) => [uidOf(it), i] as [string, number]));
    }
    const uid = uidOf(incoming);
    const at = index.get(uid);
    if (evt.type === "DELETED") {
      if (at !== undefined) {
        items[at] = undefined;
        index.delete(uid);
        removed = true;
      }
      continue;
    }
    if (at === undefined) {
      index.set(uid, items.length);
      items.push(incoming);
    } else {
      items[at] = incoming;
    }
  }
  const next = items === null ? prev.items : removed ? items.filter((x): x is T => x !== undefined) : (items as T[]);
  return { ...prev, metadata: { ...prev.metadata, resourceVersion: rv }, items: next };
}

/** The newest n of items, newest first: each one's time is read once, and the sort compares numbers. */
export function newestFirst<E>(items: E[], n: number, timeOf: (e: E) => string | undefined | null): E[] {
  return items
    .map((e) => [new Date(timeOf(e) ?? 0).getTime() || 0, e] as [number, E])
    .sort((a, b) => b[0] - a[0])
    .slice(0, n)
    .map(([, e]) => e);
}
