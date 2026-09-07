import { useEffect, useSyncExternalStore } from "react";
import { useRouter, type AnyRouter } from "@tanstack/react-router";
import {
  SERVICES,
  serviceForPath,
  type Service,
} from "@/components/layout/nav-items";

/**
 * "Recently visited services" — the signature AWS Console Home widget.
 *
 * We persist the list of visited *services* (by their landing route, a stable
 * unique id) in localStorage, most-recent-first. Recording is driven by a single
 * subscription installed on the singleton router the first time this hook mounts
 * (on the dashboard, the post-login landing): because the subscription lives on
 * the router — not on the dashboard component — it keeps recording every
 * navigation even after the user leaves the dashboard for a service. Home ("/")
 * and any unrooted path resolve to no service and are ignored.
 */

const STORAGE_KEY = "openinfra.dashboard.recentServices";
/** How many services to retain in the store (widget shows a subset). */
const MAX = 8;

// ── Module-scoped store (wrap-safe; survives dashboard mount/unmount) ─────────

type Listener = () => void;
const listeners = new Set<Listener>();
/** Cached snapshot: service landing routes, most-recent-first. */
let cache: string[] | null = null;

function load(): string[] {
  if (cache) return cache;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    cache = Array.isArray(parsed)
      ? parsed.filter((x): x is string => typeof x === "string")
      : [];
  } catch {
    // private mode / disabled storage / bad JSON — start empty, keep working.
    cache = [];
  }
  return cache;
}

function persist(next: string[]): void {
  cache = next; // new identity so useSyncExternalStore sees a change
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  } catch {
    // Quota or disabled storage — keep the in-memory cache; UI still updates.
  }
  for (const l of listeners) l();
}

/** Record a visit to whatever service owns `pathname` (no-op for home/unknown). */
export function recordVisit(pathname: string): void {
  const svc = serviceForPath(pathname);
  if (!svc) return; // home dashboard or an unrooted path — not a service
  const key = svc.to;
  const current = load();
  if (current[0] === key) return; // already the most recent — nothing to do
  persist([key, ...current.filter((k) => k !== key)].slice(0, MAX));
}

let recorderInstalled = false;
/** Install the router subscription exactly once for the app's lifetime. */
function ensureRecorder(router: AnyRouter): void {
  if (recorderInstalled) return;
  recorderInstalled = true;
  recordVisit(router.state.location.pathname); // capture the entry location
  router.subscribe("onResolved", ({ toLocation }) => {
    recordVisit(toLocation.pathname);
  });
}

function subscribe(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function getSnapshot(): string[] {
  return load();
}

// ── Hook ─────────────────────────────────────────────────────────────────────

/**
 * Returns the recently-visited services, most-recent-first, resolved to live
 * `Service` objects (stale entries whose service no longer exists are dropped)
 * and capped to `limit`. Mount it on the dashboard; it also installs the global
 * recorder on first mount.
 */
export function useRecentlyVisited(limit = 6): Service[] {
  const router = useRouter();
  useEffect(() => {
    ensureRecorder(router);
  }, [router]);

  const routes = useSyncExternalStore(subscribe, getSnapshot, getSnapshot);

  const byRoute = new Map(SERVICES.map((s) => [s.to, s] as const));
  const resolved: Service[] = [];
  for (const to of routes) {
    const svc = byRoute.get(to);
    if (svc) resolved.push(svc);
    if (resolved.length >= limit) break;
  }
  return resolved;
}
