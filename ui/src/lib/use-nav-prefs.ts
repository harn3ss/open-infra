import { useCallback, useState } from "react";

// Per-user navigation personalization (pinned favorites + recently visited),
// persisted to localStorage. Keyed by nav-item `to` path.
const PINS_KEY = "openinfra:nav:pins";
const RECENTS_KEY = "openinfra:nav:recents";
const RECENTS_MAX = 6;

function load(key: string): string[] {
  try {
    const raw = localStorage.getItem(key);
    const v = raw ? JSON.parse(raw) : [];
    return Array.isArray(v) ? (v as string[]) : [];
  } catch {
    return [];
  }
}

function save(key: string, v: string[]) {
  try {
    localStorage.setItem(key, JSON.stringify(v));
  } catch {
    /* ignore quota/serialization errors */
  }
}

export function useNavPrefs() {
  const [pins, setPins] = useState<string[]>(() => load(PINS_KEY));
  const [recents, setRecents] = useState<string[]>(() => load(RECENTS_KEY));

  const togglePin = useCallback((to: string) => {
    setPins((prev) => {
      const next = prev.includes(to) ? prev.filter((p) => p !== to) : [...prev, to];
      save(PINS_KEY, next);
      return next;
    });
  }, []);

  const recordVisit = useCallback((to: string) => {
    setRecents((prev) => {
      const next = [to, ...prev.filter((p) => p !== to)].slice(0, RECENTS_MAX);
      if (next.length === prev.length && next.every((v, i) => v === prev[i])) {
        return prev; // no change — avoid a re-render loop
      }
      save(RECENTS_KEY, next);
      return next;
    });
  }, []);

  return {
    pins,
    recents,
    togglePin,
    isPinned: useCallback((to: string) => pins.includes(to), [pins]),
    recordVisit,
  };
}
