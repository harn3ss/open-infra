import { useCallback, useEffect, useState } from "react";

// Content density (Cloudscape-style): comfortable (default) or compact. Persisted,
// applied as data-density on <html>; the compact CSS tightens data-dense views
// (tables) only — menus, alerts, and forms keep readable spacing.
export type Density = "comfortable" | "compact";

const KEY = "openinfra:density";

function read(): Density {
  try {
    return localStorage.getItem(KEY) === "compact" ? "compact" : "comfortable";
  } catch {
    return "comfortable";
  }
}

function apply(d: Density) {
  if (typeof document !== "undefined") {
    document.documentElement.dataset.density = d;
  }
}

// Apply on module load so there's no flash before the settings menu mounts.
apply(read());

export function useDensity() {
  const [density, setDensityState] = useState<Density>(read);

  useEffect(() => apply(density), [density]);

  const setDensity = useCallback((d: Density) => {
    setDensityState(d);
    try {
      localStorage.setItem(KEY, d);
    } catch {
      /* ignore */
    }
  }, []);

  return { density, setDensity };
}
