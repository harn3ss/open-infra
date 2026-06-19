/** Small presentation helpers shared across resource views. */

/** Compact "age" like kubectl: 5d, 3h, 12m, 8s. */
export function age(timestamp?: string): string {
  if (!timestamp) return "—";
  const then = new Date(timestamp).getTime();
  if (Number.isNaN(then)) return "—";
  let secs = Math.max(0, Math.floor((Date.now() - then) / 1000));

  const d = Math.floor(secs / 86400);
  secs -= d * 86400;
  const h = Math.floor(secs / 3600);
  secs -= h * 3600;
  const m = Math.floor(secs / 60);
  const s = secs - m * 60;

  if (d > 0) return h > 0 ? `${d}d${h}h` : `${d}d`;
  if (h > 0) return m > 0 ? `${h}h${m}m` : `${h}h`;
  if (m > 0) return `${m}m`;
  return `${s}s`;
}

/** Absolute, human timestamp for tooltips/detail views. */
export function formatTimestamp(timestamp?: string): string {
  if (!timestamp) return "—";
  const d = new Date(timestamp);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

/** A semantic tone used by status badges across the app. */
export type StatusTone =
  | "success"
  | "warning"
  | "destructive"
  | "muted"
  | "default"
  | "accent";

/** Map a free-form k8s phase/status string to a badge tone. */
export function statusTone(value: string | undefined): StatusTone {
  if (!value) return "muted";
  const v = value.toLowerCase();
  if (
    ["running", "active", "ready", "available", "succeeded", "healthy", "bound", "true"].includes(
      v,
    )
  ) {
    return "success";
  }
  if (["pending", "progressing", "updating", "containercreating", "terminating"].includes(v)) {
    return "warning";
  }
  if (
    [
      "failed",
      "error",
      "crashloopbackoff",
      "imagepullbackoff",
      "errimagepull",
      "unhealthy",
      "evicted",
      "oomkilled",
      "notready",
      "unschedulable",
      "false",
    ].includes(v)
  ) {
    return "destructive";
  }
  return "muted";
}

/**
 * Parse a Kubernetes quantity (e.g. "2", "500m", "4Gi", "1024Ki") into a
 * number of base units. CPU is returned in cores, memory in bytes.
 */
export function parseQuantity(q?: string): number {
  if (!q) return 0;
  const match = /^([0-9.]+)\s*([a-zA-Z]*)$/.exec(q.trim());
  if (!match) return Number(q) || 0;
  const value = Number(match[1]);
  const unit = match[2] ?? "";
  const binary: Record<string, number> = {
    Ki: 2 ** 10,
    Mi: 2 ** 20,
    Gi: 2 ** 30,
    Ti: 2 ** 40,
    Pi: 2 ** 50,
  };
  const decimal: Record<string, number> = {
    n: 1e-9,
    u: 1e-6,
    m: 1e-3,
    k: 1e3,
    M: 1e6,
    G: 1e9,
    T: 1e12,
    P: 1e15,
  };
  if (unit in binary) return value * (binary[unit] as number);
  if (unit in decimal) return value * (decimal[unit] as number);
  return value;
}

export function formatBytes(bytes: number): string {
  if (!bytes) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  const i = Math.min(
    units.length - 1,
    Math.floor(Math.log(bytes) / Math.log(1024)),
  );
  return `${(bytes / 1024 ** i).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/** Pick the most recent timestamp from a k8s Event. */
export function eventTime(e: {
  lastTimestamp?: string;
  eventTime?: string;
  firstTimestamp?: string;
  metadata?: { creationTimestamp?: string };
}): string | undefined {
  return (
    e.lastTimestamp ??
    e.eventTime ??
    e.firstTimestamp ??
    e.metadata?.creationTimestamp
  );
}
