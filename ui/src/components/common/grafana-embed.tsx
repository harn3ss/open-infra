import { useState } from "react";
import { useConfig } from "@/lib/config-context";
import { EmptyState } from "@/components/common/states";

// Auto-refresh choices for the embed — from near-live up to 2 minutes.
const REFRESH_OPTIONS = [
  { label: "Live (5s)", value: "5s" },
  { label: "10s", value: "10s" },
  { label: "30s", value: "30s" },
  { label: "1m", value: "1m" },
  { label: "2m", value: "2m" },
];

/**
 * Embeds a Grafana dashboard (kiosk mode) via the same-origin /grafana proxy.
 * `vars` become Grafana template variables, e.g. { "var-namespace": "ai" }.
 * A picker controls the panel auto-refresh interval (live → 2m).
 */
export function GrafanaEmbed({
  uid,
  vars,
  height = 560,
}: {
  uid: string;
  vars?: Record<string, string>;
  height?: number;
}) {
  const { grafanaBaseUrl } = useConfig();
  const [refresh, setRefresh] = useState("30s");
  const base = grafanaBaseUrl?.trim().replace(/\/+$/, "");
  if (!base) {
    return (
      <EmptyState
        title="Metrics unavailable"
        description="Grafana is not configured for this console (no grafanaBaseUrl)."
      />
    );
  }
  const params = new URLSearchParams({
    orgId: "1",
    theme: "dark",
    refresh,
    ...(vars ?? {}),
  });
  // Bare `kiosk` (not kiosk=) hides Grafana's nav/top bar.
  const src = `${base}/d/${uid}?${params.toString()}&kiosk`;
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-end gap-2">
        <label
          htmlFor={`refresh-${uid}`}
          className="text-xs text-muted-foreground"
        >
          Auto-refresh
        </label>
        <select
          id={`refresh-${uid}`}
          value={refresh}
          onChange={(e) => setRefresh(e.target.value)}
          className="rounded-md border border-border bg-background px-2 py-1 text-xs"
        >
          {REFRESH_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </div>
      <iframe
        // key forces a reload when the refresh interval changes.
        key={refresh}
        src={src}
        title="Grafana dashboard"
        className="w-full rounded-md border border-border"
        style={{ height }}
      />
    </div>
  );
}
