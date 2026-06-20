import { useConfig } from "@/lib/config-context";
import { EmptyState } from "@/components/common/states";

/**
 * Embeds a Grafana dashboard (kiosk mode) via the same-origin /grafana proxy.
 * `vars` become Grafana template variables, e.g. { "var-namespace": "ai" }.
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
    refresh: "30s",
    ...(vars ?? {}),
  });
  // Bare `kiosk` (not kiosk=) hides Grafana's nav/top bar.
  const src = `${base}/d/${uid}?${params.toString()}&kiosk`;
  return (
    <iframe
      src={src}
      title="Grafana dashboard"
      className="w-full rounded-md border border-border"
      style={{ height }}
    />
  );
}
