import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ExternalLink, LineChart } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState } from "@/components/common/states";
import { useConfig } from "@/lib/config-context";
import { useTheme } from "@/lib/theme";

/** A Grafana dashboard as returned by /api/search (via the BFF). */
interface GrafanaDashboard {
  uid: string;
  title: string;
  folderTitle?: string;
}

/**
 * Embeds Grafana dashboards via an iframe in kiosk mode (chrome hidden). The
 * base URL comes from /api/config at runtime — never hardcoded. The dashboard
 * list is fetched through the BFF (/api/grafana/dashboards) to avoid CORS, and
 * the user can pick which dashboard to view; we default to a cluster overview.
 */
export function MonitoringPage() {
  const { grafanaBaseUrl } = useConfig();
  const { theme } = useTheme();
  const hasGrafana = Boolean(grafanaBaseUrl && grafanaBaseUrl.trim());

  const { data: dashboards = [], isLoading } = useQuery({
    queryKey: ["grafana-dashboards"],
    enabled: hasGrafana,
    staleTime: 60_000,
    queryFn: async (): Promise<GrafanaDashboard[]> => {
      const res = await fetch("/api/grafana/dashboards");
      if (!res.ok) throw new Error(`dashboards: HTTP ${res.status}`);
      const raw = (await res.json()) as GrafanaDashboard[];
      return raw.map((d) => ({ uid: d.uid, title: d.title, folderTitle: d.folderTitle }));
    },
  });

  // Prefer a cluster-overview dashboard, else anything "cluster", else the first.
  const defaultUid = useMemo(() => {
    const pick =
      dashboards.find((d) => /compute resources \/ cluster/i.test(d.title)) ??
      dashboards.find((d) => /cluster/i.test(d.title)) ??
      dashboards[0];
    return pick?.uid ?? "";
  }, [dashboards]);

  const [picked, setPicked] = useState("");
  const uid = picked || defaultUid;

  const base = hasGrafana ? grafanaBaseUrl.trim().replace(/\/+$/, "") : "";
  const themeParam = theme === "dark" ? "dark" : "light";
  // Bare `kiosk` (not kiosk=) is what hides Grafana's nav + top bar.
  const src = uid
    ? `${base}/d/${uid}?orgId=1&theme=${themeParam}&kiosk&refresh=30s`
    : `${base}/?orgId=1&theme=${themeParam}&kiosk`;

  // Group dashboards by folder for the picker.
  const grouped = useMemo(() => {
    const m = new Map<string, GrafanaDashboard[]>();
    for (const d of dashboards) {
      const k = d.folderTitle || "General";
      (m.get(k) ?? m.set(k, []).get(k)!).push(d);
    }
    return [...m.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [dashboards]);

  return (
    <div className="flex h-[calc(100vh-7rem)] flex-col space-y-4">
      <PageHeader
        icon={<LineChart />}
        title="Monitoring"
        description="Metrics and dashboards via Grafana (Prometheus + Loki)."
        actions={
          hasGrafana ? (
            <div className="flex items-center gap-2">
              {dashboards.length > 0 && (
                <select
                  aria-label="Dashboard"
                  value={uid}
                  onChange={(e) => setPicked(e.target.value)}
                  className="h-9 max-w-[20rem] rounded-md border border-input bg-background px-3 text-sm text-foreground shadow-sm outline-none focus:ring-2 focus:ring-ring"
                >
                  {grouped.map(([folder, items]) => (
                    <optgroup key={folder} label={folder}>
                      {items.map((d) => (
                        <option key={d.uid} value={d.uid}>
                          {d.title}
                        </option>
                      ))}
                    </optgroup>
                  ))}
                </select>
              )}
              <Button variant="outline" asChild>
                <a href={uid ? `${base}/d/${uid}` : base} target="_blank" rel="noreferrer">
                  Open in Grafana
                  <ExternalLink className="size-4" />
                </a>
              </Button>
            </div>
          ) : null
        }
      />

      {hasGrafana ? (
        <Card className="flex-1 overflow-hidden p-0">
          <CardContent className="h-full p-0">
            {isLoading && dashboards.length === 0 ? (
              <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                Loading dashboards…
              </div>
            ) : (
              <iframe
                key={src}
                title="Grafana dashboards"
                src={src}
                className="h-full w-full border-0"
                // Grafana needs scripts + same-origin to render embedded.
                sandbox="allow-scripts allow-same-origin allow-popups allow-forms"
              />
            )}
          </CardContent>
        </Card>
      ) : (
        <Card className="flex-1">
          <CardContent className="flex h-full items-center justify-center p-6">
            <EmptyState
              icon={<LineChart className="size-6" />}
              title="Grafana isn’t configured"
              description="No grafanaBaseUrl was returned by /api/config. Set it in your open-infra config (it’s served to the console at runtime) to embed dashboards here."
            />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
