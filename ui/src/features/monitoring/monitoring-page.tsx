import { ExternalLink, LineChart } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState } from "@/components/common/states";
import { useConfig } from "@/lib/config-context";
import { useTheme } from "@/lib/theme";

/**
 * Embeds Grafana via an iframe in kiosk mode. The base URL comes from
 * /api/config at runtime — never hardcoded. If it's empty, we explain how to
 * enable it instead of rendering a broken frame.
 */
export function MonitoringPage() {
  const { grafanaBaseUrl } = useConfig();
  const { theme } = useTheme();

  const hasGrafana = Boolean(grafanaBaseUrl && grafanaBaseUrl.trim());

  // Build a kiosk-mode URL, preserving any path already in the base URL.
  const src = hasGrafana
    ? (() => {
        try {
          const url = new URL(grafanaBaseUrl, window.location.origin);
          url.searchParams.set("kiosk", "");
          url.searchParams.set("theme", theme === "dark" ? "dark" : "light");
          return url.toString();
        } catch {
          return grafanaBaseUrl;
        }
      })()
    : "";

  return (
    <div className="flex h-[calc(100vh-7rem)] flex-col space-y-4">
      <PageHeader
        icon={<LineChart />}
        title="Monitoring"
        description="Metrics and dashboards via Grafana (Prometheus + Loki)."
        actions={
          hasGrafana ? (
            <Button variant="outline" asChild>
              <a href={grafanaBaseUrl} target="_blank" rel="noreferrer">
                Open in Grafana
                <ExternalLink className="size-4" />
              </a>
            </Button>
          ) : null
        }
      />

      {hasGrafana ? (
        <Card className="flex-1 overflow-hidden p-0">
          <CardContent className="h-full p-0">
            <iframe
              key={src}
              title="Grafana dashboards"
              src={src}
              className="h-full w-full border-0"
              // Grafana needs scripts + same-origin to render embedded.
              sandbox="allow-scripts allow-same-origin allow-popups allow-forms"
            />
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
