import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { AppWindow, Info } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { KeyValuePairs } from "@/components/common/key-value-pairs";
import { CopyButton } from "@/components/common/copy-button";
import { StatusBadge } from "@/components/common/status-badge";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { StatusTone } from "@/lib/format";
import type { Condition, StaticSite } from "@/types/k8s";

function siteStatus(s: StaticSite): { label: string; tone: StatusTone } {
  const ready = s.status?.conditions?.find((c: Condition) => c.type === "Ready");
  if (ready?.status === "True" || s.status?.ready) return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

export function StaticSiteDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const path = openinfraPaths.staticsite(namespace, name);

  const { data: site, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["staticsite", namespace, name],
    queryFn: () => k8sGet<StaticSite>(path),
    refetchInterval: 5000,
  });

  const del = useMutation({
    mutationFn: () => k8sDelete(path),
    onSuccess: () => navigate({ to: "/staticsites" }),
  });

  if (isLoading) return <LoadingState label="Loading static site…" />;
  if (isError || !site) return <ErrorState error={error} onRetry={refetch} />;

  const status = siteStatus(site);
  const spec = site.spec;
  const url = site.status?.url;
  const bucket = site.status?.bucket ?? spec?.bucket ?? `${name}-site`;
  const spa = spec?.spa ?? true;
  const indexDocument = spec?.indexDocument ?? "index.html";
  const tls = spec?.tls ?? true;
  const syncInterval = spec?.syncIntervalSeconds ?? 30;

  return (
    <DetailShell
      backTo="/staticsites"
      backLabel="Static Sites"
      icon={<AppWindow className="size-5" />}
      title={name}
      subtitle={`Static site · ${namespace}`}
      status={status}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">
            Danger Zone
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4 pt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Details</CardTitle>
            </CardHeader>
            <CardContent>
              <KeyValuePairs
                columns={3}
                items={[
                  {
                    label: "Domain",
                    value: spec?.domain ? <code className="text-xs">{spec.domain}</code> : null,
                  },
                  {
                    label: "URL",
                    value: url ? (
                      <span className="inline-flex items-center gap-1">
                        <a
                          href={url}
                          target="_blank"
                          rel="noreferrer"
                          className="text-xs text-primary hover:underline"
                        >
                          {url}
                        </a>
                        <CopyButton value={url} />
                      </span>
                    ) : (
                      <span className="text-muted-foreground">provisioning…</span>
                    ),
                  },
                  {
                    label: "Bucket",
                    value: (
                      <span className="inline-flex items-center gap-1">
                        <code className="text-xs">{bucket}</code>
                        <CopyButton value={bucket} />
                      </span>
                    ),
                  },
                  {
                    label: "SPA routing",
                    value: spa ? "Enabled (history fallback)" : "Disabled",
                  },
                  {
                    label: "Index document",
                    value: <code className="text-xs">{indexDocument}</code>,
                  },
                  {
                    label: "Error document",
                    value: spec?.errorDocument ? (
                      <code className="text-xs">{spec.errorDocument}</code>
                    ) : spa ? (
                      <span className="text-muted-foreground">— (SPA fallback to index)</span>
                    ) : null,
                  },
                  {
                    label: "TLS",
                    value: tls ? "Enabled (cert-manager)" : "Disabled",
                  },
                  {
                    label: "Sync interval",
                    value: `${syncInterval}s`,
                  },
                  {
                    label: "Ready",
                    value: <StatusBadge status={status.label} tone={status.tone} />,
                  },
                ]}
              />
            </CardContent>
          </Card>

          {/* The point of a static site: upload your built bundle to the backing bucket. */}
          <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
            <Info className="mt-0.5 size-4 shrink-0" />
            <span>
              Upload your built site (the contents of your <code className="text-xs">dist/</code> or{" "}
              <code className="text-xs">build/</code> directory) to the{" "}
              <span className="font-medium text-foreground">{bucket}</span> bucket — from the Buckets console, or with{" "}
              <code className="text-xs">mc</code> / <code className="text-xs">aws s3</code> against the object store.
              open-infra re-syncs the bucket into the served site every {syncInterval}s.
            </span>
          </div>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={site} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Static Site"
            resourceName={name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>
                Permanently delete static site <span className="font-medium text-foreground">{name}</span>. This removes
                the serving Ingress and stops serving the site; the backing bucket{" "}
                <span className="font-medium text-foreground">{bucket}</span> and its objects are not deleted here.
              </>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
