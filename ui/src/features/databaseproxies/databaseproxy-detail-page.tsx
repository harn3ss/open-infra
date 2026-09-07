import { useNavigate, useParams, Link } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { DatabaseZap, Info } from "lucide-react";
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
import type { Condition, DatabaseProxy } from "@/types/k8s";

function proxyStatus(p: DatabaseProxy): { label: string; tone: StatusTone } {
  const ready = p.status?.conditions?.find((c: Condition) => c.type === "Ready");
  if (ready?.status === "True") return { label: "Available", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

export function DatabaseProxyDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const path = openinfraPaths.databaseproxy(namespace, name);

  const { data: proxy, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["databaseproxy", namespace, name],
    queryFn: () => k8sGet<DatabaseProxy>(path),
    refetchInterval: 5000,
  });

  const del = useMutation({
    mutationFn: () => k8sDelete(path),
    onSuccess: () => navigate({ to: "/database-proxies" }),
  });

  if (isLoading) return <LoadingState label="Loading database proxy…" />;
  if (isError || !proxy) return <ErrorState error={error} onRetry={refetch} />;

  const status = proxyStatus(proxy);
  const spec = proxy.spec;
  const endpoint = proxy.status?.endpoint;
  const engine = spec?.engineFamily ?? "babelfish";
  const tls = spec?.tls;

  return (
    <DetailShell
      backTo="/database-proxies"
      backLabel="Database Proxies"
      icon={<DatabaseZap className="size-5" />}
      title={name}
      subtitle={`Database proxy · ${namespace}`}
      status={status}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
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
                    label: "Target database",
                    value: spec?.targetDatabase ? (
                      <Link
                        to="/databases/managed/$namespace/$name"
                        params={{ namespace, name: spec.targetDatabase }}
                        className="text-primary hover:underline"
                      >
                        {spec.targetDatabase}
                      </Link>
                    ) : null,
                  },
                  {
                    label: "Engine family",
                    value: <code className="text-xs">{engine}</code>,
                  },
                  {
                    label: "Endpoint",
                    value: endpoint ? (
                      <span className="inline-flex items-center gap-1">
                        <code className="text-xs">{endpoint}</code>
                        <CopyButton value={endpoint} />
                      </span>
                    ) : (
                      <span className="text-muted-foreground">provisioning…</span>
                    ),
                  },
                  {
                    label: "Max pool size",
                    value: <span>{spec?.poolMax ?? 20} conns / credential</span>,
                  },
                  {
                    label: "Acquire timeout",
                    value: <span>{spec?.acquireTimeoutMs ?? 10000} ms</span>,
                  },
                  {
                    label: "Replicas",
                    value: <span>{spec?.replicas ?? 1}</span>,
                  },
                  {
                    label: "Client TLS",
                    value: tls?.terminate ? (
                      <span>
                        Terminated
                        {tls.issuerRef?.name ? (
                          <span className="text-muted-foreground">
                            {" "}· {tls.issuerRef.kind ?? "ClusterIssuer"} <code className="text-xs">{tls.issuerRef.name}</code>
                          </span>
                        ) : null}
                        {tls.dnsNames?.length ? (
                          <span className="text-muted-foreground"> · SANs {tls.dnsNames.join(", ")}</span>
                        ) : null}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">Disabled (plaintext TDS)</span>
                    ),
                  },
                  {
                    label: "Status",
                    value: <StatusBadge status={status.label} tone={status.tone} />,
                  },
                ]}
              />
            </CardContent>
          </Card>

          <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
            <Info className="mt-0.5 size-4 shrink-0" />
            <span>
              This is an <span className="font-medium text-foreground">RDS Proxy</span>-style pool: clients connect to the endpoint
              above instead of the database directly. It terminates each client login, reuses warm backend connections, and caps
              concurrency at <span className="font-medium text-foreground">{spec?.poolMax ?? 20}</span> per credential — smoothing
              connection storms and speeding reconnects for the managed <code className="text-xs">{engine}</code> database.
            </span>
          </div>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={proxy} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Database Proxy"
            resourceName={name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>Permanently delete database proxy <span className="font-medium text-foreground">{name}</span>. Point any clients back at the database's own endpoint first — the pooled endpoint above will stop answering.</>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
