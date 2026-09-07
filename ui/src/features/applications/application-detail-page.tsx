import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Boxes, ExternalLink } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { KeyValuePairs } from "@/components/common/key-value-pairs";
import { KeyValueList } from "@/components/common/detail-row";
import { Badge } from "@/components/ui/badge";
import { CopyButton } from "@/components/common/copy-button";
import { StatusBadge } from "@/components/common/status-badge";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { GrafanaEmbed } from "@/components/common/grafana-embed";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { ResourceSecurityTab } from "@/components/common/resource-security-tab";
import {
  applicationHealth,
  conditionTone,
} from "@/features/applications/application-status";
import { k8sDelete, k8sGet, k8sReplace } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age, formatTimestamp } from "@/lib/format";
import type { Application } from "@/types/k8s";

export function ApplicationDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const appPath = openinfraPaths.application(namespace, name);

  const { data: app, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["application", namespace, name],
    queryFn: () => k8sGet<Application>(appPath),
    refetchInterval: 5000,
  });

  const del = useMutation({
    mutationFn: () => k8sDelete(appPath),
    onSuccess: () => navigate({ to: "/applications" }),
  });

  const saveSgs = useMutation({
    mutationFn: async (next: string[]) => {
      const cur = await k8sGet<Application>(appPath);
      return k8sReplace<Application>(appPath, {
        ...cur,
        spec: { ...(cur.spec ?? {}), securityGroups: next },
      } as Application);
    },
    onSuccess: () => void refetch(),
  });

  if (isLoading) return <LoadingState label="Loading application…" />;
  if (isError || !app) return <ErrorState error={error} onRetry={refetch} />;

  const s = app.spec;
  const health = applicationHealth(app);
  const url = app.status?.url;
  const conditions = app.status?.conditions ?? [];

  const buckets = s?.storage?.buckets ?? [];
  const queues = s?.queues ?? [];
  const secrets = s?.secrets ?? [];
  const env = s?.env ?? [];

  return (
    <DetailShell
      backTo="/applications"
      backLabel="Applications"
      icon={<Boxes className="size-5" />}
      title={name}
      subtitle={`Application · ${namespace}`}
      status={health}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="resources">Resources</TabsTrigger>
          <TabsTrigger value="environment">
            Environment ({env.length})
          </TabsTrigger>
          <TabsTrigger value="conditions">
            Conditions ({conditions.length})
          </TabsTrigger>
          <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger
            value="danger"
            className="text-destructive data-[state=active]:text-destructive"
          >
            Danger Zone
          </TabsTrigger>
        </TabsList>

        {/* Overview — service configuration at a glance (ECS/App Runner "Configuration"). */}
        <TabsContent value="overview" className="space-y-4 pt-4">
          <Card>
            <CardContent className="p-5">
              <KeyValuePairs
                columns={3}
                items={[
                  {
                    label: "Status",
                    value: (
                      <StatusBadge status={health.label} tone={health.tone} />
                    ),
                  },
                  {
                    label: "Endpoint",
                    value: url ? (
                      <span className="inline-flex items-center gap-1.5">
                        <a
                          href={url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 break-all font-medium text-accent hover:underline"
                        >
                          {url}
                          <ExternalLink className="size-3.5 shrink-0" />
                        </a>
                        <CopyButton value={url} />
                      </span>
                    ) : (
                      ""
                    ),
                  },
                  {
                    label: "Image",
                    value: s?.image ? (
                      <span className="inline-flex items-center gap-1.5">
                        <code className="break-all text-xs">{s.image}</code>
                        <CopyButton value={s.image} />
                      </span>
                    ) : (
                      ""
                    ),
                  },
                  { label: "Port", value: s?.port ?? "" },
                  {
                    label: "Domain",
                    value: s?.domain ? (
                      <code className="break-all text-xs">{s.domain}</code>
                    ) : (
                      ""
                    ),
                  },
                  { label: "Namespace", value: namespace },
                  {
                    label: "Created",
                    value: app.metadata.creationTimestamp ? (
                      <span title={formatTimestamp(app.metadata.creationTimestamp)}>
                        {age(app.metadata.creationTimestamp)} ago
                      </span>
                    ) : (
                      ""
                    ),
                  },
                ]}
              />
            </CardContent>
          </Card>

          <Card>
            <CardContent className="space-y-4 p-5">
              <h3 className="text-sm font-semibold">Autoscaling</h3>
              <KeyValuePairs
                columns={3}
                items={[
                  { label: "Min replicas", value: s?.scaling?.min ?? 1 },
                  { label: "Max replicas", value: s?.scaling?.max ?? 5 },
                  {
                    label: "Target CPU %",
                    value: s?.scaling?.targetCPUPercent ?? 70,
                  },
                ]}
              />
            </CardContent>
          </Card>
        </TabsContent>

        {/* Resources — the attached data plane the platform provisioned. */}
        <TabsContent value="resources" className="pt-4">
          <Card>
            <CardContent className="space-y-5 p-5">
              <div className="space-y-2">
                <h3 className="text-sm font-semibold">Database</h3>
                {s?.database?.name ? (
                  <Badge variant="accent">
                    {s.database.engine ?? "postgres"} · {s.database.name}
                    {s.database.highAvailability ? " · HA" : ""}
                    {s.database.stopped ? " · stopped" : ""}
                  </Badge>
                ) : (
                  <span className="text-sm text-muted-foreground">None</span>
                )}
              </div>

              <div className="space-y-2">
                <h3 className="text-sm font-semibold">Buckets</h3>
                {buckets.length ? (
                  <div className="flex flex-wrap gap-1.5">
                    {buckets.map((b) => (
                      <Badge key={b} variant="secondary">
                        {b}
                      </Badge>
                    ))}
                  </div>
                ) : (
                  <span className="text-sm text-muted-foreground">None</span>
                )}
              </div>

              <div className="space-y-2">
                <h3 className="text-sm font-semibold">Queues</h3>
                {queues.length ? (
                  <div className="flex flex-wrap gap-1.5">
                    {queues.map((q) => (
                      <Badge key={q} variant="secondary">
                        {q}
                      </Badge>
                    ))}
                  </div>
                ) : (
                  <span className="text-sm text-muted-foreground">None</span>
                )}
              </div>

              <div className="space-y-2">
                <h3 className="text-sm font-semibold">Secrets</h3>
                {secrets.length ? (
                  <div className="flex flex-wrap gap-1.5">
                    {secrets.map((sec) => (
                      <Badge key={sec} variant="muted">
                        {sec}
                      </Badge>
                    ))}
                  </div>
                ) : (
                  <span className="text-sm text-muted-foreground">None</span>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Environment — env vars + labels. */}
        <TabsContent value="environment" className="space-y-4 pt-4">
          <Card>
            <CardContent className="space-y-3 p-5">
              <h3 className="text-sm font-semibold">Environment variables</h3>
              {env.length ? (
                <div className="rounded-lg border border-border">
                  {env.map((e, i) => (
                    <div
                      key={`${e.name}-${i}`}
                      className="flex items-center justify-between gap-3 border-b border-border px-3 py-1.5 text-sm last:border-0"
                    >
                      <code className="text-xs text-muted-foreground">
                        {e.name}
                      </code>
                      <code className="truncate text-xs">{e.value}</code>
                    </div>
                  ))}
                </div>
              ) : (
                <span className="text-sm text-muted-foreground">
                  No environment variables.
                </span>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardContent className="space-y-3 p-5">
              <h3 className="text-sm font-semibold">Labels</h3>
              <KeyValueList data={app.metadata.labels} />
            </CardContent>
          </Card>
        </TabsContent>

        {/* Conditions — Crossplane Ready/Synced (ECS "Events/Deployments"). */}
        <TabsContent value="conditions" className="space-y-2 pt-4">
          {conditions.length ? (
            conditions.map((c, i) => (
              <div
                key={`${c.type}-${i}`}
                className="rounded-lg border border-border p-3"
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{c.type}</span>
                  <StatusBadge status={c.status} tone={conditionTone(c)} />
                </div>
                {c.reason ? (
                  <p className="mt-1 text-xs text-muted-foreground">{c.reason}</p>
                ) : null}
                {c.message ? (
                  <p className="mt-1 text-xs text-muted-foreground">
                    {c.message}
                  </p>
                ) : null}
                {c.lastTransitionTime ? (
                  <p className="mt-1 text-[0.7rem] text-muted-foreground/70">
                    {formatTimestamp(c.lastTransitionTime)}
                  </p>
                ) : null}
              </div>
            ))
          ) : (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No conditions reported yet.
            </p>
          )}
        </TabsContent>

        {/* Monitoring — same app-overview dashboard Function/VM embed. */}
        <TabsContent value="monitoring" className="pt-4">
          <GrafanaEmbed
            uid="openinfra-app-overview"
            vars={{ "var-namespace": namespace, "var-pod": `${name}-.*` }}
          />
        </TabsContent>

        <TabsContent value="security" className="pt-4">
          <ResourceSecurityTab
            namespace={namespace}
            securityGroups={s?.securityGroups ?? []}
            onSave={(next) => saveSgs.mutate(next)}
            saving={saveSgs.isPending}
          />
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={app} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Application"
            resourceName={name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>
                Permanently delete application{" "}
                <span className="font-medium text-foreground">{name}</span> and
                the infrastructure it provisioned (hosting, and any attached
                database, buckets, and queues). This cannot be undone.
              </>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
