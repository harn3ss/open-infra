import { useMemo } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Gauge } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { claimHealth } from "@/lib/resource-health";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths, batchPaths } from "@/lib/k8s-paths";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import type { CronJob, ModelMonitor } from "@/types/k8s";

export function ModelMonitorDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as { namespace: string; name: string };
  const navigate = useNavigate();

  const { data: mm, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["modelmonitor", namespace, name],
    queryFn: () => k8sGet<ModelMonitor>(openinfraPaths.modelmonitor(namespace, name)),
  });

  const cronWatch = useK8sWatch<CronJob>(batchPaths.cronjobs(namespace));
  const cronName = mm?.status?.cronJob ?? `${name}-monitor`;
  const cron = useMemo(() => cronWatch.items.find((c) => c.metadata.name === cronName), [cronWatch.items, cronName]);

  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.modelmonitor(namespace, name)),
    onSuccess: () => navigate({ to: "/model-monitor" }),
  });

  if (isLoading) return <LoadingState label="Loading model monitor…" />;
  if (isError || !mm) return <ErrorState error={error} onRetry={refetch} />;

  const s = mm.spec;
  const out = s?.output;

  return (
    <DetailShell
      backTo="/model-monitor"
      backLabel="Model Monitors"
      icon={<Gauge className="size-5" />}
      title={name}
      subtitle={`Model monitor · ${namespace}`}
      status={claimHealth(mm)}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Schedule"><code className="text-xs">{s?.schedule ?? "0 * * * *"}</code></DetailRow>
              <DetailRow label="Last run">
                {cron?.status?.lastScheduleTime ? (
                  <span className="text-xs">{cron.status.lastScheduleTime}</span>
                ) : (
                  <span className="text-xs text-muted-foreground">not run yet</span>
                )}
              </DetailRow>
              {s?.modelRef ? <DetailRow label="Monitors model">{s.modelRef}</DetailRow> : null}
              <DetailRow label="Baseline"><code className="text-xs">s3://{s?.baseline?.bucket}/{s?.baseline?.key ?? ""}</code></DetailRow>
              <DetailRow label="Current"><code className="text-xs">s3://{s?.current?.bucket}/{s?.current?.prefix ?? ""}</code></DetailRow>
              <DetailRow label="Reports">
                <code className="text-xs">s3://{out?.bucket}/{out?.prefix ?? ""}latest.json</code>
              </DetailRow>
              <DetailRow label="Threshold">{s?.threshold ?? 0.2} <span className="text-xs text-muted-foreground">relative mean shift</span></DetailRow>
              {s?.features?.length ? (
                <DetailRow label="Features">{s.features.join(", ")}</DetailRow>
              ) : (
                <DetailRow label="Features"><span className="text-xs text-muted-foreground">all numeric fields</span></DetailRow>
              )}
              <DetailRow label="CronJob">
                <code className="text-xs">{cronName}</code>
                <span className="ml-2 text-xs text-muted-foreground">— run now: <code>kubectl create job --from=cronjob/{cronName} run-1 -n {namespace}</code></span>
              </DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={mm} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Model Monitor"
            resourceName={name}
            deleting={deleteMutation.isPending}
            onConfirm={() => deleteMutation.mutate()}
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
