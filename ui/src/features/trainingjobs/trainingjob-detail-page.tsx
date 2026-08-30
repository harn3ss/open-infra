import { useMemo } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { BrainCog } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { StatusBadge } from "@/components/common/status-badge";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths, batchPaths } from "@/lib/k8s-paths";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import type { Job, TrainingJob } from "@/types/k8s";

/** Map a batch Job's status to a run phase + badge tone. */
function jobPhase(job?: Job): { label: string; tone: "success" | "destructive" | "accent" | "muted" } {
  const s = job?.status;
  if (!s) return { label: "Pending", tone: "muted" };
  if ((s.succeeded ?? 0) > 0) return { label: "Succeeded", tone: "success" };
  if ((s.failed ?? 0) > 0 && (s.conditions ?? []).some((c) => c.type === "Failed" && c.status === "True"))
    return { label: "Failed", tone: "destructive" };
  if ((s.active ?? 0) > 0) return { label: "Running", tone: "accent" };
  return { label: "Pending", tone: "muted" };
}

export function TrainingJobDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as { namespace: string; name: string };
  const navigate = useNavigate();

  const { data: tj, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["trainingjob", namespace, name],
    queryFn: () => k8sGet<TrainingJob>(openinfraPaths.trainingjob(namespace, name)),
  });

  // The run status is the underlying batch Job's — read it live.
  const jobWatch = useK8sWatch<Job>(batchPaths.jobs(namespace));
  const jobName = tj?.status?.jobName ?? `${name}-train`;
  const job = useMemo(
    () => jobWatch.items.find((j) => j.metadata.name === jobName),
    [jobWatch.items, jobName],
  );

  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.trainingjob(namespace, name)),
    onSuccess: () => navigate({ to: "/trainingjobs" }),
  });

  if (isLoading) return <LoadingState label="Loading training job…" />;
  if (isError || !tj) return <ErrorState error={error} onRetry={refetch} />;

  const s = tj.spec;
  const gpu = s?.gpu ?? 1;
  const run = jobPhase(job);

  return (
    <DetailShell
      backTo="/trainingjobs"
      backLabel="Training Jobs"
      icon={<BrainCog className="size-5" />}
      title={name}
      subtitle={`Training job · ${namespace}`}
      status={run}
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
              <DetailRow label="Run status">
                <StatusBadge status={run.label} tone={run.tone} />
                {job?.status?.startTime ? (
                  <span className="ml-2 text-xs text-muted-foreground">started {job.status.startTime}</span>
                ) : null}
                {job?.status?.completionTime ? (
                  <span className="ml-2 text-xs text-muted-foreground">finished {job.status.completionTime}</span>
                ) : null}
              </DetailRow>
              <DetailRow label="Image"><code className="text-xs">{s?.image ?? "—"}</code></DetailRow>
              <DetailRow label="GPU">
                {gpu > 0 ? <Badge variant="secondary">{gpu}× {s?.gpuTier ?? "smallgpu"}</Badge> : <span className="text-xs text-muted-foreground">CPU-only</span>}
              </DetailRow>
              {(s?.cpu || s?.memory) ? (
                <DetailRow label="Resources">
                  <span className="text-xs">{s?.cpu ? `${s.cpu} CPU` : ""}{s?.cpu && s?.memory ? " · " : ""}{s?.memory ?? ""}</span>
                </DetailRow>
              ) : null}
              {s?.dataset?.bucket ? (
                <DetailRow label="Dataset">
                  <code className="text-xs">s3://{s.dataset.bucket}/{s.dataset.prefix ?? ""}</code>
                </DetailRow>
              ) : null}
              {s?.output?.bucket ? (
                <DetailRow label="Output">
                  <code className="text-xs">s3://{s.output.bucket}/{s.output.prefix ?? ""}</code>
                </DetailRow>
              ) : null}
              {s?.env?.length ? (
                <DetailRow label="Environment">
                  <span className="flex flex-wrap gap-1">
                    {s.env.map((e) => (
                      <Badge key={e.name} variant="secondary">{e.name}={e.value}</Badge>
                    ))}
                  </span>
                </DetailRow>
              ) : null}
              <DetailRow label="Job">
                <code className="text-xs">{jobName}</code>
                <span className="ml-2 text-xs text-muted-foreground">— view logs with <code>kubectl logs -n {namespace} job/{jobName}</code></span>
              </DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={tj} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Training Job"
            resourceName={name}
            deleting={deleteMutation.isPending}
            onConfirm={() => deleteMutation.mutate()}
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
