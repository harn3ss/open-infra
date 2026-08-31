import { useMemo } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Layers } from "lucide-react";
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
import type { BatchTransform, Job } from "@/types/k8s";

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

export function BatchTransformDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as { namespace: string; name: string };
  const navigate = useNavigate();

  const { data: bt, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["batchtransform", namespace, name],
    queryFn: () => k8sGet<BatchTransform>(openinfraPaths.batchtransform(namespace, name)),
  });

  const jobWatch = useK8sWatch<Job>(batchPaths.jobs(namespace));
  const jobName = bt?.status?.jobName ?? `${name}-transform`;
  const job = useMemo(() => jobWatch.items.find((j) => j.metadata.name === jobName), [jobWatch.items, jobName]);

  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.batchtransform(namespace, name)),
    onSuccess: () => navigate({ to: "/batch-transform" }),
  });

  if (isLoading) return <LoadingState label="Loading batch transform…" />;
  if (isError || !bt) return <ErrorState error={error} onRetry={refetch} />;

  const s = bt.spec;
  const gpu = s?.gpu ?? 0;
  const run = jobPhase(job);

  return (
    <DetailShell
      backTo="/batch-transform"
      backLabel="Batch Transform"
      icon={<Layers className="size-5" />}
      title={name}
      subtitle={`Batch transform · ${namespace}`}
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
                {job?.status?.completionTime ? (
                  <span className="ml-2 text-xs text-muted-foreground">finished {job.status.completionTime}</span>
                ) : null}
              </DetailRow>
              <DetailRow label="Image"><code className="text-xs">{s?.image ?? "—"}</code></DetailRow>
              <DetailRow label="GPU">
                {gpu > 0 ? <Badge variant="secondary">{gpu}× {s?.gpuTier ?? "smallgpu"}</Badge> : <span className="text-xs text-muted-foreground">CPU-only</span>}
              </DetailRow>
              <DetailRow label="Input"><code className="text-xs">s3://{s?.input?.bucket}/{s?.input?.prefix ?? ""}</code></DetailRow>
              <DetailRow label="Output"><code className="text-xs">s3://{s?.output?.bucket}/{s?.output?.prefix ?? ""}</code></DetailRow>
              {s?.artifact?.bucket ? (
                <DetailRow label="Model artifact"><code className="text-xs">s3://{s.artifact.bucket}/{s.artifact.key ?? ""}</code></DetailRow>
              ) : null}
              {s?.env?.length ? (
                <DetailRow label="Environment">
                  <span className="flex flex-wrap gap-1">
                    {s.env.map((e) => <Badge key={e.name} variant="secondary">{e.name}={e.value}</Badge>)}
                  </span>
                </DetailRow>
              ) : null}
              <DetailRow label="Job">
                <code className="text-xs">{jobName}</code>
                <span className="ml-2 text-xs text-muted-foreground">— logs: <code>kubectl logs -n {namespace} job/{jobName}</code></span>
              </DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={bt} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Batch Transform"
            resourceName={name}
            deleting={deleteMutation.isPending}
            onConfirm={() => deleteMutation.mutate()}
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
