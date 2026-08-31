import { useMemo } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { FlaskConical } from "lucide-react";
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
import type { ProcessingChannel, ProcessingJob, Job } from "@/types/k8s";

function jobPhase(job?: Job): { label: string; tone: "success" | "destructive" | "accent" | "muted" } {
  const s = job?.status;
  if (!s) return { label: "Pending", tone: "muted" };
  if ((s.succeeded ?? 0) > 0) return { label: "Succeeded", tone: "success" };
  if ((s.failed ?? 0) > 0 && (s.conditions ?? []).some((c) => c.type === "Failed" && c.status === "True"))
    return { label: "Failed", tone: "destructive" };
  if ((s.active ?? 0) > 0) return { label: "Running", tone: "accent" };
  return { label: "Pending", tone: "muted" };
}

function ChannelRows({ label, channels }: { label: string; channels?: ProcessingChannel[] }) {
  if (!channels?.length) return null;
  return (
    <DetailRow label={label}>
      <span className="flex flex-col gap-1">
        {channels.map((c) => (
          <span key={c.name} className="text-xs">
            <Badge variant="secondary" className="mr-2">{c.name}</Badge>
            <code>s3://{c.bucket}/{c.prefix ?? ""}</code>
          </span>
        ))}
      </span>
    </DetailRow>
  );
}

export function ProcessingJobDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as { namespace: string; name: string };
  const navigate = useNavigate();

  const { data: pj, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["processingjob", namespace, name],
    queryFn: () => k8sGet<ProcessingJob>(openinfraPaths.processingjob(namespace, name)),
  });

  const jobWatch = useK8sWatch<Job>(batchPaths.jobs(namespace));
  const jobName = pj?.status?.jobName ?? `${name}-proc`;
  const job = useMemo(() => jobWatch.items.find((j) => j.metadata.name === jobName), [jobWatch.items, jobName]);

  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.processingjob(namespace, name)),
    onSuccess: () => navigate({ to: "/processing" }),
  });

  if (isLoading) return <LoadingState label="Loading processing job…" />;
  if (isError || !pj) return <ErrorState error={error} onRetry={refetch} />;

  const s = pj.spec;
  const gpu = s?.gpu ?? 0;
  const run = jobPhase(job);

  return (
    <DetailShell
      backTo="/processing"
      backLabel="Processing Jobs"
      icon={<FlaskConical className="size-5" />}
      title={name}
      subtitle={`Processing job · ${namespace}`}
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
              <ChannelRows label="Inputs" channels={s?.inputs} />
              <ChannelRows label="Outputs" channels={s?.outputs} />
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
          <YamlViewer value={pj} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Processing Job"
            resourceName={name}
            deleting={deleteMutation.isPending}
            onConfirm={() => deleteMutation.mutate()}
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
