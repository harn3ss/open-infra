import { useMemo, useState } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { CalendarClock } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { CopyButton } from "@/components/common/copy-button";
import { JobLogs } from "@/components/common/job-logs";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { StatusBadge } from "@/components/common/status-badge";
import { claimHealth } from "@/lib/resource-health";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths, batchPaths } from "@/lib/k8s-paths";
import { formatTimestamp } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import type { CronJob, Job, ScheduledJob } from "@/types/k8s";

type Phase = { label: string; tone: "success" | "destructive" | "accent" | "muted" };

/** Map a batch Job's status to a run phase + badge tone (mirrors the TrainingJob run phase). */
function jobPhase(job?: Job): Phase {
  const s = job?.status;
  if (!s) return { label: "Pending", tone: "muted" };
  if ((s.succeeded ?? 0) > 0) return { label: "Succeeded", tone: "success" };
  if ((s.failed ?? 0) > 0 && (s.conditions ?? []).some((c) => c.type === "Failed" && c.status === "True"))
    return { label: "Failed", tone: "destructive" };
  if ((s.active ?? 0) > 0) return { label: "Running", tone: "accent" };
  return { label: "Pending", tone: "muted" };
}

/** Best-effort start time for ordering runs newest-first. */
function runStart(job: Job): number {
  const raw = job.status?.startTime ?? job.metadata.creationTimestamp;
  const t = raw ? new Date(raw).getTime() : 0;
  return Number.isNaN(t) ? 0 : t;
}

export function ScheduledJobDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as { namespace: string; name: string };
  const navigate = useNavigate();

  const { data: sj, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["scheduledjob", namespace, name],
    queryFn: () => k8sGet<ScheduledJob>(openinfraPaths.scheduledjob(namespace, name)),
  });

  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.scheduledjob(namespace, name)),
    onSuccess: () => navigate({ to: "/scheduled-jobs" }),
  });

  if (isLoading) return <LoadingState label="Loading scheduled job…" />;
  if (isError || !sj) return <ErrorState error={error} onRetry={refetch} />;

  const s = sj.spec;
  const cronName = sj.status?.cronJob ?? `${name}-scheduled`;
  const cmd = [...(s?.command ?? []), ...(s?.args ?? [])].join(" ");
  const gpu = s?.gpu ?? 0;

  return (
    <DetailShell
      backTo="/scheduled-jobs"
      backLabel="Scheduled Jobs"
      icon={<CalendarClock className="size-5" />}
      title={name}
      subtitle={`Scheduled job · ${namespace}`}
      status={claimHealth(sj)}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="runs">Runs</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Schedule"><code className="text-xs">{s?.schedule ?? "—"}</code></DetailRow>
              <DetailRow label="Time zone">
                {s?.timeZone ? <code className="text-xs">{s.timeZone}</code> : <span className="text-xs text-muted-foreground">UTC (default)</span>}
              </DetailRow>
              <DetailRow label="Suspended">
                {s?.suspend ? <Badge variant="warning">Suspended</Badge> : <span className="text-xs text-muted-foreground">No — runs on schedule</span>}
              </DetailRow>
              <DetailRow label="Concurrency">
                <code className="text-xs">{s?.concurrencyPolicy ?? "Allow"}</code>
              </DetailRow>
              <DetailRow label="Image"><code className="text-xs">{s?.image ?? "—"}</code></DetailRow>
              {cmd ? (
                <DetailRow label="Command"><code className="text-xs break-all">{cmd}</code></DetailRow>
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
              {s?.secrets?.length ? (
                <DetailRow label="Secrets">
                  <span className="flex flex-wrap gap-1">
                    {s.secrets.map((sec) => (
                      <Badge key={sec} variant="secondary">{sec}</Badge>
                    ))}
                  </span>
                </DetailRow>
              ) : null}
              {s?.queues?.length ? (
                <DetailRow label="Queues">
                  <span className="flex flex-wrap gap-1">
                    {s.queues.map((q) => (
                      <Badge key={q} variant="secondary">{q}</Badge>
                    ))}
                  </span>
                </DetailRow>
              ) : null}
              <DetailRow label="Retries">
                {s?.retries ?? 0} <span className="text-xs text-muted-foreground">per run (backoff limit)</span>
              </DetailRow>
              <DetailRow label="Per-run timeout">
                {s?.timeout ? `${s.timeout}s` : <span className="text-xs text-muted-foreground">none</span>}
              </DetailRow>
              {s?.startingDeadline ? (
                <DetailRow label="Starting deadline">{s.startingDeadline}s</DetailRow>
              ) : null}
              <DetailRow label="Resources">
                <span className="text-xs text-muted-foreground">
                  {[s?.cpu ? `${s.cpu} CPU` : null, s?.memory ?? null, gpu > 0 ? `${gpu}× ${s?.gpuTier ?? "smallgpu"} GPU` : null]
                    .filter(Boolean)
                    .join(" · ") || "platform defaults"}
                </span>
              </DetailRow>
              <DetailRow label="CronJob">
                <span className="flex items-center gap-1">
                  <code className="text-xs">{cronName}</code>
                  <CopyButton value={cronName} label="Copy CronJob name" />
                </span>
                <span className="ml-1 text-xs text-muted-foreground">— see the <strong>Runs</strong> tab</span>
              </DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="runs" className="pt-4">
          <RunsTab namespace={namespace} name={name} cronName={cronName} />
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={sj} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Scheduled Job"
            resourceName={name}
            deleting={deleteMutation.isPending}
            onConfirm={() => deleteMutation.mutate()}
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}

/**
 * Run history for a ScheduledJob: the backing CronJob's last-schedule time plus every child Job it
 * has spawned (label openinfra.dev/scheduledjob=<name>), newest first, each with a per-run status and
 * in-console logs. Honest-empty when nothing has run yet — never fabricated runs.
 */
function RunsTab({ namespace, name, cronName }: { namespace: string; name: string; cronName: string }) {
  const cronWatch = useK8sWatch<CronJob>(batchPaths.cronjobs(namespace));
  const cron = useMemo(() => cronWatch.items.find((c) => c.metadata.name === cronName), [cronWatch.items, cronName]);

  const jobWatch = useK8sWatch<Job>(batchPaths.jobs(namespace));
  const runs = useMemo(
    () =>
      jobWatch.items
        .filter((j) => j.metadata.labels?.["openinfra.dev/scheduledjob"] === name)
        .sort((a, b) => runStart(b) - runStart(a)),
    [jobWatch.items, name],
  );

  const [selectedJob, setSelectedJob] = useState<string | null>(null);
  const active = useMemo(
    () => runs.find((r) => r.metadata.name === selectedJob) ?? runs[0],
    [runs, selectedJob],
  );
  const activeName = active?.metadata.name ?? "";
  const activeRunning = active ? jobPhase(active).label === "Running" : false;

  return (
    <div className="space-y-6">
      <Card>
        <CardContent className="divide-y divide-border p-0">
          <DetailRow label="Last run">
            {cron?.status?.lastScheduleTime ? (
              <span className="text-xs">{formatTimestamp(cron.status.lastScheduleTime)}</span>
            ) : (
              <span className="text-xs text-muted-foreground">not run yet</span>
            )}
          </DetailRow>
          <DetailRow label="Last successful">
            {cron?.status?.lastSuccessfulTime ? (
              <span className="text-xs">{formatTimestamp(cron.status.lastSuccessfulTime)}</span>
            ) : (
              <span className="text-xs text-muted-foreground">—</span>
            )}
          </DetailRow>
          <DetailRow label="Active now">
            {cron?.status?.active?.length ? (
              <span className="text-xs">{cron.status.active.length} running</span>
            ) : (
              <span className="text-xs text-muted-foreground">none</span>
            )}
          </DetailRow>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="p-5 pb-3">
          <CardTitle className="text-sm">Run history</CardTitle>
          <CardDescription>Child Jobs of this schedule, newest first. Select a run to view its logs.</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {runs.length === 0 ? (
            <p className="px-5 pb-5 text-sm text-muted-foreground">
              No runs recorded yet. Runs appear here after the schedule fires (or after a manual{" "}
              <code>kubectl create job --from=cronjob/{cronName} -n {namespace}</code>).
            </p>
          ) : (
            <table className="w-full text-sm">
              <thead className="border-y border-border text-left text-xs text-muted-foreground">
                <tr>
                  <th className="p-3 font-medium">Run</th>
                  <th className="p-3 font-medium">Started</th>
                  <th className="p-3 font-medium">Finished</th>
                  <th className="p-3 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((r) => {
                  const p = jobPhase(r);
                  const isActive = r.metadata.name === activeName;
                  return (
                    <tr
                      key={r.metadata.uid ?? r.metadata.name}
                      className={cn(
                        "cursor-pointer border-b border-border last:border-0 hover:bg-muted/40",
                        isActive && "bg-primary/5",
                      )}
                      onClick={() => setSelectedJob(r.metadata.name ?? null)}
                    >
                      <td className="p-3">
                        <code className="text-xs">{r.metadata.name}</code>
                        {isActive ? <Badge variant="secondary" className="ml-2">viewing</Badge> : null}
                      </td>
                      <td className="p-3 whitespace-nowrap text-xs text-muted-foreground">
                        {r.status?.startTime ? formatTimestamp(r.status.startTime) : "—"}
                      </td>
                      <td className="p-3 whitespace-nowrap text-xs text-muted-foreground">
                        {r.status?.completionTime ? formatTimestamp(r.status.completionTime) : "—"}
                      </td>
                      <td className="p-3">
                        <StatusBadge status={p.label} tone={p.tone} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      {active ? (
        <Card>
          <CardHeader className="p-5 pb-3">
            <CardTitle className="text-sm">Logs</CardTitle>
            <CardDescription>
              <code className="text-xs">{activeName}</code>
            </CardDescription>
          </CardHeader>
          <CardContent className="p-4 pt-0">
            <JobLogs namespace={namespace} jobName={activeName} running={activeRunning} />
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
