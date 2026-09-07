import { useMemo } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { BarChart3, Gauge } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState, EmptyState } from "@/components/common/states";
import { claimHealth } from "@/lib/resource-health";
import { k8sDelete, k8sGet, modelMonitorReport } from "@/lib/api";
import type { ModelMonitorReportDoc } from "@/lib/api";
import { openinfraPaths, batchPaths } from "@/lib/k8s-paths";
import { formatTimestamp } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import type { CronJob, ModelMonitor } from "@/types/k8s";

/** Format a numeric report figure; honest em-dash when absent. */
function fmtNum(n: number | undefined | null): string {
  if (n === undefined || n === null || Number.isNaN(n)) return "—";
  if (Number.isInteger(n)) return n.toLocaleString();
  return n.toLocaleString(undefined, { maximumFractionDigits: 4 });
}

/** Clamp a value to a 0–100 percentage of the given scale. */
function pct(v: number, max: number): number {
  if (!(max > 0)) return 0;
  return Math.max(0, Math.min(100, (v / max) * 100));
}

/** Prefer a run's derived report time, fall back to the object's lastModified. */
function runTime(r: { time?: string; lastModified: string }): string {
  const raw = r.time || r.lastModified;
  const f = formatTimestamp(raw);
  return f === "—" ? raw || "—" : f;
}

/** Whether a report doc counts as an overall violation. */
function isViolation(doc: ModelMonitorReportDoc): boolean {
  if (typeof doc.violation === "boolean") return doc.violation;
  if (doc.driftedFeatures && doc.driftedFeatures.length > 0) return true;
  if (doc.features) return Object.values(doc.features).some((f) => f.violation);
  return false;
}

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
          <TabsTrigger value="reports">Reports</TabsTrigger>
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

        <TabsContent value="reports" className="pt-4">
          <ReportsTab namespace={namespace} name={name} specThreshold={s?.threshold} />
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

/**
 * The rendered drift/violations report (SageMaker Model Monitor / Clarify shaped):
 * latest report summary + verdict, a per-feature drift bar view, a violations table,
 * and the monitoring run history. Renders honest empty states — never fabricates drift.
 */
function ReportsTab({
  namespace,
  name,
  specThreshold,
}: {
  namespace: string;
  name: string;
  specThreshold?: number;
}) {
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["modelmonitor-report", namespace, name],
    queryFn: () => modelMonitorReport(namespace, name),
  });

  if (isLoading) return <LoadingState label="Loading reports…" />;
  if (isError || !data) return <ErrorState error={error} onRetry={refetch} />;

  const { latest, runs, reason, bucket, prefix } = data;
  const latestTime = latest?.time;

  return (
    <div className="space-y-6">
      {/* ---- Latest report ---- */}
      {latest ? (
        <LatestReport doc={latest} specThreshold={specThreshold} bucket={bucket} prefix={prefix} />
      ) : (
        <Card>
          <CardContent className="p-0">
            <EmptyState
              icon={<BarChart3 className="size-6" />}
              title="No drift report yet"
              description={
                reason ??
                "This monitor hasn't written a report. Reports appear here after the monitoring schedule runs."
              }
            />
          </CardContent>
        </Card>
      )}

      {/* ---- Run history ---- */}
      <Card>
        <CardHeader className="p-5 pb-3">
          <CardTitle className="text-sm">Run history</CardTitle>
          <CardDescription>Schedule runs, newest first.</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {runs.length === 0 ? (
            <p className="px-5 pb-5 text-sm text-muted-foreground">No monitoring runs recorded yet.</p>
          ) : (
            <table className="w-full text-sm">
              <thead className="border-y border-border text-left text-xs text-muted-foreground">
                <tr>
                  <th className="p-3 font-medium">Run time</th>
                  <th className="p-3 font-medium">Report object</th>
                  <th className="p-3 font-medium">Verdict</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((r) => {
                  // We can only attach a verdict to a run we can correlate with the
                  // parsed latest report (by its time); others show the timestamp only.
                  const isLatest = !!latest && !!latestTime && r.time === latestTime;
                  return (
                    <tr key={r.key} className={cn("border-b border-border last:border-0", isLatest && "bg-primary/5")}>
                      <td className="p-3 whitespace-nowrap">
                        {runTime(r)}
                        {isLatest ? <Badge variant="secondary" className="ml-2">latest</Badge> : null}
                      </td>
                      <td className="p-3 text-xs text-muted-foreground"><code className="break-all">{r.key}</code></td>
                      <td className="p-3">
                        {isLatest && latest ? (
                          <Badge variant={isViolation(latest) ? "destructive" : "success"}>
                            {isViolation(latest) ? "VIOLATION" : "PASS"}
                          </Badge>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

/** Latest report: summary header + verdict, per-feature drift bars, violations table. */
function LatestReport({
  doc,
  specThreshold,
  bucket,
  prefix,
}: {
  doc: ModelMonitorReportDoc;
  specThreshold?: number;
  bucket?: string;
  prefix?: string;
}) {
  const threshold = doc.threshold ?? specThreshold ?? 0.2;
  const features = doc.features ? Object.entries(doc.features) : [];
  const violated = isViolation(doc);
  const violations = features.filter(([, f]) => f.violation);
  const driftedCount = doc.driftedFeatures?.length ?? violations.length;

  // Scale the drift bars so the threshold marker and the largest drift both fit,
  // with a little headroom so a violating bar visibly overshoots the marker.
  const scaleMax =
    Math.max(threshold, ...features.map(([, f]) => Math.abs(f.drift)), 0.0001) * 1.15;

  return (
    <div className="space-y-4">
      {/* Summary + verdict */}
      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-3 p-5 pb-3">
          <div className="space-y-1">
            <CardTitle className="text-sm">Latest drift report</CardTitle>
            <CardDescription>{formatTimestamp(doc.time)}</CardDescription>
          </div>
          <Badge variant={violated ? "destructive" : "success"}>
            {violated ? "VIOLATION" : "PASS"}
          </Badge>
        </CardHeader>
        <CardContent className="divide-y divide-border p-0">
          <DetailRow label="Report time">{formatTimestamp(doc.time)}</DetailRow>
          <DetailRow label="Baseline records">{fmtNum(doc.baselineCount)}</DetailRow>
          <DetailRow label="Current records">{fmtNum(doc.currentCount)}</DetailRow>
          <DetailRow label="Threshold">
            {fmtNum(threshold)} <span className="text-xs text-muted-foreground">relative mean shift</span>
          </DetailRow>
          <DetailRow label="Drifted features">
            {driftedCount} of {features.length}
          </DetailRow>
          {bucket ? (
            <DetailRow label="Source"><code className="text-xs break-all">s3://{bucket}/{prefix ?? ""}</code></DetailRow>
          ) : null}
        </CardContent>
      </Card>

      {/* Per-feature drift bars */}
      <Card>
        <CardHeader className="p-5 pb-3">
          <CardTitle className="text-sm">Feature drift</CardTitle>
          <CardDescription>
            Relative mean shift per feature. The marker is the {fmtNum(threshold)} threshold; bars past it drifted.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-5 pt-1">
          {features.length === 0 ? (
            <p className="text-sm text-muted-foreground">No per-feature drift figures in this report.</p>
          ) : (
            <div className="space-y-4">
              {features.map(([fname, f]) => (
                <div key={fname} className="space-y-1.5">
                  <div className="flex items-center justify-between gap-3 text-sm">
                    <span className="flex items-center gap-2 font-medium">
                      {fname}
                      {f.violation ? <Badge variant="destructive">drift</Badge> : null}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {fmtNum(f.baselineMean)} → {fmtNum(f.currentMean)} · drift {fmtNum(f.drift)}
                    </span>
                  </div>
                  <div className="relative h-2.5 w-full rounded-full bg-secondary" title={`drift ${fmtNum(f.drift)} · threshold ${fmtNum(threshold)}`}>
                    <div
                      className={cn(
                        "absolute inset-y-0 left-0 rounded-full",
                        f.violation ? "bg-destructive" : "bg-success",
                      )}
                      style={{ width: `${pct(Math.abs(f.drift), scaleMax)}%` }}
                    />
                    <div
                      className="absolute inset-y-[-3px] w-0.5 rounded bg-foreground/70"
                      style={{ left: `${pct(threshold, scaleMax)}%` }}
                    />
                  </div>
                </div>
              ))}
              <div className="flex items-center gap-4 pt-1 text-xs text-muted-foreground">
                <span className="flex items-center gap-1.5"><span className="size-2 rounded-full bg-success" /> within threshold</span>
                <span className="flex items-center gap-1.5"><span className="size-2 rounded-full bg-destructive" /> drifted</span>
                <span className="flex items-center gap-1.5"><span className="inline-block h-3 w-0.5 bg-foreground/70" /> threshold</span>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Violations table */}
      <Card>
        <CardHeader className="p-5 pb-3">
          <CardTitle className="text-sm">Constraint violations</CardTitle>
          <CardDescription>Features whose drift exceeded the threshold.</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {violations.length === 0 ? (
            <p className="px-5 pb-5 text-sm text-muted-foreground">No violations — all monitored features are within the threshold.</p>
          ) : (
            <table className="w-full text-sm">
              <thead className="border-y border-border text-left text-xs text-muted-foreground">
                <tr>
                  <th className="p-3 font-medium">Feature</th>
                  <th className="p-3 font-medium">Baseline mean</th>
                  <th className="p-3 font-medium">Current mean</th>
                  <th className="p-3 font-medium">Drift</th>
                  <th className="p-3 font-medium">Threshold</th>
                </tr>
              </thead>
              <tbody>
                {violations.map(([fname, f]) => (
                  <tr key={fname} className="border-b border-border last:border-0">
                    <td className="p-3 font-medium">{fname}</td>
                    <td className="p-3"><code className="text-xs">{fmtNum(f.baselineMean)}</code></td>
                    <td className="p-3"><code className="text-xs">{fmtNum(f.currentMean)}</code></td>
                    <td className="p-3"><code className="text-xs text-destructive">{fmtNum(f.drift)}</code></td>
                    <td className="p-3"><code className="text-xs">{fmtNum(threshold)}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
