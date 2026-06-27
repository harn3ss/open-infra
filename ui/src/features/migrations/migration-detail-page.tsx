import { useParams } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ArrowRightLeft, ArrowRight, AlertTriangle, Database } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { DetailRow } from "@/components/common/detail-row";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { LoadingState, ErrorState } from "@/components/common/states";
import { k8sGet, getMigrationStatus } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { Migration } from "@/types/k8s";
import { formatBytes, type StatusTone } from "@/lib/format";

function migStatus(m?: Migration): { label: string; tone: StatusTone } {
  const conds = m?.status?.conditions ?? [];
  const ready = conds.find((c) => c.type === "Ready");
  const synced = conds.find((c) => c.type === "Synced");
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  if (synced?.status === "False") return { label: "Error", tone: "destructive" };
  return { label: "Provisioning", tone: "warning" };
}

// A single pipeline stage box.
function Stage({ title, value, sub }: { title: string; value: string; sub?: string }) {
  return (
    <Card className="flex-1">
      <CardContent className="p-4">
        <div className="text-xs uppercase tracking-wide text-muted-foreground">{title}</div>
        <div className="mt-1 text-2xl font-semibold tabular-nums">{value}</div>
        {sub ? <div className="mt-0.5 text-xs text-muted-foreground">{sub}</div> : null}
      </CardContent>
    </Card>
  );
}

export function MigrationDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };

  const {
    data: mig,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ["migration", namespace, name],
    queryFn: () => k8sGet<Migration>(openinfraPaths.migration(namespace, name)),
    refetchInterval: 10_000,
  });

  // Live apply-pipeline status from JetStream (lag, per-table, dead-letter).
  const { data: ps } = useQuery({
    queryKey: ["migration-status", namespace, name],
    queryFn: () => getMigrationStatus(namespace, name),
    refetchInterval: 4_000,
  });

  if (isLoading) return <LoadingState label="Loading migration…" />;
  if (isError) return <ErrorState error={error} onRetry={refetch} />;

  const st = migStatus(mig);
  const src = mig?.spec?.source;
  const tgt = mig?.spec?.target;
  const lag = ps?.lag ?? 0;
  const inSync = !!ps?.found && lag === 0 && (ps?.ackPending ?? 0) === 0;

  return (
    <DetailShell
      backTo="/migrations"
      backLabel="Migrations"
      icon={<ArrowRightLeft className="size-5" />}
      title={name}
      subtitle={`DMS · ${src?.engine ?? "?"} → ${tgt?.engine ?? "postgres"} · ${mig?.spec?.mode ?? "full-load"}`}
      status={st}
    >
      <Tabs defaultValue="status">
        <TabsList>
          <TabsTrigger value="status">Status</TabsTrigger>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
        </TabsList>

        {/* ---- Status / live pipeline ---- */}
        <TabsContent value="status" className="space-y-4 pt-4">
          {/* headline: freshness / lag */}
          <Card>
            <CardContent className="flex items-center justify-between p-5">
              <div>
                <div className="text-sm text-muted-foreground">Replication lag</div>
                <div className="mt-1 text-3xl font-semibold tabular-nums">
                  {!ps?.found
                    ? "Provisioning…"
                    : inSync
                      ? "In sync"
                      : `${lag.toLocaleString()} behind`}
                </div>
              </div>
              <Badge variant={inSync ? "secondary" : "default"}>
                {!ps?.found ? "starting" : inSync ? "caught up" : "applying"}
              </Badge>
            </CardContent>
          </Card>

          {/* pipeline strip: Capture -> Buffer -> Apply */}
          <div className="flex items-stretch gap-2">
            <Stage title="Capture" value={src?.engine ?? "—"} sub="Debezium CDC" />
            <div className="flex items-center text-muted-foreground"><ArrowRight className="size-4" /></div>
            <Stage
              title="Buffer"
              value={(ps?.captured ?? 0).toLocaleString()}
              sub={`${formatBytes(ps?.bytes ?? 0)} in stream`}
            />
            <div className="flex items-center text-muted-foreground"><ArrowRight className="size-4" /></div>
            <Stage
              title="Apply"
              value={lag === 0 ? "0 pending" : `${lag.toLocaleString()} pending`}
              sub={`${ps?.ackPending ?? 0} in flight · ${ps?.redelivered ?? 0} retries → ${tgt?.engine ?? "postgres"}`}
            />
          </div>

          {/* dead-letter */}
          {(ps?.deadLetter ?? 0) > 0 ? (
            <Card className="border-destructive/40">
              <CardContent className="p-4">
                <div className="flex items-center gap-2 text-destructive">
                  <AlertTriangle className="size-4" />
                  <span className="font-medium">
                    {ps?.deadLetter?.toLocaleString()} rows dead-lettered
                  </span>
                </div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {(ps?.dlqSubjects ?? []).map((d) => (
                    <Badge key={d.subject} variant="destructive">
                      {d.table}: {d.count}
                    </Badge>
                  ))}
                </div>
                <p className="mt-2 text-xs text-muted-foreground">
                  Rows that failed to apply after retries (e.g. type/constraint errors). Kept in the
                  dead-letter stream for inspection — they don't block other rows.
                </p>
              </CardContent>
            </Card>
          ) : null}

          {/* per-table */}
          <Card>
            <CardContent className="p-0">
              <div className="border-b px-4 py-2 text-xs uppercase tracking-wide text-muted-foreground">
                Tables
              </div>
              {(ps?.tables ?? []).length === 0 ? (
                <div className="px-4 py-3 text-sm text-muted-foreground">
                  No change events captured yet.
                </div>
              ) : (
                <div className="divide-y divide-border">
                  {(ps?.tables ?? []).map((t) => (
                    <div key={t.subject} className="flex items-center justify-between px-4 py-2 text-sm">
                      <span className="flex items-center gap-2">
                        <Database className="size-3.5 text-muted-foreground" />
                        <code>{t.table}</code>
                      </span>
                      <span className="tabular-nums text-muted-foreground">
                        {t.count.toLocaleString()} events
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ---- Overview ---- */}
        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Mode">{mig?.spec?.mode ?? "full-load"}</DetailRow>
              <DetailRow label="Source">
                <code>{src?.engine}</code> {src?.username}@{src?.host}:{src?.port ?? 5432}/{src?.database}
              </DetailRow>
              <DetailRow label="Target">
                <code>{tgt?.engine ?? "postgres"}</code> {tgt?.username}@{tgt?.host}:{tgt?.port ?? 5432}/{tgt?.database}
              </DetailRow>
              <DetailRow label="Tables">
                {(mig?.spec?.tables ?? []).length === 0 ? (
                  <span className="text-muted-foreground">all tables</span>
                ) : (
                  <span className="flex flex-wrap gap-1">
                    {(mig?.spec?.tables ?? []).map((t) => (
                      <Badge key={t} variant="secondary">{t}</Badge>
                    ))}
                  </span>
                )}
              </DetailRow>
              <DetailRow label="Stream">{ps?.stream ?? mig?.status?.stream ?? "—"}</DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={mig} />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
