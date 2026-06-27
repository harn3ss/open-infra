import { useParams } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Repeat, ArrowRight } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { DetailRow } from "@/components/common/detail-row";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { LoadingState, ErrorState } from "@/components/common/states";
import { k8sGet, getReplicationStatus } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { Replication, ReplicationEndpoint } from "@/types/k8s";
import { type StatusTone } from "@/lib/format";
import { PipelineView } from "./pipeline-view";

function replStatus(r?: Replication): { label: string; tone: StatusTone } {
  const conds = r?.status?.conditions ?? [];
  const ready = conds.find((c) => c.type === "Ready");
  const synced = conds.find((c) => c.type === "Synced");
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  if (synced?.status === "False") return { label: "Error", tone: "destructive" };
  return { label: "Provisioning", tone: "warning" };
}

function endpointLine(e?: ReplicationEndpoint) {
  if (!e) return "—";
  return `${e.username}@${e.host}:${e.port ?? 5432}/${e.database}`;
}

export function ReplicationDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };

  const {
    data: repl,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ["replication", namespace, name],
    queryFn: () => k8sGet<Replication>(openinfraPaths.replication(namespace, name)),
    refetchInterval: 10_000,
  });

  const a = repl?.spec?.siteA;
  const b = repl?.spec?.siteB;
  const aName = a?.name ?? "";
  const bName = b?.name ?? "";

  const { data: status } = useQuery({
    queryKey: ["replication-status", namespace, name, aName, bName],
    queryFn: () => getReplicationStatus(namespace, name, aName, bName),
    refetchInterval: 4_000,
    enabled: !!aName && !!bName,
  });

  if (isLoading) return <LoadingState label="Loading replication…" />;
  if (isError) return <ErrorState error={error} onRetry={refetch} />;

  const st = replStatus(repl);

  return (
    <DetailShell
      backTo="/replications"
      backLabel="Replication"
      icon={<Repeat className="size-5" />}
      title={name}
      subtitle={`Multi-master · ${a?.engine ?? "?"} (${aName}) ⇄ ${b?.engine ?? "?"} (${bName})`}
      status={st}
    >
      <Tabs defaultValue="status">
        <TabsList>
          <TabsTrigger value="status">Status</TabsTrigger>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
        </TabsList>

        {/* Both directions, each its own pipeline. */}
        <TabsContent value="status" className="space-y-6 pt-4">
          <section className="space-y-2">
            <div className="flex items-center gap-2 text-sm font-medium">
              <code>{aName}</code> <ArrowRight className="size-4 text-muted-foreground" /> <code>{bName}</code>
              <span className="text-muted-foreground">({a?.engine} → {b?.engine})</span>
            </div>
            <PipelineView ps={status?.[aName]} sourceEngine={a?.engine} targetEngine={b?.engine} />
          </section>
          <section className="space-y-2">
            <div className="flex items-center gap-2 text-sm font-medium">
              <code>{bName}</code> <ArrowRight className="size-4 text-muted-foreground" /> <code>{aName}</code>
              <span className="text-muted-foreground">({b?.engine} → {a?.engine})</span>
            </div>
            <PipelineView ps={status?.[bName]} sourceEngine={b?.engine} targetEngine={a?.engine} />
          </section>
        </TabsContent>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label={`Site A (${aName})`}>
                <code>{a?.engine}</code> {endpointLine(a)}
              </DetailRow>
              <DetailRow label={`Site B (${bName})`}>
                <code>{b?.engine}</code> {endpointLine(b)}
              </DetailRow>
              <DetailRow label="Tables">
                {(repl?.spec?.tables ?? []).length === 0 ? (
                  <span className="text-muted-foreground">—</span>
                ) : (
                  <span className="flex flex-wrap gap-1">
                    {(repl?.spec?.tables ?? []).map((t) => (
                      <Badge key={t} variant="secondary">{t}</Badge>
                    ))}
                  </span>
                )}
              </DetailRow>
              <DetailRow label="Conflict resolution">
                last-write-wins (HLC version · origin tiebreak)
              </DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={repl} />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
