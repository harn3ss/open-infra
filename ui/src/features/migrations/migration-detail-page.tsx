import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ArrowRightLeft } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { DetailRow } from "@/components/common/detail-row";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { LoadingState, ErrorState } from "@/components/common/states";
import { k8sDelete, k8sGet, getMigrationStatus } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { Migration } from "@/types/k8s";
import { type StatusTone } from "@/lib/format";
import { PipelineView } from "./pipeline-view";

function migStatus(m?: Migration): { label: string; tone: StatusTone } {
  const conds = m?.status?.conditions ?? [];
  const ready = conds.find((c) => c.type === "Ready");
  const synced = conds.find((c) => c.type === "Synced");
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  if (synced?.status === "False") return { label: "Error", tone: "destructive" };
  return { label: "Provisioning", tone: "warning" };
}

export function MigrationDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();

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

  const del = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.migration(namespace, name)),
    onSuccess: () => navigate({ to: "/migrations" }),
  });

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
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="status" className="pt-4">
          <PipelineView ps={ps} sourceEngine={src?.engine} targetEngine={tgt?.engine ?? "postgres"} />
        </TabsContent>

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

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Migration"
            resourceName={name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>Permanently delete migration <span className="font-medium text-foreground">{name}</span> and tear down its pipeline. This cannot be undone.</>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
