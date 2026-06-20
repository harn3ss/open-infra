import { useState } from "react";
import { useParams } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Database, Eye, EyeOff } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { CopyButton } from "@/components/common/copy-button";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { GrafanaEmbed } from "@/components/common/grafana-embed";
import { LoadingState, ErrorState } from "@/components/common/states";
import { k8sGet } from "@/lib/api";
import { cnpgPaths } from "@/lib/k8s-paths";
import { type StatusTone } from "@/lib/format";
import type { CnpgCluster, K8sObject } from "@/types/k8s";

function decode(v?: string): string {
  if (!v) return "";
  try {
    return atob(v);
  } catch {
    return "";
  }
}

function dbTone(phase?: string): StatusTone {
  if (!phase) return "muted";
  const p = phase.toLowerCase();
  if (p.includes("healthy")) return "success";
  if (p.includes("fail") || p.includes("unhealth") || p.includes("error"))
    return "destructive";
  return "warning";
}

export function DatabaseDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const [showUri, setShowUri] = useState(false);

  const { data: db, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["database", namespace, name],
    queryFn: () => k8sGet<CnpgCluster>(cnpgPaths.cluster(namespace, name)),
  });
  const { data: secret } = useQuery({
    queryKey: ["database-secret", namespace, name],
    queryFn: () =>
      k8sGet<K8sObject & { data?: Record<string, string> }>(
        `/api/v1/namespaces/${namespace}/secrets/${name}-app`,
      ),
    retry: false,
  });

  if (isLoading) return <LoadingState label="Loading database…" />;
  if (isError || !db) return <ErrorState error={error} onRetry={refetch} />;

  const d = secret?.data ?? {};
  const uri = decode(d["uri"]);
  const phase = db.status?.phase;
  const ready = db.status?.readyInstances ?? 0;
  const total = db.spec?.instances ?? db.status?.instances ?? 1;

  return (
    <DetailShell
      backTo="/databases"
      backLabel="Databases"
      icon={<Database className="size-5" />}
      title={name}
      subtitle={`Managed PostgreSQL · ${namespace}`}
      status={phase ? { label: phase, tone: dbTone(phase) } : null}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="connectivity">Connectivity</TabsTrigger>
          <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Status">{phase ?? "—"}</DetailRow>
              <DetailRow label="Instances">
                {ready}/{total} ready
              </DetailRow>
              <DetailRow label="Storage">
                {db.spec?.storage?.size ?? "—"} (
                {db.spec?.storage?.storageClass ?? "default"})
              </DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="connectivity" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Host">
                {decode(d["host"]) || `${name}-rw.${namespace}.svc`}
              </DetailRow>
              <DetailRow label="Port">{decode(d["port"]) || "5432"}</DetailRow>
              <DetailRow label="Database">{decode(d["dbname"]) || "—"}</DetailRow>
              <DetailRow label="User">{decode(d["user"]) || "—"}</DetailRow>
              <DetailRow label="Connection URI">
                <span className="flex items-center gap-1">
                  <code className="max-w-[26rem] truncate text-xs">
                    {uri ? (showUri ? uri : "postgresql://•••") : "—"}
                  </code>
                  {uri ? (
                    <>
                      <button
                        onClick={() => setShowUri((v) => !v)}
                        className="text-muted-foreground hover:text-foreground"
                        aria-label={showUri ? "Hide" : "Show"}
                      >
                        {showUri ? (
                          <EyeOff className="size-4" />
                        ) : (
                          <Eye className="size-4" />
                        )}
                      </button>
                      <CopyButton value={uri} />
                    </>
                  ) : null}
                </span>
              </DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="monitoring" className="pt-4">
          <GrafanaEmbed
            uid="openinfra-app-overview"
            vars={{ "var-namespace": namespace }}
          />
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={db} />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
