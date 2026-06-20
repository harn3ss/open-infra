import { useState } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Database, Eye, EyeOff } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { CopyButton } from "@/components/common/copy-button";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { GrafanaEmbed } from "@/components/common/grafana-embed";
import { ResourceNameRow } from "@/components/common/resource-name-row";
import { DbConnectivity } from "@/components/common/db-connectivity";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { k8sDelete, k8sGet } from "@/lib/api";
import { cnpgPaths, openinfraPaths } from "@/lib/k8s-paths";
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
  const navigate = useNavigate();
  // The CNPG cluster is named "<app>-db" and owned by its Application; deleting
  // the database means deleting that Application (Crossplane would otherwise
  // recreate the cluster). Strip the "-db" suffix to get the app name.
  const appName = name.replace(/-db$/, "");
  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.application(namespace, appName)),
    onSuccess: () => navigate({ to: "/databases" }),
  });

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
              <ResourceNameRow kind="database" name={name} namespace={namespace} />
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
          <div className="pt-4">
            <DbConnectivity
              namespace={namespace}
              internalSvc={`${name}-rw`}
              lanSvc={`${appName}-db-lan`}
              port={5432}
              scheme="postgresql"
            />
          </div>
        </TabsContent>

        <TabsContent value="monitoring" className="pt-4">
          <GrafanaEmbed
            uid="openinfra-app-overview"
            vars={{ "var-namespace": namespace, "var-pod": `${name}-.*` }}
          />
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={db} />
        </TabsContent>
      </Tabs>

      <DangerZone
        resourceLabel="Database"
        resourceName={name}
        deleting={deleteMutation.isPending}
        onConfirm={() => deleteMutation.mutate()}
        confirmDescription={
          <>
            Permanently delete the application{" "}
            <span className="font-medium text-foreground">{appName}</span> and its
            PostgreSQL database. This cannot be undone.
          </>
        }
      />
    </DetailShell>
  );
}
