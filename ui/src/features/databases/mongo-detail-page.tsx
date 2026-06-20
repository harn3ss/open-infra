import { useState } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Database, Eye, EyeOff } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { CopyButton } from "@/components/common/copy-button";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { GrafanaEmbed } from "@/components/common/grafana-embed";
import { ResourceNameRow } from "@/components/common/resource-name-row";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { claimHealth } from "@/lib/resource-health";
import { k8sDelete, k8sGet } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { Application, K8sObject } from "@/types/k8s";

function decode(v?: string): string {
  if (!v) return "";
  try {
    return atob(v);
  } catch {
    return "";
  }
}

/**
 * Detail view for a mongo (FerretDB) database. Unlike postgres there's no CNPG
 * Cluster CR; the database is the FerretDB + DocumentDB-Postgres stack a mongo
 * Application provisions, so we key off the owning Application and its
 * connection secret (<app>-mongo-app). Route name param = the Application name.
 */
export function MongoDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const [showUri, setShowUri] = useState(false);
  const navigate = useNavigate();
  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.application(namespace, name)),
    onSuccess: () => navigate({ to: "/databases" }),
  });

  const { data: app, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["mongo-app", namespace, name],
    queryFn: () => k8sGet<Application>(openinfraPaths.application(namespace, name)),
  });
  const { data: secret } = useQuery({
    queryKey: ["mongo-secret", namespace, name],
    queryFn: () =>
      k8sGet<K8sObject<unknown, unknown> & { data?: Record<string, string> }>(
        `/api/v1/namespaces/${namespace}/secrets/${name}-mongo-app`,
      ),
    retry: false,
  });

  if (isLoading) return <LoadingState label="Loading database…" />;
  if (isError || !app) return <ErrorState error={error} onRetry={refetch} />;

  const db = app.spec?.database;
  const uri = decode(secret?.data?.["MONGODB_URI"]);
  const health = claimHealth(app);
  const ha = Boolean(db?.highAvailability);

  return (
    <DetailShell
      backTo="/databases"
      backLabel="Databases"
      icon={<Database className="size-5" />}
      title={db?.name ?? name}
      subtitle={`MongoDB (FerretDB) · ${namespace}`}
      status={health}
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <ResourceNameRow kind="database" name={name} namespace={namespace} />
              <DetailRow label="Engine">
                <Badge variant="secondary">MongoDB (FerretDB)</Badge>
              </DetailRow>
              <DetailRow label="Database">{db?.name ?? "—"}</DetailRow>
              <DetailRow label="Namespace">{namespace}</DetailRow>
              <DetailRow label="Application">{name}</DetailRow>
              <DetailRow label="High availability">
                {ha
                  ? "On · 2 FerretDB replicas (proxy tier)"
                  : "Off (single replica)"}
              </DetailRow>
              <DetailRow label="Connection (MONGODB_URI)">
                <span className="flex items-center gap-1">
                  <code className="text-xs">
                    {uri ? (showUri ? uri : "•".repeat(16)) : "—"}
                  </code>
                  {uri ? (
                    <>
                      <button
                        onClick={() => setShowUri((s) => !s)}
                        className="text-muted-foreground hover:text-foreground"
                        aria-label={showUri ? "Hide URI" : "Show URI"}
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
              <DetailRow label="Apps consume it via">
                <code className="text-xs">MONGODB_URI</code> (any MongoDB driver)
              </DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="monitoring" className="pt-4">
          {/* Scoped to this database's FerretDB + DocumentDB-Postgres pods. */}
          <GrafanaEmbed
            uid="openinfra-app-overview"
            vars={{
              "var-namespace": namespace,
              "var-pod": `${name}-(mongo|docdb)-.*`,
            }}
          />
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={app} />
        </TabsContent>
      </Tabs>

      <DangerZone
        resourceLabel="Database"
        resourceName={db?.name ?? name}
        deleting={deleteMutation.isPending}
        onConfirm={() => deleteMutation.mutate()}
        confirmDescription={
          <>
            Permanently delete the application{" "}
            <span className="font-medium text-foreground">{name}</span> and its
            FerretDB database. This cannot be undone.
          </>
        }
      />
    </DetailShell>
  );
}
