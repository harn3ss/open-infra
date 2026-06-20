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

// Per-engine wiring for the non-CNPG databases (no Cluster CR — the DB is the
// stack a mongo/mysql Application provisions, keyed off that Application).
const ENGINES = {
  mongo: {
    label: "MongoDB (FerretDB)",
    secretSuffix: "-mongo-app",
    uriKey: "MONGODB_URI",
    uriLabel: "Connection (MONGODB_URI)",
    consume: "MONGODB_URI (any MongoDB driver)",
    podRe: "(mongo|docdb)",
  },
  mysql: {
    label: "MySQL (MariaDB)",
    secretSuffix: "-mysql-app",
    uriKey: "DATABASE_URL",
    uriLabel: "Connection (DATABASE_URL)",
    consume: "DATABASE_URL (any MySQL driver)",
    podRe: "mysql",
  },
} as const;

/**
 * Detail view for a managed database that has no CloudNativePG Cluster CR —
 * mongo (FerretDB) or mysql (MariaDB). Keys off the owning Application + its
 * connection secret. Route name param = the Application name.
 */
export function ManagedDatabaseDetailPage() {
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
    queryKey: ["managed-db", namespace, name],
    queryFn: () => k8sGet<Application>(openinfraPaths.application(namespace, name)),
  });

  const engineKey = (app?.spec?.database?.engine ?? "mongo") as keyof typeof ENGINES;
  const e = ENGINES[engineKey] ?? ENGINES.mongo;

  const { data: secret } = useQuery({
    queryKey: ["managed-db-secret", namespace, name, engineKey],
    enabled: Boolean(app),
    queryFn: () =>
      k8sGet<K8sObject<unknown, unknown> & { data?: Record<string, string> }>(
        `/api/v1/namespaces/${namespace}/secrets/${name}${e.secretSuffix}`,
      ),
    retry: false,
  });

  if (isLoading) return <LoadingState label="Loading database…" />;
  if (isError || !app) return <ErrorState error={error} onRetry={refetch} />;

  const db = app.spec?.database;
  const uri = decode(secret?.data?.[e.uriKey]);
  const health = claimHealth(app);
  const ha = Boolean(db?.highAvailability);

  return (
    <DetailShell
      backTo="/databases"
      backLabel="Databases"
      icon={<Database className="size-5" />}
      title={db?.name ?? name}
      subtitle={`${e.label} · ${namespace}`}
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
                <Badge variant="secondary">{e.label}</Badge>
              </DetailRow>
              <DetailRow label="Database">{db?.name ?? "—"}</DetailRow>
              <DetailRow label="Namespace">{namespace}</DetailRow>
              <DetailRow label="Application">{name}</DetailRow>
              <DetailRow label="High availability">
                {engineKey === "mongo" && ha
                  ? "On · 2 FerretDB replicas (proxy tier)"
                  : "Off (single instance)"}
              </DetailRow>
              <DetailRow label={e.uriLabel}>
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
                <code className="text-xs">{e.consume}</code>
              </DetailRow>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="monitoring" className="pt-4">
          {/* Scoped to this database's backing pods. */}
          <GrafanaEmbed
            uid="openinfra-app-overview"
            vars={{
              "var-namespace": namespace,
              "var-pod": `${name}-${e.podRe}-.*`,
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
            <span className="font-medium text-foreground">{name}</span> and its{" "}
            {e.label} database. This cannot be undone.
          </>
        }
      />
    </DetailShell>
  );
}
