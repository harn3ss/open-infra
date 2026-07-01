import { useState } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Database, Eye, EyeOff } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { CopyButton } from "@/components/common/copy-button";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { GrafanaEmbed } from "@/components/common/grafana-embed";
import { ResourceNameRow } from "@/components/common/resource-name-row";
import { DbConnectivity } from "@/components/common/db-connectivity";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { ResourceSecurityTab } from "@/components/common/resource-security-tab";
import { claimHealth } from "@/lib/resource-health";
import { k8sDelete, k8sGet, k8sReplace, getManagedDbStats } from "@/lib/api";
import { DbStatsPanel } from "@/components/common/db-stats-panel";
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
    svcSuffix: "-mongo",
    port: 27017,
    scheme: "mongodb",
  },
  mysql: {
    label: "MySQL (MariaDB)",
    secretSuffix: "-mysql-app",
    uriKey: "DATABASE_URL",
    uriLabel: "Connection (DATABASE_URL)",
    consume: "DATABASE_URL (any MySQL driver)",
    podRe: "mysql",
    svcSuffix: "-mysql",
    port: 3306,
    scheme: "mysql",
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

  const saveSgs = useMutation({
    mutationFn: async (next: string[]) => {
      const p = openinfraPaths.application(namespace, name);
      const cur = await k8sGet<Application>(p);
      return k8sReplace<Application>(p, {
        ...cur,
        spec: { ...(cur.spec ?? {}), securityGroups: next },
      } as Application);
    },
    onSuccess: () => void refetch(),
  });
  // Start/Stop: toggle database.stopped (RDS stop/start) — scales the engine to 0, keeps the PVC.
  const setStopped = useMutation({
    mutationFn: async (stopped: boolean) => {
      const p = openinfraPaths.application(namespace, name);
      const cur = await k8sGet<Application>(p);
      const spec = (cur.spec ?? {}) as Record<string, unknown>;
      const database = { ...((spec.database as Record<string, unknown>) ?? {}), stopped };
      return k8sReplace<Application>(p, { ...cur, spec: { ...spec, database } } as unknown as Application);
    },
    onSuccess: () => void refetch(),
  });
  // Convert non-HA <-> HA on demand: mongo scales the FerretDB proxy tier; mysql converts
  // the standalone MariaDB to a 3-node Galera cluster.
  const setHA = useMutation({
    mutationFn: async (highAvailability: boolean) => {
      const p = openinfraPaths.application(namespace, name);
      const cur = await k8sGet<Application>(p);
      const spec = (cur.spec ?? {}) as Record<string, unknown>;
      const database = { ...((spec.database as Record<string, unknown>) ?? {}), highAvailability };
      return k8sReplace<Application>(p, { ...cur, spec: { ...spec, database } } as unknown as Application);
    },
    onSuccess: () => void refetch(),
  });

  const engineKey = (app?.spec?.database?.engine ?? "mongo") as keyof typeof ENGINES;
  const e = ENGINES[engineKey] ?? ENGINES.mongo;

  // Peek (live engine internals) — only the SQL engines expose stats; MongoDB doesn't.
  const peekable = engineKey === "mysql";
  const [peekOpen, setPeekOpen] = useState(false);
  const peekQ = useQuery({
    queryKey: ["managed-db-peek", namespace, name],
    queryFn: () => getManagedDbStats(namespace, name),
    enabled: peekOpen && peekable,
    refetchInterval: peekOpen ? 5000 : false,
    retry: false,
  });

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
  const stopped = Boolean((db as Record<string, unknown> | undefined)?.stopped);

  return (
    <DetailShell
      backTo="/databases"
      backLabel="Databases"
      icon={<Database className="size-5" />}
      title={db?.name ?? name}
      subtitle={`${e.label} · ${namespace}`}
      status={health}
    >
      <Tabs defaultValue="overview" onValueChange={(v) => setPeekOpen(v === "peek")}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          {peekable ? <TabsTrigger value="peek">Peek</TabsTrigger> : null}
          <TabsTrigger value="connectivity">Connectivity</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
        </TabsList>
            <DangerZone inline
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
          </div>

        {peekable ? (
          <TabsContent value="peek" className="pt-4">
            <Card>
              <CardContent className="space-y-3 p-4">
                <span className="text-xs font-medium text-muted-foreground">
                  Live engine internals {peekQ.isFetching ? "· refreshing" : ""}
                </span>
                <DbStatsPanel stats={peekQ.data} loading={peekQ.isFetching} error={peekQ.isError} />
              </CardContent>
            </Card>
          </TabsContent>
        ) : null}

        <TabsContent value="security" className="pt-4">
          <ResourceSecurityTab
            namespace={namespace}
            securityGroups={app.spec?.securityGroups ?? []}
            onSave={(next) => saveSgs.mutate(next)}
            saving={saveSgs.isPending}
          />
        </TabsContent>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <ResourceNameRow kind="database" name={name} namespace={namespace} />
              <DetailRow label="Engine">
                <Badge variant="secondary">{e.label}</Badge>
              </DetailRow>
              <DetailRow label="Power">
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">{stopped ? "Stopped — data retained, compute off" : "Running"}</span>
                  <Button
                    size="sm"
                    variant={stopped ? "default" : "outline"}
                    disabled={setStopped.isPending}
                    onClick={() => setStopped.mutate(!stopped)}
                  >
                    {setStopped.isPending ? "Working…" : stopped ? "Start" : "Stop"}
                  </Button>
                </div>
              </DetailRow>
              <DetailRow label="Database">{db?.name ?? "—"}</DetailRow>
              <DetailRow label="Namespace">{namespace}</DetailRow>
              <DetailRow label="Application">{name}</DetailRow>
              <DetailRow label="High availability">
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">
                    {ha
                      ? engineKey === "mongo"
                        ? "On · 2 FerretDB replicas (proxy tier)"
                        : "On · Galera 3-node cluster"
                      : "Off (single instance)"}
                  </span>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={setHA.isPending || stopped}
                    onClick={() => setHA.mutate(!ha)}
                    title={stopped ? "Start the database first" : engineKey === "mysql" ? "Converts the standalone MariaDB to a 3-node Galera cluster" : undefined}
                  >
                    {setHA.isPending ? "Working…" : ha ? "Make single-instance" : "Convert to HA"}
                  </Button>
                </div>
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

        <TabsContent value="connectivity" className="pt-4">
          <DbConnectivity
            namespace={namespace}
            internalSvc={`${name}${e.svcSuffix}`}
            lanSvc={`${name}-db-lan`}
            port={e.port}
            scheme={e.scheme}
          />
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

    </DetailShell>
  );
}
