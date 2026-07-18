import { useState } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Database, Eye, EyeOff, Camera, Trash2 } from "lucide-react";
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
import {
  k8sDelete,
  k8sGet,
  k8sReplace,
  getManagedDbStats,
  createDbSnapshot,
  listDbSnapshots,
  deleteDbSnapshot,
  type DbSnapshot,
} from "@/lib/api";
import { age, formatBytes, formatTimestamp } from "@/lib/format";
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
  babelfish: {
    label: "SQL Server (Babelfish) · experimental",
    secretSuffix: "-babelfish",
    uriKey: "SQLSERVER_URL",
    uriLabel: "Connection (SQLSERVER_URL · TDS 1433)",
    consume: "SQLSERVER_URL — any SQL Server driver (Encrypt=optional)",
    podRe: "babelfish",
    svcSuffix: "-babelfish",
    port: 1433,
    scheme: "sqlserver",
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

  // ── Snapshots (managed engines are Longhorn-backed → durable CSI VolumeSnapshot). ──
  const snapsQ = useQuery({
    queryKey: ["db-snapshots", namespace, name],
    queryFn: listDbSnapshots,
    select: (all: DbSnapshot[]) =>
      all
        .filter((s) => s.namespace === namespace && s.sourceName === name)
        .sort((a, b) => (b.createdAt ?? "").localeCompare(a.createdAt ?? "")),
    refetchInterval: 8000,
  });
  const takeSnap = useMutation({
    mutationFn: () => createDbSnapshot(namespace, name),
    onSuccess: () => void snapsQ.refetch(),
  });
  const delSnap = useMutation({
    mutationFn: (s: DbSnapshot) => deleteDbSnapshot(s.namespace, s.sourceName, s.id, s.kind),
    onSuccess: () => void snapsQ.refetch(),
  });

  // Danger Zone: optional "final snapshot before delete" (RDS-style). The delete WAITS for the
  // backup to finish uploading to MinIO before destroying the source — else it wouldn't survive.
  const [finalSnap, setFinalSnap] = useState(true);
  const [snapPhase, setSnapPhase] = useState<string | null>(null);
  async function deleteWithOptionalSnapshot() {
    try {
      if (finalSnap) {
        setSnapPhase("Taking a final snapshot…");
        await createDbSnapshot(namespace, name);
        for (let i = 0; i < 200; i++) {
          const mine = (await listDbSnapshots())
            .filter((s) => s.namespace === namespace && s.sourceName === name)
            .sort((a, b) => (b.createdAt ?? "").localeCompare(a.createdAt ?? ""));
          const latest = mine[0];
          if (latest?.status === "ready") break;
          if (latest?.status === "failed") throw new Error("the final snapshot failed — not deleting");
          await new Promise((r) => setTimeout(r, 3000));
        }
        setSnapPhase("Deleting…");
      }
      deleteMutation.mutate();
    } catch (err) {
      setSnapPhase(null);
      alert((err as Error).message);
    }
  }

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
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          {peekable ? <TabsTrigger value="peek">Peek</TabsTrigger> : null}
          <TabsTrigger value="connectivity">Connectivity</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
          <TabsTrigger value="snapshots">Snapshots</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

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

        <TabsContent value="snapshots" className="pt-4">
          <Card>
            <CardContent className="space-y-4 pt-6">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="font-medium">Snapshots</div>
                  <p className="text-sm text-muted-foreground">
                    A durable backup of this database's disk (Longhorn → object storage). It
                    survives the database's deletion; restore it into a new database from the{" "}
                    <span className="font-medium text-foreground">Backup → Snapshots</span> page.
                  </p>
                </div>
                <Button
                  onClick={() => takeSnap.mutate()}
                  disabled={takeSnap.isPending}
                >
                  <Camera className="size-4" />
                  {takeSnap.isPending ? "Snapshotting…" : "Take snapshot"}
                </Button>
              </div>

              {takeSnap.isError ? (
                <p className="text-sm text-destructive">
                  {(takeSnap.error as Error).message}
                </p>
              ) : null}

              {(snapsQ.data?.length ?? 0) === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No snapshots yet. Take one before you deprovision this database.
                </p>
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-muted-foreground">
                      <th className="py-2 font-medium">Taken</th>
                      <th className="py-2 text-right font-medium">Size</th>
                      <th className="py-2 font-medium">Status</th>
                      <th className="py-2 text-right font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {snapsQ.data?.map((s) => (
                      <tr key={s.id} className="border-b last:border-0">
                        <td className="py-2 text-muted-foreground" title={s.createdAt ? `${age(s.createdAt)} ago` : undefined}>
                          {formatTimestamp(s.createdAt)}
                        </td>
                        <td className="py-2 text-right tabular-nums">
                          {s.sizeBytes ? formatBytes(s.sizeBytes) : "—"}
                        </td>
                        <td className="py-2">
                          <Badge
                            variant={s.status === "ready" ? "default" : "secondary"}
                            className={s.status === "failed" ? "bg-destructive" : ""}
                          >
                            {s.status}
                          </Badge>
                        </td>
                        <td className="py-2 text-right">
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-destructive"
                            disabled={delSnap.isPending}
                            onClick={() => delSnap.mutate(s)}
                          >
                            <Trash2 className="size-3.5" />
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={app} />
        </TabsContent>
      <TabsContent value="danger" className="space-y-4 pt-4">
        <label className="flex items-start gap-3 rounded-lg border p-4 text-sm">
          <input
            type="checkbox"
            className="mt-0.5 size-4"
            checked={finalSnap}
            onChange={(ev) => setFinalSnap(ev.target.checked)}
          />
          <span>
            <span className="font-medium">Take a final snapshot before deleting</span>
            <span className="block text-muted-foreground">
              A durable backup is taken and confirmed complete before the database is
              removed, so you can restore it later (RDS-style). {snapPhase ?? ""}
            </span>
          </span>
        </label>
        <DangerZone
        resourceLabel="Database"
        resourceName={db?.name ?? name}
        deleting={deleteMutation.isPending || snapPhase !== null}
        onConfirm={() => void deleteWithOptionalSnapshot()}
        confirmDescription={
          <>
            Permanently delete the application{" "}
            <span className="font-medium text-foreground">{name}</span> and its{" "}
            {e.label} database. This cannot be undone.
            {finalSnap ? " A final snapshot will be taken first." : ""}
          </>
        }
      />
        </TabsContent>
      </Tabs>

    </DetailShell>
  );
}
