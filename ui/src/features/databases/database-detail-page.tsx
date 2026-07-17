import { useState } from "react";
import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Database, Eye, EyeOff, Camera, Trash2 } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
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
import { DbStatsPanel } from "@/components/common/db-stats-panel";
import { Badge } from "@/components/ui/badge";
import { cnpgPaths, openinfraPaths } from "@/lib/k8s-paths";
import { type StatusTone, age, formatBytes } from "@/lib/format";
import type { Application, CnpgCluster, K8sObject } from "@/types/k8s";

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
  // "final snapshot before delete" (RDS-style): snapshot must COMPLETE before we remove
  // the database, or the dump Job races the deletion. So we take it, poll to ready, then delete.
  const [finalSnap, setFinalSnap] = useState(true);
  const [snapPhase, setSnapPhase] = useState<string | null>(null);
  async function deleteWithOptionalSnapshot() {
    if (finalSnap) {
      setSnapPhase("Taking final snapshot…");
      try {
        const snap = await createDbSnapshot(namespace, appName);
        for (let i = 0; i < 120; i++) {
          const s = (await listDbSnapshots()).find((x) => x.id === snap.id);
          if (s?.status === "ready") break;
          if (s?.status === "failed") throw new Error("the snapshot job failed");
          await new Promise((r) => setTimeout(r, 3000));
        }
      } catch (e) {
        setSnapPhase(null);
        alert(`Final snapshot failed — not deleting.\n${(e as Error).message}`);
        return;
      }
    }
    setSnapPhase(null);
    deleteMutation.mutate();
  }
  const navigate = useNavigate();
  // The CNPG cluster is named "<app>-db" and owned by its Application; deleting
  // the database means deleting that Application (Crossplane would otherwise
  // recreate the cluster). Strip the "-db" suffix to get the app name.
  const appName = name.replace(/-db$/, "");
  const deleteMutation = useMutation({
    mutationFn: () => k8sDelete(openinfraPaths.application(namespace, appName)),
    onSuccess: () => navigate({ to: "/databases" }),
  });

  // Snapshots for this database (logical pg_dump → MinIO).
  const snapsQ = useQuery({
    queryKey: ["db-snapshots", namespace, appName],
    queryFn: listDbSnapshots,
    select: (all: DbSnapshot[]) =>
      all
        .filter((s) => s.namespace === namespace && s.sourceName === appName)
        .sort((a, b) => (b.createdAt ?? "").localeCompare(a.createdAt ?? "")),
    refetchInterval: 8000,
  });
  const takeSnap = useMutation({
    mutationFn: () => createDbSnapshot(namespace, appName),
    onSuccess: () => void snapsQ.refetch(),
  });
  const delSnap = useMutation({
    mutationFn: (s: DbSnapshot) => deleteDbSnapshot(s.namespace, s.sourceName, s.id, s.kind),
    onSuccess: () => void snapsQ.refetch(),
  });

  const { data: db, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["database", namespace, name],
    queryFn: () => k8sGet<CnpgCluster>(cnpgPaths.cluster(namespace, name)),
  });
  // The owning data-only Application carries securityGroups (propagated to the
  // cluster's pods via inheritedMetadata by the composition).
  const { data: app, refetch: refetchApp } = useQuery({
    queryKey: ["database-app", namespace, appName],
    queryFn: () => k8sGet<Application>(openinfraPaths.application(namespace, appName)),
    retry: false,
  });
  const saveSgs = useMutation({
    mutationFn: async (next: string[]) => {
      const p = openinfraPaths.application(namespace, appName);
      const cur = await k8sGet<Application>(p);
      return k8sReplace<Application>(p, {
        ...cur,
        spec: { ...(cur.spec ?? {}), securityGroups: next },
      } as Application);
    },
    onSuccess: () => void refetchApp(),
  });
  // Start/Stop: toggle database.stopped on the owning Application (RDS stop/start).
  const setStopped = useMutation({
    mutationFn: async (stopped: boolean) => {
      const p = openinfraPaths.application(namespace, appName);
      const cur = await k8sGet<Application>(p);
      const spec = (cur.spec ?? {}) as Record<string, unknown>;
      const database = { ...((spec.database as Record<string, unknown>) ?? {}), stopped };
      return k8sReplace<Application>(p, { ...cur, spec: { ...spec, database } } as unknown as Application);
    },
    onSuccess: () => void refetchApp(),
  });
  // Convert non-HA <-> HA on demand: toggle database.highAvailability. CNPG scales the
  // instance count live (adds/removes a streaming-replication standby) — no recreate.
  const setHA = useMutation({
    mutationFn: async (highAvailability: boolean) => {
      const p = openinfraPaths.application(namespace, appName);
      const cur = await k8sGet<Application>(p);
      const spec = (cur.spec ?? {}) as Record<string, unknown>;
      const database = { ...((spec.database as Record<string, unknown>) ?? {}), highAvailability };
      return k8sReplace<Application>(p, { ...cur, spec: { ...spec, database } } as unknown as Application);
    },
    onSuccess: () => void refetchApp(),
  });
  // Live engine internals ("Peek") — refetched while the tab is open.
  const [peekOpen, setPeekOpen] = useState(false);
  const peekQ = useQuery({
    queryKey: ["database-peek", namespace, name],
    queryFn: () => getManagedDbStats(namespace, name),
    enabled: peekOpen,
    refetchInterval: peekOpen ? 5000 : false,
    retry: false,
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
  const dbSpec = (app?.spec as Record<string, unknown> | undefined)?.database as Record<string, unknown> | undefined;
  const stopped = Boolean(dbSpec?.stopped);
  const ha = Boolean(dbSpec?.highAvailability);
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
      <Tabs defaultValue="overview" onValueChange={(v) => setPeekOpen(v === "peek")}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="peek">Peek</TabsTrigger>
          <TabsTrigger value="connectivity">Connectivity</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
          <TabsTrigger value="snapshots">Snapshots</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger value="danger" className="text-destructive data-[state=active]:text-destructive">Danger Zone</TabsTrigger>
        </TabsList>

        <TabsContent value="peek" className="pt-4">
          <Card>
            <CardContent className="space-y-3 p-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-muted-foreground">
                  Live engine internals {peekQ.isFetching ? "· refreshing" : ""}
                </span>
              </div>
              <DbStatsPanel stats={peekQ.data} loading={peekQ.isFetching} error={peekQ.isError} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security" className="pt-4">
          <ResourceSecurityTab
            namespace={namespace}
            securityGroups={app?.spec?.securityGroups ?? []}
            onSave={(next) => saveSgs.mutate(next)}
            saving={saveSgs.isPending}
          />
        </TabsContent>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <ResourceNameRow kind="database" name={name} namespace={namespace} />
              <DetailRow label="Status">{stopped ? "Stopped" : (phase ?? "—")}</DetailRow>
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
              <DetailRow label="Instances">
                {ready}/{total} ready
              </DetailRow>
              <DetailRow label="High availability">
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">{ha ? "On · primary + standby (auto-failover)" : "Off · single instance"}</span>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={setHA.isPending || stopped}
                    onClick={() => setHA.mutate(!ha)}
                    title={stopped ? "Start the database first" : undefined}
                  >
                    {setHA.isPending ? "Working…" : ha ? "Make single-instance" : "Convert to HA"}
                  </Button>
                </div>
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

        <TabsContent value="snapshots" className="pt-4">
          <Card>
            <CardContent className="space-y-4 pt-6">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="font-medium">Snapshots</div>
                  <p className="text-sm text-muted-foreground">
                    A logical dump (<span className="font-mono">pg_dump</span>) kept in object
                    storage. It survives the database's deletion; restore it into a new database
                    from the <span className="font-medium text-foreground">Backup → Snapshots</span> page.
                  </p>
                </div>
                <Button
                  onClick={() => takeSnap.mutate()}
                  disabled={takeSnap.isPending || stopped}
                >
                  <Camera className="size-4" />
                  {takeSnap.isPending ? "Snapshotting…" : "Take snapshot"}
                </Button>
              </div>

              {stopped ? (
                <p className="text-sm text-muted-foreground">
                  The database is <span className="font-medium">stopped</span> — start it to take a
                  snapshot (a logical dump needs the database running).
                </p>
              ) : null}
              {takeSnap.isError ? (
                <p className="text-sm text-destructive">{(takeSnap.error as Error).message}</p>
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
                        <td className="py-2 text-muted-foreground">
                          {s.createdAt ? age(s.createdAt) : "—"}
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
          <YamlViewer value={db} />
        </TabsContent>
      <TabsContent value="danger" className="space-y-3 pt-4">
        <label className="flex items-start gap-2 rounded-md border p-3 text-sm">
          <input
            type="checkbox"
            className="mt-0.5"
            checked={finalSnap}
            onChange={(e) => setFinalSnap(e.target.checked)}
          />
          <span>
            <span className="font-medium">Take a final snapshot before deleting</span>
            <span className="block text-xs text-muted-foreground">
              A pg_dump kept in object storage that outlives this database — restore it
              into a new one from the Snapshots page. The delete waits for it to finish.
            </span>
          </span>
        </label>
<DangerZone
        resourceLabel="Database"
        resourceName={name}
        deleting={deleteMutation.isPending || snapPhase !== null}
        onConfirm={() => void deleteWithOptionalSnapshot()}
        confirmDescription={
          <>
            Permanently delete the application{" "}
            <span className="font-medium text-foreground">{appName}</span> and its
            PostgreSQL database. This cannot be undone.
            {finalSnap ? (
              <span className="mt-2 block text-xs">
                A final snapshot is taken first and kept in the Snapshots page.
              </span>
            ) : null}
            {snapPhase ? (
              <span className="mt-2 block text-xs text-foreground">{snapPhase}</span>
            ) : null}
          </>
        }
      />
        </TabsContent>
      </Tabs>

    </DetailShell>
  );
}
