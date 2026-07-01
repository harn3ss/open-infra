import { useParams, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Camera, HardDrive, RotateCcw, Trash2 } from "lucide-react";
import { DetailShell } from "@/components/common/detail-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DetailRow } from "@/components/common/detail-row";
import { YamlViewer } from "@/components/common/yaml-viewer";
import { DangerZone } from "@/components/common/danger-zone";
import { LoadingState, ErrorState } from "@/components/common/states";
import { ApiError, k8sCreate, k8sDelete, k8sGet, k8sList } from "@/lib/api";
import { openinfraPaths, snapshotPaths } from "@/lib/k8s-paths";
import {
  OPENINFRA_GROUP,
  OPENINFRA_VERSION,
  type K8sObject,
  type Volume,
  type VolumeSnapshot,
} from "@/types/k8s";

export function VolumeDetailPage() {
  const { namespace, name } = useParams({ strict: false }) as {
    namespace: string;
    name: string;
  };
  const navigate = useNavigate();
  const qc = useQueryClient();
  const path = openinfraPaths.volume(namespace, name);

  const { data: vol, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["volume", namespace, name],
    queryFn: () => k8sGet<Volume>(path),
    refetchInterval: 5000,
  });
  const snapsQuery = useQuery({
    queryKey: ["volumesnapshots", namespace],
    queryFn: () => k8sList<VolumeSnapshot>(snapshotPaths.volumeSnapshots(namespace)),
    refetchInterval: 5000,
  });
  // snapshots taken from THIS volume's PVC (a Volume's PVC is named after it).
  const snaps = (snapsQuery.data?.items ?? []).filter(
    (s) => s.spec?.source?.persistentVolumeClaimName === name,
  );

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["volume", namespace, name] });
    void qc.invalidateQueries({ queryKey: ["volumesnapshots", namespace] });
  };

  const snapshot = useMutation({
    mutationFn: () =>
      k8sCreate(snapshotPaths.volumeSnapshots(namespace), {
        apiVersion: "snapshot.storage.k8s.io/v1",
        kind: "VolumeSnapshot",
        metadata: { generateName: `${name}-snap-`, namespace },
        spec: {
          volumeSnapshotClassName: "longhorn-snapshot",
          source: { persistentVolumeClaimName: name },
        },
      } as unknown as K8sObject),
    onSuccess: invalidate,
  });
  const restore = useMutation({
    mutationFn: (snap: VolumeSnapshot) =>
      k8sCreate(openinfraPaths.volumes(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "Volume",
        metadata: { name: `${snap.metadata.name}-restored`, namespace },
        spec: {
          size: snap.status?.restoreSize ?? vol?.spec?.size ?? "10Gi",
          source: { snapshot: snap.metadata.name },
          migratable: vol?.spec?.migratable,
        },
      } as K8sObject),
    onSuccess: invalidate,
  });
  const delSnap = useMutation({
    mutationFn: (snapName: string) =>
      k8sDelete(snapshotPaths.volumeSnapshot(namespace, snapName)),
    onSuccess: invalidate,
  });
  const del = useMutation({
    mutationFn: () => k8sDelete(path),
    onSuccess: () => navigate({ to: "/volumes" }),
  });

  if (isLoading) return <LoadingState label="Loading volume…" />;
  if (isError || !vol) return <ErrorState error={error} onRetry={refetch} />;

  const migratable = vol.spec?.migratable;
  const actionErr = snapshot.error || restore.error || delSnap.error;

  return (
    <DetailShell
      backTo="/volumes"
      backLabel="Volumes"
      icon={<HardDrive className="size-5" />}
      title={name}
      subtitle={`Volume · ${namespace}`}
      actions={
        <Button onClick={() => snapshot.mutate()} disabled={snapshot.isPending}>
          <Camera className="size-4" /> Snapshot
        </Button>
      }
    >
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="snapshots">Snapshots ({snaps.length})</TabsTrigger>
          <TabsTrigger value="yaml">YAML</TabsTrigger>
          <TabsTrigger
            value="danger"
            className="text-destructive data-[state=active]:text-destructive"
          >
            Danger Zone
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="pt-4">
          <Card>
            <CardContent className="divide-y divide-border p-0">
              <DetailRow label="Namespace">{namespace}</DetailRow>
              <DetailRow label="Size">{vol.spec?.size ?? "—"}</DetailRow>
              <DetailRow label="Type">
                {migratable
                  ? "High-availability — RWX block, live-migratable"
                  : "Standard — RWO block"}
              </DetailRow>
              <DetailRow label="Status">{vol.status?.phase ?? "—"}</DetailRow>
            </CardContent>
          </Card>
          <p className="mt-3 text-xs text-muted-foreground">
            Attach this volume to a VM from that VM's Storage tab. It appears as a raw
            disk in the guest; format and mount it there.
          </p>
        </TabsContent>

        <TabsContent value="snapshots" className="pt-4">
          {actionErr ? (
            <div className="mb-3 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
              {actionErr instanceof ApiError ? actionErr.message : "Action failed."}
            </div>
          ) : null}
          <Card>
            <CardContent className="p-4">
              {snaps.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No snapshots yet. Use <strong>Snapshot</strong> (top right) to capture a
                  point-in-time copy you can restore to a new volume.
                </p>
              ) : (
                <div className="divide-y divide-border">
                  {snaps.map((s) => (
                    <div
                      key={s.metadata.name}
                      className="flex items-center justify-between py-2"
                    >
                      <span className="flex items-center gap-2 text-sm">
                        <Camera className="size-4 text-muted-foreground" />
                        <span className="font-medium">{s.metadata.name}</span>
                        <Badge variant={s.status?.readyToUse ? "secondary" : "outline"}>
                          {s.status?.readyToUse ? "ready" : "pending"}
                        </Badge>
                      </span>
                      <span className="flex gap-1">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => restore.mutate(s)}
                          disabled={restore.isPending || !s.status?.readyToUse}
                        >
                          <RotateCcw className="size-4" /> Restore to new volume
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => delSnap.mutate(s.metadata.name ?? "")}
                          disabled={delSnap.isPending}
                        >
                          <Trash2 className="size-4" />
                        </Button>
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="yaml" className="pt-4">
          <YamlViewer value={vol} />
        </TabsContent>

        <TabsContent value="danger" className="pt-4">
          <DangerZone
            resourceLabel="Volume"
            resourceName={name}
            deleting={del.isPending}
            onConfirm={() => del.mutate()}
            confirmDescription={
              <>
                Permanently delete volume{" "}
                <span className="font-medium text-foreground">{name}</span> and its data.
                Detach it from any VM first. This cannot be undone.
              </>
            }
          />
        </TabsContent>
      </Tabs>
    </DetailShell>
  );
}
