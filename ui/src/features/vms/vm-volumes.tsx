import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Camera, HardDrive, Plus, RotateCcw, Trash2, Unplug } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  ApiError,
  k8sCreate,
  k8sDelete,
  k8sGet,
  k8sList,
  k8sReplace,
} from "@/lib/api";
import { kubevirtPaths, openinfraPaths, snapshotPaths } from "@/lib/k8s-paths";
import {
  OPENINFRA_GROUP,
  OPENINFRA_VERSION,
  type K8sObject,
  type Vmi,
  type Volume,
  type VolumeSnapshot,
} from "@/types/k8s";

// Live attach state comes from the VMI: hotplugged volumes carry a hotplugVolume
// marker in status.volumeStatus.
type VolumeStatusEntry = {
  name: string;
  target?: string;
  phase?: string;
  hotplugVolume?: unknown;
};

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/**
 * Storage tab: attach/detach EBS-style Volumes to a running VM (KubeVirt hotplug)
 * and snapshot/restore them (CSI VolumeSnapshots on Longhorn). All via the k8s
 * proxy — no bespoke backend. Hotplug needs a running VM.
 */
export function VmVolumesTab({
  namespace,
  vmName,
  vmi,
}: {
  namespace: string;
  vmName: string;
  vmi?: Vmi;
}) {
  const qc = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const running = vmi?.status?.phase === "Running";

  const volumesQuery = useQuery({
    queryKey: ["volumes", namespace],
    queryFn: () => k8sList<Volume>(openinfraPaths.volumes(namespace)),
    refetchInterval: 5000,
  });
  const snapsQuery = useQuery({
    queryKey: ["volumesnapshots", namespace],
    queryFn: () =>
      k8sList<VolumeSnapshot>(snapshotPaths.volumeSnapshots(namespace)),
    refetchInterval: 5000,
  });

  const volumes = volumesQuery.data?.items ?? [];
  const snapshots = snapsQuery.data?.items ?? [];

  // Volumes hot-attached to THIS VM (from the live VMI).
  const attached = useMemo(() => {
    const st = (vmi?.status as { volumeStatus?: VolumeStatusEntry[] } | undefined)
      ?.volumeStatus;
    return (st ?? []).filter((v) => v.hotplugVolume !== undefined);
  }, [vmi]);
  const attachedNames = new Set(attached.map((v) => v.name));
  const available = volumes.filter((v) => !attachedNames.has(v.metadata.name));

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["volumes", namespace] });
    void qc.invalidateQueries({ queryKey: ["volumesnapshots", namespace] });
    void qc.invalidateQueries({ queryKey: ["vmi", namespace, vmName] });
  };

  const attach = useMutation({
    mutationFn: (vol: string) =>
      // PUT AddVolumeOptions to the addvolume subresource (scsi bus is required
      // for hotplug). --persist == also update the VM spec, so it survives reboot.
      k8sReplace(kubevirtPaths.addVolume(namespace, vmName), {
        name: vol,
        disk: { name: vol, disk: { bus: "scsi" }, serial: vol },
        volumeSource: { persistentVolumeClaim: { claimName: vol } },
      }),
    onSuccess: invalidate,
  });
  const detach = useMutation({
    mutationFn: (vol: string) =>
      k8sReplace(kubevirtPaths.removeVolume(namespace, vmName), { name: vol }),
    onSuccess: invalidate,
  });
  const snapshot = useMutation({
    mutationFn: (vol: string) =>
      k8sCreate(snapshotPaths.volumeSnapshots(namespace), {
        apiVersion: "snapshot.storage.k8s.io/v1",
        kind: "VolumeSnapshot",
        metadata: { generateName: `${vol}-snap-`, namespace },
        spec: {
          volumeSnapshotClassName: "longhorn-snapshot",
          source: { persistentVolumeClaimName: vol },
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
          size: snap.status?.restoreSize ?? "10Gi",
          source: { snapshot: snap.metadata.name },
        },
      } as K8sObject),
    onSuccess: invalidate,
  });
  const delSnap = useMutation({
    mutationFn: (name: string) =>
      k8sDelete(snapshotPaths.volumeSnapshot(namespace, name)),
    onSuccess: invalidate,
  });
  const delVol = useMutation({
    mutationFn: (name: string) =>
      k8sDelete(openinfraPaths.volume(namespace, name)),
    onSuccess: invalidate,
  });

  const err =
    attach.error ||
    detach.error ||
    snapshot.error ||
    restore.error ||
    delSnap.error ||
    delVol.error;

  return (
    <div className="space-y-4">
      {err ? (
        <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {err instanceof ApiError ? err.message : "Action failed."}
        </div>
      ) : null}

      {/* Attached volumes */}
      <Card>
        <CardContent className="p-4">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-medium">Attached volumes</h3>
            <Button
              size="sm"
              onClick={() => setDialogOpen(true)}
              disabled={!running}
              title={running ? undefined : "Start the VM to attach volumes"}
            >
              <Plus className="size-4" /> Attach
            </Button>
          </div>
          {!running ? (
            <p className="text-xs text-muted-foreground">
              Start the VM to attach or detach volumes (live hotplug).
            </p>
          ) : attached.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No volumes attached. The root disk is separate and fixed; attach
              volumes here for extra storage.
            </p>
          ) : (
            <div className="divide-y divide-border">
              {attached.map((v) => (
                <div
                  key={v.name}
                  className="flex items-center justify-between py-2"
                >
                  <span className="flex items-center gap-2 text-sm">
                    <HardDrive className="size-4 text-muted-foreground" />
                    <span className="font-medium">{v.name}</span>
                    {v.target ? (
                      <code className="text-xs text-muted-foreground">
                        /dev/{v.target}
                      </code>
                    ) : null}
                    <Badge variant="secondary">{v.phase ?? "—"}</Badge>
                  </span>
                  <span className="flex gap-1">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => snapshot.mutate(v.name)}
                      disabled={snapshot.isPending}
                    >
                      <Camera className="size-4" /> Snapshot
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => detach.mutate(v.name)}
                      disabled={detach.isPending}
                    >
                      <Unplug className="size-4" /> Detach
                    </Button>
                  </span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Snapshots */}
      <Card>
        <CardContent className="p-4">
          <h3 className="mb-3 text-sm font-medium">Snapshots</h3>
          {snapshots.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No snapshots yet. Snapshot an attached volume to capture a
              point-in-time copy you can restore to a new volume.
            </p>
          ) : (
            <div className="divide-y divide-border">
              {snapshots.map((s) => (
                <div
                  key={s.metadata.name}
                  className="flex items-center justify-between py-2"
                >
                  <span className="flex items-center gap-2 text-sm">
                    <Camera className="size-4 text-muted-foreground" />
                    <span className="font-medium">{s.metadata.name}</span>
                    <code className="text-xs text-muted-foreground">
                      {s.spec?.source?.persistentVolumeClaimName}
                    </code>
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
                      <RotateCcw className="size-4" /> Restore
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => delSnap.mutate(s.metadata.name)}
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

      {/* Unattached volumes (manage/delete) */}
      {available.length > 0 ? (
        <Card>
          <CardContent className="p-4">
            <h3 className="mb-3 text-sm font-medium">Other volumes</h3>
            <div className="divide-y divide-border">
              {available.map((v) => (
                <div
                  key={v.metadata.name}
                  className="flex items-center justify-between py-2"
                >
                  <span className="flex items-center gap-2 text-sm">
                    <HardDrive className="size-4 text-muted-foreground" />
                    <span className="font-medium">{v.metadata.name}</span>
                    <code className="text-xs text-muted-foreground">
                      {v.spec?.size}
                    </code>
                    <span className="text-xs text-muted-foreground">
                      (unattached)
                    </span>
                  </span>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => delVol.mutate(v.metadata.name)}
                    disabled={delVol.isPending}
                  >
                    <Trash2 className="size-4" />
                  </Button>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      ) : null}

      <AttachDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        namespace={namespace}
        available={available}
        onAttach={(vol) => attach.mutate(vol)}
        onDone={() => setDialogOpen(false)}
      />
    </div>
  );
}

function AttachDialog({
  open,
  onOpenChange,
  namespace,
  available,
  onAttach,
  onDone,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  namespace: string;
  available: Volume[];
  onAttach: (vol: string) => void;
  onDone: () => void;
}) {
  const [mode, setMode] = useState<"new" | "existing">("new");
  const [name, setName] = useState("");
  const [size, setSize] = useState("20Gi");
  const [pick, setPick] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reset = () => {
    setName("");
    setSize("20Gi");
    setPick("");
    setError(null);
    setBusy(false);
  };

  const submit = async () => {
    setError(null);
    try {
      if (mode === "new") {
        if (!RFC1123.test(name)) {
          setError("Lowercase letters, numbers and hyphens only.");
          return;
        }
        setBusy(true);
        // Create the Volume, then poll until its PVC binds, then attach.
        await k8sCreate(openinfraPaths.volumes(namespace), {
          apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
          kind: "Volume",
          metadata: { name, namespace },
          spec: { size: size || "20Gi" },
        } as K8sObject);
        await waitBound(namespace, name);
        onAttach(name);
      } else {
        if (!pick) {
          setError("Pick a volume.");
          return;
        }
        setBusy(true);
        onAttach(pick);
      }
      reset();
      onDone();
    } catch (e) {
      setBusy(false);
      setError(e instanceof ApiError ? e.message : "Failed.");
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (busy) return;
        if (!o) reset();
        onOpenChange(o);
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Attach a volume</DialogTitle>
          <DialogDescription>
            Hot-attach a Longhorn volume to this VM. It appears as a raw disk in
            the guest; format and mount it there.
          </DialogDescription>
        </DialogHeader>

        <div className="flex gap-2">
          <Button
            variant={mode === "new" ? "default" : "outline"}
            size="sm"
            onClick={() => setMode("new")}
          >
            Create new
          </Button>
          <Button
            variant={mode === "existing" ? "default" : "outline"}
            size="sm"
            onClick={() => setMode("existing")}
            disabled={available.length === 0}
          >
            Attach existing
          </Button>
        </div>

        {mode === "new" ? (
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="vol-name">Name</Label>
              <Input
                id="vol-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="data-disk"
                autoFocus
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="vol-size">Size</Label>
              <Input
                id="vol-size"
                value={size}
                onChange={(e) => setSize(e.target.value)}
                placeholder="20Gi"
              />
            </div>
          </div>
        ) : (
          <div className="space-y-1.5">
            <Label htmlFor="vol-pick">Volume</Label>
            <Select value={pick} onValueChange={setPick}>
              <SelectTrigger id="vol-pick">
                <SelectValue placeholder="Select a volume" />
              </SelectTrigger>
              <SelectContent>
                {available.map((v) => (
                  <SelectItem key={v.metadata.name} value={v.metadata.name}>
                    {v.metadata.name} · {v.spec?.size}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        )}

        {error ? (
          <p className="text-sm text-destructive">{error}</p>
        ) : null}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy}>
            {busy ? "Attaching…" : "Attach"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// Poll the Volume's PVC until Bound (hotplug needs a bound PVC).
async function waitBound(namespace: string, name: string) {
  for (let i = 0; i < 30; i++) {
    try {
      const pvc = await k8sGet<K8sObject<unknown, { phase?: string }>>(
        `/api/v1/namespaces/${namespace}/persistentvolumeclaims/${name}`,
      );
      if (pvc.status?.phase === "Bound") return;
    } catch {
      /* not created yet */
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
}
