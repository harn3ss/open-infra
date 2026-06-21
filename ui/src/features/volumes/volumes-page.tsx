import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { Camera, HardDrive, Plus, Trash2 } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
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
import { useMutation } from "@tanstack/react-query";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { ApiError, k8sCreate, k8sDelete } from "@/lib/api";
import { corePaths, openinfraPaths, snapshotPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import {
  OPENINFRA_GROUP,
  OPENINFRA_VERSION,
  type Condition,
  type K8sObject,
  type Volume,
} from "@/types/k8s";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

function volStatus(v: Volume): { label: string; tone: StatusTone } {
  const ready = (v.status as { conditions?: Condition[] } | undefined)?.conditions?.find(
    (c) => c.type === "Ready",
  );
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

export function VolumesPage() {
  const { scoped } = useNamespace();
  const [newOpen, setNewOpen] = useState(false);

  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = nsWatch.items
    .map((n) => n.metadata.name)
    .filter((n): n is string => Boolean(n))
    .sort((a, b) => a.localeCompare(b));

  const snapshot = useMutation({
    mutationFn: (v: Volume) =>
      k8sCreate(snapshotPaths.volumeSnapshots(v.metadata.namespace ?? "default"), {
        apiVersion: "snapshot.storage.k8s.io/v1",
        kind: "VolumeSnapshot",
        metadata: {
          generateName: `${v.metadata.name}-snap-`,
          namespace: v.metadata.namespace,
        },
        spec: {
          volumeSnapshotClassName: "longhorn-snapshot",
          source: { persistentVolumeClaimName: v.metadata.name },
        },
      } as unknown as K8sObject),
  });
  const remove = useMutation({
    mutationFn: (v: Volume) =>
      k8sDelete(
        openinfraPaths.volume(v.metadata.namespace ?? "default", v.metadata.name ?? ""),
      ),
  });

  const columns = useMemo<ColumnDef<Volume, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (v) => v.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 200,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (v) => v.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.metadata.namespace}</span>
        ),
        size: 120,
      },
      {
        id: "size",
        header: "Size",
        accessorFn: (v) => v.spec?.size ?? "",
        cell: ({ row }) => (
          <span className="font-mono text-xs">{row.original.spec?.size ?? "—"}</span>
        ),
        size: 100,
      },
      {
        id: "restored",
        header: "Source",
        accessorFn: (v) => v.spec?.source?.snapshot ?? "",
        cell: ({ row }) =>
          row.original.spec?.source?.snapshot ? (
            <span className="text-xs text-muted-foreground">
              from {row.original.spec.source.snapshot}
            </span>
          ) : (
            <span className="text-xs text-muted-foreground">blank</span>
          ),
        size: 160,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (v) => volStatus(v).label,
        cell: ({ row }) => {
          const s = volStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 130,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (v) => v.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => (
          <span className="flex justify-end gap-1">
            <Button
              size="sm"
              variant="outline"
              onClick={() => snapshot.mutate(row.original)}
              disabled={snapshot.isPending}
              title="Snapshot this volume"
            >
              <Camera className="size-4" />
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => remove.mutate(row.original)}
              disabled={remove.isPending}
              title="Delete this volume"
            >
              <Trash2 className="size-4" />
            </Button>
          </span>
        ),
        size: 110,
      },
    ],
    [snapshot, remove],
  );

  return (
    <>
      <ResourceTablePage<Volume>
        icon={<HardDrive />}
        title="Volumes"
        description="Block volumes — open-infra's EBS. Attach them to VMs (on the VM's Storage tab), snapshot, and restore. Snapshots can back up to MinIO."
        listPath={openinfraPaths.volumes}
        columns={columns}
        search={(v) => [v.metadata.name, v.metadata.namespace, v.spec?.size]}
        singular="Volume"
        plural="Volumes"
        emptyTitle="No volumes yet"
        emptyDescription="Create a volume, then attach it to a VM from the VM's Storage tab."
        headerActions={
          <Button onClick={() => setNewOpen(true)}>
            <Plus className="size-4" /> New Volume
          </Button>
        }
      />
      <NewVolumeDialog
        open={newOpen}
        onOpenChange={setNewOpen}
        namespaces={namespaces}
        defaultNamespace={scoped}
      />
    </>
  );
}

function NewVolumeDialog({
  open,
  onOpenChange,
  namespaces,
  defaultNamespace,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  namespaces: string[];
  defaultNamespace?: string;
}) {
  const [name, setName] = useState("");
  const [size, setSize] = useState("20Gi");
  const [namespace, setNamespace] = useState(defaultNamespace ?? "default");

  const create = useMutation({
    mutationFn: () =>
      k8sCreate(openinfraPaths.volumes(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "Volume",
        metadata: { name, namespace },
        spec: { size: size || "20Gi" },
      } as K8sObject),
    onSuccess: () => {
      setName("");
      setSize("20Gi");
      onOpenChange(false);
    },
  });

  return (
    <Dialog open={open} onOpenChange={(o) => !create.isPending && onOpenChange(o)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New Volume</DialogTitle>
          <DialogDescription>
            A Longhorn-backed block volume. Attach it to a VM from that VM's Storage tab.
          </DialogDescription>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1.5">
            <Label htmlFor="vol-name">Name</Label>
            <Input id="vol-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="data-disk" autoFocus />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="vol-size">Size</Label>
            <Input id="vol-size" value={size} onChange={(e) => setSize(e.target.value)} placeholder="20Gi" />
          </div>
          <div className="space-y-1.5 col-span-2">
            <Label htmlFor="vol-ns">Namespace</Label>
            <Select value={namespace} onValueChange={setNamespace}>
              <SelectTrigger id="vol-ns"><SelectValue placeholder="Namespace" /></SelectTrigger>
              <SelectContent>
                {(namespaces.length ? namespaces : [namespace]).map((ns) => (
                  <SelectItem key={ns} value={ns}>{ns}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
        {create.error ? (
          <p className="text-sm text-destructive">
            {create.error instanceof ApiError ? create.error.message : "Failed to create the volume."}
          </p>
        ) : null}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={create.isPending}>Cancel</Button>
          <Button onClick={() => create.mutate()} disabled={create.isPending || !RFC1123.test(name)}>
            {create.isPending ? "Creating…" : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
