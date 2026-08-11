import { useMemo } from "react";
import { useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { HardDrive, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import { type Condition, type Volume } from "@/types/k8s";

function volStatus(v: Volume): { label: string; tone: StatusTone } {
  const ready = (v.status as { conditions?: Condition[] } | undefined)?.conditions?.find(
    (c) => c.type === "Ready",
  );
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

export function VolumesPage() {
  const navigate = useNavigate();

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
    ],
    [],
  );

  return (
    <ResourceTablePage<Volume>
      icon={<HardDrive />}
      title="Volumes"
      description="Block volumes — open-infra's EBS. Attach them to VMs (on the VM's Storage tab), snapshot, and restore. Snapshots can back up to MinIO."
      listPath={openinfraPaths.volumes}
      columns={columns}
      onRowClick={(v) =>
        navigate({
          to: "/volumes/$namespace/$name",
          params: {
            namespace: v.metadata.namespace ?? "default",
            name: v.metadata.name ?? "",
          },
        })
      }
      search={(v) => [v.metadata.name, v.metadata.namespace, v.spec?.size]}
      singular="Volume"
      plural="Volumes"
      emptyTitle="No volumes yet"
      emptyDescription="Create a volume, then attach it to a VM from the VM's Storage tab."
      headerActions={
        <Button onClick={() => navigate({ to: "/volumes/new" })}>
          <Plus className="size-4" /> New Volume
        </Button>
      }
    />
  );
}
