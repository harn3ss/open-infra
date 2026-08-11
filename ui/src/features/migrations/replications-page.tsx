import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { Repeat, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { kindDocsUrl } from "@/lib/kind-docs";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age, type StatusTone } from "@/lib/format";
import type { Replication } from "@/types/k8s";

function replStatus(r: Replication): { label: string; tone: StatusTone } {
  const conds = r.status?.conditions ?? [];
  const ready = conds.find((c) => c.type === "Ready");
  const synced = conds.find((c) => c.type === "Synced");
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  if (synced?.status === "False") return { label: "Error", tone: "destructive" };
  return { label: "Provisioning", tone: "warning" };
}

export function ReplicationsPage() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<Replication, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (r) => r.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 150,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (r) => r.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.metadata.namespace}</span>
        ),
        size: 110,
      },
      {
        id: "topology",
        header: "Sites",
        accessorFn: (r) => r.spec?.siteA?.engine ?? "",
        cell: ({ row }) => {
          const a = row.original.spec?.siteA;
          const b = row.original.spec?.siteB;
          return (
            <span className="text-xs">
              <code>{a?.engine}</code> <span className="text-muted-foreground">{a?.name}</span>
              {" ⇄ "}
              <code>{b?.engine}</code> <span className="text-muted-foreground">{b?.name}</span>
            </span>
          );
        },
        size: 280,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (r) => replStatus(r).label,
        cell: ({ row }) => {
          const s = replStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 110,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (r) => r.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<Replication>
      icon={<Repeat />}
      title="Replication"
      description="Bidirectional / multi-master replication — keep two databases in sync both ways (each is source and target), even across engines (e.g. SQL Server ⇄ Postgres). Loop-prevented, with last-write-wins conflict resolution. Open one to watch live lag, per-table throughput, and dead-letters."
      listPath={openinfraPaths.replications}
      columns={columns}
      search={(r) => [r.metadata.name, r.metadata.namespace, r.spec?.siteA?.engine, r.spec?.siteB?.engine]}
      singular="Replication"
      plural="Replications"
      emptyTitle="No replications yet"
      emptyDescription="Create a bidirectional replication between two databases."
      docsHref={kindDocsUrl("Replication")}
      onRowClick={(r) =>
        navigate({
          to: "/replications/$namespace/$name",
          params: {
            namespace: r.metadata.namespace ?? "default",
            name: r.metadata.name ?? "",
          },
        })
      }
      headerActions={
        <Button onClick={() => navigate({ to: "/replications/new" })}>
          <Plus className="size-4" />
          New Replication
        </Button>
      }
    />
  );
}
