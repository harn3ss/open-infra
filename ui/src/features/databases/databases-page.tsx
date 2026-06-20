import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { Database } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { cnpgPaths } from "@/lib/k8s-paths";
import { age, type StatusTone } from "@/lib/format";
import type { CnpgCluster } from "@/types/k8s";

/** CloudNativePG reports a free-text status.phase ("Cluster in healthy state", …). */
function dbTone(phase?: string): StatusTone {
  if (!phase) return "muted";
  const p = phase.toLowerCase();
  if (p.includes("healthy")) return "success";
  if (p.includes("fail") || p.includes("unhealth") || p.includes("error")) {
    return "destructive";
  }
  return "warning";
}

export function DatabasesPage() {
  const navigate = useNavigate();
  const columns = useMemo<ColumnDef<CnpgCluster, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (c) => c.metadata.name,
        cell: ({ row }) => (
          <span className="font-medium">{row.original.metadata.name}</span>
        ),
        size: 220,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (c) => c.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {row.original.metadata.namespace}
          </span>
        ),
        size: 140,
      },
      {
        id: "instances",
        header: "Instances",
        accessorFn: (c) => c.status?.readyInstances ?? 0,
        cell: ({ row }) => {
          const s = row.original;
          const ready = s.status?.readyInstances ?? 0;
          const total = s.spec?.instances ?? s.status?.instances ?? 1;
          return (
            <span className="text-xs text-muted-foreground">
              {ready}/{total} ready
            </span>
          );
        },
        size: 120,
      },
      {
        id: "storage",
        header: "Storage",
        accessorFn: (c) => c.spec?.storage?.size ?? "",
        cell: ({ row }) => (
          <span className="text-xs text-muted-foreground">
            {row.original.spec?.storage?.size ?? "—"}
          </span>
        ),
        size: 100,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (c) => c.status?.phase ?? "",
        cell: ({ row }) => {
          const phase = row.original.status?.phase;
          return (
            <StatusBadge status={phase ?? "Pending"} tone={dbTone(phase)} />
          );
        },
        size: 220,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (c) => c.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {age(row.original.metadata.creationTimestamp)}
          </span>
        ),
        size: 90,
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<CnpgCluster>
      icon={<Database />}
      title="Databases"
      description="Managed PostgreSQL — open-infra's RDS (CloudNativePG). Provisioned by an Application's `database:` block."
      listPath={cnpgPaths.clusters}
      columns={columns}
      search={(c) => [c.metadata.name, c.metadata.namespace, c.status?.phase]}
      singular="Database"
      plural="Databases"
      emptyTitle="No Databases yet"
      emptyDescription="Add `database: { engine: postgres }` to an Application and the platform provisions a Postgres cluster here."
      onRowClick={(c) =>
        navigate({
          to: "/databases/$namespace/$name",
          params: {
            namespace: c.metadata.namespace ?? "default",
            name: c.metadata.name ?? "",
          },
        })
      }
    />
  );
}
