import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { ArrowRightLeft, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import type { Migration } from "@/types/k8s";

// A Migration's status, derived from the claim's Crossplane conditions.
function migStatus(m: Migration): { label: string; tone: StatusTone } {
  const conds = m.status?.conditions ?? [];
  const ready = conds.find((c) => c.type === "Ready");
  const synced = conds.find((c) => c.type === "Synced");
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  if (synced?.status === "False") return { label: "Error", tone: "destructive" };
  return { label: "Provisioning", tone: "warning" };
}

export function MigrationsPage() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<Migration, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (m) => m.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 150,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (m) => m.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.metadata.namespace}</span>
        ),
        size: 110,
      },
      {
        id: "mode",
        header: "Type",
        accessorFn: (m) => m.spec?.mode ?? "full-load",
        cell: ({ row }) => <span className="text-xs">{row.original.spec?.mode ?? "full-load"}</span>,
        size: 130,
      },
      {
        id: "route",
        header: "Route",
        accessorFn: (m) => m.spec?.source?.engine ?? "",
        cell: ({ row }) => {
          const s = row.original.spec?.source;
          const t = row.original.spec?.target;
          return (
            <span className="text-xs">
              <code>{s?.engine}</code>{" "}
              <span className="text-muted-foreground">{s?.host}</span>
              {" → "}
              <code>{t?.engine ?? "postgres"}</code>{" "}
              <span className="text-muted-foreground">{t?.host}</span>
            </span>
          );
        },
        size: 280,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (m) => migStatus(m).label,
        cell: ({ row }) => {
          const s = migStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 110,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (m) => m.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<Migration>
      icon={<ArrowRightLeft />}
      title="Migrations"
      description="Database migrations — open-infra's DMS. Full-load and/or ongoing CDC sync from a source database (Postgres, MySQL, MariaDB, SQL Server) into a target SQL database (Postgres, MySQL, or SQL Server). Like AWS DMS: define source + target endpoints, pick a task type, and it keeps your data flowing."
      listPath={openinfraPaths.migrations}
      columns={columns}
      search={(m) => [m.metadata.name, m.metadata.namespace, m.spec?.source?.engine, m.spec?.source?.host]}
      singular="Migration"
      plural="Migrations"
      emptyTitle="No migrations yet"
      emptyDescription="Create one to full-load or continuously sync a source database into a managed Postgres."
      onRowClick={(m) =>
        navigate({
          to: "/migrations/$namespace/$name",
          params: {
            namespace: m.metadata.namespace ?? "default",
            name: m.metadata.name ?? "",
          },
        })
      }
      headerActions={
        <Button onClick={() => navigate({ to: "/migrations/new" })}>
          <Plus className="size-4" /> New Migration
        </Button>
      }
    />
  );
}
