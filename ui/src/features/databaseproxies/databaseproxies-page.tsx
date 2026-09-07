import { useMemo } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { DatabaseZap, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { type FilterPropertyDef } from "@/components/common/property-filter";
import { kindDocsUrl } from "@/lib/kind-docs";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import { type Condition, type DatabaseProxy } from "@/types/k8s";

function proxyStatus(p: DatabaseProxy): { label: string; tone: StatusTone } {
  const ready = (p.status as { conditions?: Condition[] } | undefined)?.conditions?.find(
    (c) => c.type === "Ready",
  );
  if (ready?.status === "True") return { label: "Available", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

function engineOf(p: DatabaseProxy): string {
  return p.spec?.engineFamily ?? "babelfish";
}

export function DatabaseProxiesPage() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<DatabaseProxy, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (p) => p.metadata.name,
        cell: ({ row }) => (
          <Link
            to="/database-proxies/$namespace/$name"
            params={{
              namespace: row.original.metadata.namespace ?? "default",
              name: row.original.metadata.name ?? "",
            }}
            className="font-medium text-primary hover:underline"
          >
            {row.original.metadata.name}
          </Link>
        ),
        size: 200,
      },
      {
        id: "targetDatabase",
        header: "Target DB",
        accessorFn: (p) => p.spec?.targetDatabase ?? "",
        cell: ({ row }) =>
          row.original.spec?.targetDatabase ? (
            <Link
              to="/databases/managed/$namespace/$name"
              params={{
                namespace: row.original.metadata.namespace ?? "default",
                name: row.original.spec.targetDatabase,
              }}
              className="text-primary hover:underline"
            >
              {row.original.spec.targetDatabase}
            </Link>
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
        size: 180,
      },
      {
        id: "engine",
        header: "Engine",
        accessorFn: (p) => engineOf(p),
        cell: ({ row }) => (
          <span className="text-muted-foreground">{engineOf(row.original)}</span>
        ),
        size: 130,
      },
      {
        id: "endpoint",
        header: "Endpoint",
        accessorFn: (p) => p.status?.endpoint ?? "",
        cell: ({ row }) => {
          const ep = row.original.status?.endpoint;
          if (ep) return <code className="text-xs">{ep}</code>;
          const s = proxyStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 260,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (p) => p.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
    ],
    [],
  );

  const filterProperties = useMemo<FilterPropertyDef<DatabaseProxy>[]>(
    () => [
      { key: "name", label: "Name", getValue: (p) => p.metadata.name },
      { key: "targetDatabase", label: "Target DB", getValue: (p) => p.spec?.targetDatabase },
      {
        key: "engine",
        label: "Engine",
        getValue: (p) => engineOf(p),
        options: [{ value: "babelfish" }, { value: "sqlserver" }],
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<DatabaseProxy>
      icon={<DatabaseZap />}
      title="Database Proxies"
      description="A pooled, connection-bounded endpoint in front of a managed SQL Server / Babelfish database (the AWS RDS Proxy path) — it terminates client logins, reuses warm backend connections, and caps concurrency."
      listPath={openinfraPaths.databaseproxies}
      columns={columns}
      onRowClick={(p) =>
        navigate({
          to: "/database-proxies/$namespace/$name",
          params: {
            namespace: p.metadata.namespace ?? "default",
            name: p.metadata.name ?? "",
          },
        })
      }
      search={(p) => [p.metadata.name, p.metadata.namespace, p.spec?.targetDatabase, engineOf(p)]}
      singular="database proxy"
      plural="database proxies"
      emptyTitle="No database proxies yet"
      emptyDescription="Create a database proxy to pool connections in front of a managed SQL Server / Babelfish database."
      docsHref={kindDocsUrl("DatabaseProxy")}
      filterProperties={filterProperties}
      enablePreferences
      enablePagination
      columnLabels={{ targetDatabase: "Target DB" }}
      headerActions={
        <Button onClick={() => navigate({ to: "/database-proxies/new" })}>
          <Plus className="size-4" /> Create database proxy
        </Button>
      }
    />
  );
}
