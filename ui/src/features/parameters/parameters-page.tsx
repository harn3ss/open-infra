import { useMemo } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { SlidersHorizontal, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { type FilterPropertyDef } from "@/components/common/property-filter";
import { kindDocsUrl } from "@/lib/kind-docs";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import { type Parameter } from "@/types/k8s";

function typeOf(p: Parameter): string {
  return p.spec?.type ?? "String";
}
function tierOf(p: Parameter): string {
  return p.spec?.tier ?? "Standard";
}
/** The stored path (status is authoritative once reconciled; spec.path is the intent). */
function pathOf(p: Parameter): string {
  return p.status?.path ?? p.spec?.path ?? "";
}

export function ParametersPage() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<Parameter, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (p) => p.metadata.name,
        cell: ({ row }) => (
          <Link
            to="/parameters/$namespace/$name"
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
        id: "path",
        header: "Path",
        accessorFn: (p) => pathOf(p),
        cell: ({ row }) => {
          const path = pathOf(row.original);
          return path ? (
            <code className="text-xs">{path}</code>
          ) : (
            <span className="text-muted-foreground">—</span>
          );
        },
        size: 280,
      },
      {
        id: "type",
        header: "Type",
        accessorFn: (p) => typeOf(p),
        cell: ({ row }) => {
          const t = typeOf(row.original);
          return (
            <StatusBadge
              status={t}
              tone={t === "SecureString" ? "accent" : "muted"}
            />
          );
        },
        size: 140,
      },
      {
        id: "tier",
        header: "Tier",
        accessorFn: (p) => tierOf(p),
        cell: ({ row }) => (
          <span className="text-muted-foreground">{tierOf(row.original)}</span>
        ),
        size: 120,
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

  // Property filter — path (contains) gives the SSM hierarchy feel (e.g. path : /app/db).
  const filterProperties = useMemo<FilterPropertyDef<Parameter>[]>(
    () => [
      { key: "name", label: "Name", getValue: (p) => p.metadata.name },
      { key: "path", label: "Path", getValue: (p) => pathOf(p) },
      {
        key: "type",
        label: "Type",
        getValue: (p) => typeOf(p),
        options: [{ value: "String" }, { value: "SecureString" }],
      },
      {
        key: "tier",
        label: "Tier",
        getValue: (p) => tierOf(p),
        options: [{ value: "Standard" }, { value: "Advanced" }],
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<Parameter>
      icon={<SlidersHorizontal />}
      title="Parameters"
      description="Hierarchical configuration and secrets stored by path (AWS SSM Parameter Store). String values are stored in the clear; SecureString values are encrypted (Vault-backed) and never shown in the console."
      listPath={openinfraPaths.parameters}
      columns={columns}
      onRowClick={(p) =>
        navigate({
          to: "/parameters/$namespace/$name",
          params: {
            namespace: p.metadata.namespace ?? "default",
            name: p.metadata.name ?? "",
          },
        })
      }
      search={(p) => [p.metadata.name, p.metadata.namespace, pathOf(p), typeOf(p)]}
      singular="parameter"
      plural="parameters"
      emptyTitle="No parameters yet"
      emptyDescription="Create a parameter to store a configuration value or secret by path, then read it from your applications."
      docsHref={kindDocsUrl("Parameter")}
      filterProperties={filterProperties}
      enablePreferences
      enablePagination
      headerActions={
        <Button onClick={() => navigate({ to: "/parameters/new" })}>
          <Plus className="size-4" /> Create parameter
        </Button>
      }
    />
  );
}
