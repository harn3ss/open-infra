import { useMemo } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { Table2, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { type FilterPropertyDef } from "@/components/common/property-filter";
import { kindDocsUrl } from "@/lib/kind-docs";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import { type Table, type TableKey } from "@/types/k8s";

/** DynamoDB-style status: an Active/Creating verdict from the CR status. */
export function tableStatus(t: Table): { label: string; tone: StatusTone } {
  const ready = t.status?.conditions?.find((c) => c.type === "Ready");
  if (ready?.status === "True" || t.status?.ready) return { label: "Active", tone: "success" };
  return { label: "Creating", tone: "warning" };
}

/** PAY_PER_REQUEST is AWS's "On-demand"; PROVISIONED stays "Provisioned". */
export function billingLabel(mode?: string): string {
  return mode === "PROVISIONED" ? "Provisioned" : "On-demand";
}

/** A DynamoDB key as `name (S)` — attribute name + AWS attribute-type suffix. */
export function KeyCell({ keyDef }: { keyDef?: TableKey }) {
  if (!keyDef?.name) return <span className="text-muted-foreground">—</span>;
  return (
    <span className="inline-flex items-center gap-1">
      <code className="text-xs">{keyDef.name}</code>
      <span className="text-muted-foreground">({keyDef.type})</span>
    </span>
  );
}

export function TablesPage() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<Table, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (t) => t.spec?.tableName ?? t.metadata.name,
        cell: ({ row }) => (
          <Link
            to="/tables/$namespace/$name"
            params={{
              namespace: row.original.metadata.namespace ?? "default",
              name: row.original.metadata.name ?? "",
            }}
            className="font-medium text-primary hover:underline"
          >
            {row.original.spec?.tableName ?? row.original.metadata.name}
          </Link>
        ),
        size: 220,
      },
      {
        id: "partitionKey",
        header: "Partition key",
        accessorFn: (t) => t.spec?.hashKey?.name ?? "",
        cell: ({ row }) => <KeyCell keyDef={row.original.spec?.hashKey} />,
        size: 180,
      },
      {
        id: "sortKey",
        header: "Sort key",
        accessorFn: (t) => t.spec?.rangeKey?.name ?? "",
        cell: ({ row }) => <KeyCell keyDef={row.original.spec?.rangeKey} />,
        size: 180,
      },
      {
        id: "billing",
        header: "Capacity mode",
        accessorFn: (t) => billingLabel(t.spec?.billingMode),
        cell: ({ row }) => (
          <span className="text-muted-foreground">{billingLabel(row.original.spec?.billingMode)}</span>
        ),
        size: 140,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (t) => tableStatus(t).label,
        cell: ({ row }) => {
          const s = tableStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 120,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (t) => t.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
    ],
    [],
  );

  const filterProperties = useMemo<FilterPropertyDef<Table>[]>(
    () => [
      { key: "name", label: "Name", getValue: (t) => t.spec?.tableName ?? t.metadata.name },
      { key: "partitionKey", label: "Partition key", getValue: (t) => t.spec?.hashKey?.name },
      {
        key: "billing",
        label: "Capacity mode",
        getValue: (t) => billingLabel(t.spec?.billingMode),
        options: [{ value: "On-demand" }, { value: "Provisioned" }],
      },
      {
        key: "status",
        label: "Status",
        getValue: (t) => tableStatus(t).label,
        options: [{ value: "Active" }, { value: "Creating" }],
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<Table>
      icon={<Table2 />}
      title="Tables"
      description="Managed key/value tables (DynamoDB-compatible), served by the aws-shim DynamoDB front door. Each table has an immutable partition key and an optional sort key; items are read and written through the DynamoDB data API."
      listPath={openinfraPaths.tables}
      columns={columns}
      onRowClick={(t) =>
        navigate({
          to: "/tables/$namespace/$name",
          params: {
            namespace: t.metadata.namespace ?? "default",
            name: t.metadata.name ?? "",
          },
        })
      }
      search={(t) => [t.metadata.name, t.metadata.namespace, t.spec?.tableName, t.spec?.hashKey?.name]}
      singular="table"
      plural="tables"
      emptyTitle="No tables yet"
      emptyDescription="Create a table with a partition key (and an optional sort key), then read and write items through the DynamoDB data API."
      docsHref={kindDocsUrl("Table")}
      filterProperties={filterProperties}
      enablePreferences
      enablePagination
      columnLabels={{
        partitionKey: "Partition key",
        sortKey: "Sort key",
        billing: "Capacity mode",
      }}
      headerActions={
        <Button onClick={() => navigate({ to: "/tables/new" })}>
          <Plus className="size-4" /> Create table
        </Button>
      }
    />
  );
}
