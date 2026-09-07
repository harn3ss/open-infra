import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { Boxes, Plus } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { type FilterPropertyDef } from "@/components/common/property-filter";
import { Button } from "@/components/ui/button";
import { applicationHealth } from "@/features/applications/application-status";
import { openinfraPaths } from "@/lib/k8s-paths";
import { kindDocsUrl } from "@/lib/kind-docs";
import { age } from "@/lib/format";
import type { Application } from "@/types/k8s";

export function ApplicationsPage() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<Application, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (a) => a.metadata.name,
        cell: ({ row }) => (
          <span className="font-medium">{row.original.metadata.name}</span>
        ),
        size: 220,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (a) => a.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {row.original.metadata.namespace}
          </span>
        ),
        size: 140,
      },
      {
        id: "image",
        header: "Image",
        accessorFn: (a) => a.spec?.image ?? "",
        cell: ({ row }) => (
          <code className="block max-w-[22rem] truncate text-xs">
            {row.original.spec?.image ?? "—"}
          </code>
        ),
        size: 320,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (a) => applicationHealth(a).label,
        cell: ({ row }) => {
          const h = applicationHealth(row.original);
          return <StatusBadge status={h.label} tone={h.tone} />;
        },
        size: 150,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (a) => a.metadata.creationTimestamp ?? "",
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

  const filterProperties = useMemo<FilterPropertyDef<Application>[]>(
    () => [
      { key: "name", label: "Name", getValue: (a) => a.metadata.name },
      {
        key: "namespace",
        label: "Namespace",
        getValue: (a) => a.metadata.namespace,
      },
      { key: "image", label: "Image", getValue: (a) => a.spec?.image },
      {
        key: "status",
        label: "Status",
        getValue: (a) => applicationHealth(a).label,
        options: [
          { value: "Ready" },
          { value: "Provisioning" },
          { value: "Pending" },
          { value: "Terminating" },
        ],
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<Application>
      icon={<Boxes />}
      title="Applications"
      description="The open-infra flagship resource. Declare intent; the platform provisions the rest."
      listPath={openinfraPaths.applications}
      columns={columns}
      search={(a) => [
        a.metadata.name,
        a.metadata.namespace,
        a.spec?.image,
        a.spec?.domain,
      ]}
      filterProperties={filterProperties}
      enablePreferences
      enablePagination
      columnLabels={{
        name: "Name",
        namespace: "Namespace",
        image: "Image",
        status: "Status",
        age: "Age",
      }}
      singular="Application"
      plural="Applications"
      emptyTitle="No Applications yet"
      emptyDescription="Create your first Application to spin up an autoscaling, HTTPS service with optional database, buckets, and queues."
      docsHref={kindDocsUrl("Application")}
      onRowClick={(a) =>
        navigate({
          to: "/applications/$namespace/$name",
          params: {
            namespace: a.metadata.namespace ?? "default",
            name: a.metadata.name ?? "",
          },
        })
      }
      headerActions={
        <Button onClick={() => navigate({ to: "/applications/new" })}>
          <Plus className="size-4" />
          New Application
        </Button>
      }
    />
  );
}
