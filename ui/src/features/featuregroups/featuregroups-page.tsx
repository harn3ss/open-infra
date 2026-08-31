import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { Table2, Plus } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { kindDocsUrl } from "@/lib/kind-docs";
import { claimHealth } from "@/lib/resource-health";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { FeatureGroup } from "@/types/k8s";

/** kind: FeatureGroup — the online feature store (SageMaker Feature Store): low-latency
 *  PutRecord/GetRecord for real-time inference, backed by a per-group Valkey. */
export function FeatureGroupsPage() {
  const navigate = useNavigate();
  const columns = useMemo<ColumnDef<FeatureGroup, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (g) => g.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 220,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (g) => g.metadata.namespace,
        cell: ({ row }) => <span className="text-muted-foreground">{row.original.metadata.namespace}</span>,
        size: 140,
      },
      {
        id: "recordId",
        header: "Record identifier",
        accessorFn: (g) => g.spec?.recordIdentifier,
        cell: ({ row }) => <code className="text-xs">{row.original.spec?.recordIdentifier}</code>,
        size: 180,
      },
      {
        id: "features",
        header: "Features",
        accessorFn: (g) => g.spec?.features?.length ?? 0,
        cell: ({ row }) => (
          <span className="text-xs text-muted-foreground">{row.original.spec?.features?.length ?? 0}</span>
        ),
        size: 90,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (g) => claimHealth(g).label,
        cell: ({ row }) => {
          const h = claimHealth(row.original);
          return <StatusBadge status={h.label} tone={h.tone} />;
        },
        size: 140,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (g) => g.metadata.creationTimestamp ?? "",
        cell: ({ row }) => <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>,
        size: 90,
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<FeatureGroup>
      icon={<Table2 />}
      title="Feature Store"
      description="Online feature store — open-infra's SageMaker Feature Store. Low-latency PutRecord/GetRecord for real-time inference, backed by a per-group Valkey."
      listPath={openinfraPaths.featuregroups}
      columns={columns}
      search={(g) => [g.metadata.name, g.metadata.namespace, g.spec?.recordIdentifier]}
      singular="Feature Group"
      plural="Feature Groups"
      emptyTitle="No feature groups yet"
      emptyDescription="Create a feature group with a record identifier; then PutRecord / GetRecord against its endpoint."
      docsHref={kindDocsUrl("FeatureGroup")}
      headerActions={
        <Button onClick={() => navigate({ to: "/feature-store/new" })}>
          <Plus className="size-4" />
          New Feature Group
        </Button>
      }
      onRowClick={(g) =>
        navigate({
          to: "/feature-store/$namespace/$name",
          params: { namespace: g.metadata.namespace ?? "default", name: g.metadata.name ?? "" },
        })
      }
    />
  );
}
