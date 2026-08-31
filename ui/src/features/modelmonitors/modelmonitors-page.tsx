import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { Gauge, Plus } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { kindDocsUrl } from "@/lib/kind-docs";
import { claimHealth } from "@/lib/resource-health";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { ModelMonitor } from "@/types/k8s";

/** kind: ModelMonitor — scheduled data-drift monitoring (SageMaker Model Monitor).
 *  On a cron schedule it compares recent data to a baseline and flags drift. */
export function ModelMonitorsPage() {
  const navigate = useNavigate();
  const columns = useMemo<ColumnDef<ModelMonitor, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (m) => m.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 200,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (m) => m.metadata.namespace,
        cell: ({ row }) => <span className="text-muted-foreground">{row.original.metadata.namespace}</span>,
        size: 130,
      },
      {
        id: "schedule",
        header: "Schedule",
        accessorFn: (m) => m.spec?.schedule ?? "0 * * * *",
        cell: ({ row }) => <code className="text-xs">{row.original.spec?.schedule ?? "0 * * * *"}</code>,
        size: 130,
      },
      {
        id: "model",
        header: "Monitors",
        accessorFn: (m) => m.spec?.modelRef ?? "",
        cell: ({ row }) =>
          row.original.spec?.modelRef ? (
            <span className="text-xs">{row.original.spec.modelRef}</span>
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          ),
        size: 150,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (m) => claimHealth(m).label,
        cell: ({ row }) => {
          const h = claimHealth(row.original);
          return <StatusBadge status={h.label} tone={h.tone} />;
        },
        size: 140,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (m) => m.metadata.creationTimestamp ?? "",
        cell: ({ row }) => <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>,
        size: 90,
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<ModelMonitor>
      icon={<Gauge />}
      title="Model Monitors"
      description="Scheduled drift monitoring — open-infra's SageMaker Model Monitor. On a cron schedule, compares recent data to a baseline, flags features that drift, and writes a report to the object store."
      listPath={openinfraPaths.modelmonitors}
      columns={columns}
      search={(m) => [m.metadata.name, m.metadata.namespace, m.spec?.modelRef, m.spec?.baseline?.bucket]}
      singular="Model Monitor"
      plural="Model Monitors"
      emptyTitle="No model monitors yet"
      emptyDescription="Monitor a model for drift: point at a baseline dataset and where recent data lands."
      docsHref={kindDocsUrl("ModelMonitor")}
      headerActions={
        <Button onClick={() => navigate({ to: "/model-monitor/new" })}>
          <Plus className="size-4" />
          New Model Monitor
        </Button>
      }
      onRowClick={(m) =>
        navigate({
          to: "/model-monitor/$namespace/$name",
          params: { namespace: m.metadata.namespace ?? "default", name: m.metadata.name ?? "" },
        })
      }
    />
  );
}
