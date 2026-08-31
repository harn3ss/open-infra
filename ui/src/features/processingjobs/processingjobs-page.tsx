import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { FlaskConical, Plus } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { kindDocsUrl } from "@/lib/kind-docs";
import { claimHealth } from "@/lib/resource-health";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { ProcessingJob } from "@/types/k8s";

/** kind: ProcessingJob — general data processing (SageMaker Processing): a run-once
 *  job with named inputs/outputs for preprocessing, feature engineering, or evaluation.
 *  Run status is the underlying batch Job's, shown on the detail page. */
export function ProcessingJobsPage() {
  const navigate = useNavigate();
  const columns = useMemo<ColumnDef<ProcessingJob, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (t) => t.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 200,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (t) => t.metadata.namespace,
        cell: ({ row }) => <span className="text-muted-foreground">{row.original.metadata.namespace}</span>,
        size: 130,
      },
      {
        id: "channels",
        header: "Channels",
        accessorFn: (t) => `${t.spec?.inputs?.length ?? 0}/${t.spec?.outputs?.length ?? 0}`,
        cell: ({ row }) => (
          <span className="text-xs text-muted-foreground">
            {row.original.spec?.inputs?.length ?? 0} in · {row.original.spec?.outputs?.length ?? 0} out
          </span>
        ),
        size: 130,
      },
      {
        id: "gpu",
        header: "GPU",
        accessorFn: (t) => ((t.spec?.gpu ?? 0) > 0 ? `${t.spec?.gpu}` : "CPU"),
        cell: ({ row }) => {
          const gpu = row.original.spec?.gpu ?? 0;
          return gpu > 0 ? (
            <Badge variant="secondary">{gpu}× {row.original.spec?.gpuTier ?? "smallgpu"}</Badge>
          ) : (
            <span className="text-xs text-muted-foreground">CPU</span>
          );
        },
        size: 120,
      },
      {
        id: "status",
        header: "Provisioning",
        accessorFn: (t) => claimHealth(t).label,
        cell: ({ row }) => {
          const h = claimHealth(row.original);
          return <StatusBadge status={h.label} tone={h.tone} />;
        },
        size: 140,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (t) => t.metadata.creationTimestamp ?? "",
        cell: ({ row }) => <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>,
        size: 90,
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<ProcessingJob>
      icon={<FlaskConical />}
      title="Processing Jobs"
      description="Data processing — open-infra's SageMaker Processing. A run-once job with named inputs and outputs for preprocessing, feature engineering, dataset validation, or model evaluation."
      listPath={openinfraPaths.processingjobs}
      columns={columns}
      search={(t) => [t.metadata.name, t.metadata.namespace, t.spec?.image]}
      singular="Processing Job"
      plural="Processing Jobs"
      emptyTitle="No processing jobs yet"
      emptyDescription="Run a container over data: give named input and output channels in the object store."
      docsHref={kindDocsUrl("ProcessingJob")}
      headerActions={
        <Button onClick={() => navigate({ to: "/processing/new" })}>
          <Plus className="size-4" />
          New Processing Job
        </Button>
      }
      onRowClick={(t) =>
        navigate({
          to: "/processing/$namespace/$name",
          params: { namespace: t.metadata.namespace ?? "default", name: t.metadata.name ?? "" },
        })
      }
    />
  );
}
