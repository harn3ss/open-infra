import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { BrainCog, Plus } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { kindDocsUrl } from "@/lib/kind-docs";
import { claimHealth } from "@/lib/resource-health";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { TrainingJob } from "@/types/k8s";

/** kind: TrainingJob — a run-once, GPU-capable model-training Job (SageMaker Training
 *  Jobs). The training-loop counterpart to kind: Model (inference). Run status is the
 *  underlying batch Job's, shown on the detail page. */
export function TrainingJobsPage() {
  const navigate = useNavigate();
  const columns = useMemo<ColumnDef<TrainingJob, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (t) => t.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 220,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (t) => t.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.metadata.namespace}</span>
        ),
        size: 140,
      },
      {
        id: "gpu",
        header: "GPU",
        accessorFn: (t) => (t.spec?.gpu ?? 1) > 0 ? `${t.spec?.gpu ?? 1}×${t.spec?.gpuTier ?? "smallgpu"}` : "CPU",
        cell: ({ row }) => {
          const gpu = row.original.spec?.gpu ?? 1;
          return gpu > 0 ? (
            <Badge variant="secondary">{gpu}× {row.original.spec?.gpuTier ?? "smallgpu"}</Badge>
          ) : (
            <span className="text-xs text-muted-foreground">CPU</span>
          );
        },
        size: 150,
      },
      {
        id: "status",
        header: "Provisioning",
        accessorFn: (t) => claimHealth(t).label,
        cell: ({ row }) => {
          const h = claimHealth(row.original);
          return <StatusBadge status={h.label} tone={h.tone} />;
        },
        size: 150,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (t) => t.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 90,
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<TrainingJob>
      icon={<BrainCog />}
      title="Training Jobs"
      description="Run-once model training on GPUs — open-infra's SageMaker Training Jobs. Your training container runs to completion on a GPU node; read datasets and write model artifacts to the object store."
      listPath={openinfraPaths.trainingjobs}
      columns={columns}
      search={(t) => [t.metadata.name, t.metadata.namespace, t.spec?.image, t.spec?.gpuTier]}
      singular="Training Job"
      plural="Training Jobs"
      emptyTitle="No Training Jobs yet"
      emptyDescription="Start a training run from a container image; pick a GPU tier and (optionally) a dataset and artifact bucket."
      docsHref={kindDocsUrl("TrainingJob")}
      headerActions={
        <Button onClick={() => navigate({ to: "/trainingjobs/new" })}>
          <Plus className="size-4" />
          New Training Job
        </Button>
      }
      onRowClick={(t) =>
        navigate({
          to: "/trainingjobs/$namespace/$name",
          params: { namespace: t.metadata.namespace ?? "default", name: t.metadata.name ?? "" },
        })
      }
    />
  );
}
