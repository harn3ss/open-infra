import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { Layers, Plus } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { kindDocsUrl } from "@/lib/kind-docs";
import { claimHealth } from "@/lib/resource-health";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { BatchTransform } from "@/types/k8s";

/** kind: BatchTransform — offline batch inference (SageMaker Batch Transform): a
 *  run-once job that scores an input dataset with a model and writes predictions. Run
 *  status is the underlying batch Job's, shown on the detail page. */
export function BatchTransformsPage() {
  const navigate = useNavigate();
  const columns = useMemo<ColumnDef<BatchTransform, unknown>[]>(
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
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.metadata.namespace}</span>
        ),
        size: 130,
      },
      {
        id: "io",
        header: "Input → Output",
        accessorFn: (t) => `${t.spec?.input?.bucket} ${t.spec?.output?.bucket}`,
        cell: ({ row }) => (
          <span className="text-xs text-muted-foreground">
            <code>{row.original.spec?.input?.bucket}</code> → <code>{row.original.spec?.output?.bucket}</code>
          </span>
        ),
        size: 220,
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
        size: 130,
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
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 90,
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<BatchTransform>
      icon={<Layers />}
      title="Batch Transform"
      description="Offline batch inference — open-infra's SageMaker Batch Transform. A run-once job loads a model, scores a whole input dataset, and writes predictions to the object store."
      listPath={openinfraPaths.batchtransforms}
      columns={columns}
      search={(t) => [t.metadata.name, t.metadata.namespace, t.spec?.image, t.spec?.input?.bucket]}
      singular="Batch Transform"
      plural="Batch Transforms"
      emptyTitle="No batch transforms yet"
      emptyDescription="Score a dataset offline: give an inference container, a model artifact, and input/output buckets."
      docsHref={kindDocsUrl("BatchTransform")}
      headerActions={
        <Button onClick={() => navigate({ to: "/batch-transform/new" })}>
          <Plus className="size-4" />
          New Batch Transform
        </Button>
      }
      onRowClick={(t) =>
        navigate({
          to: "/batch-transform/$namespace/$name",
          params: { namespace: t.metadata.namespace ?? "default", name: t.metadata.name ?? "" },
        })
      }
    />
  );
}
