import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { Target, Plus } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { kindDocsUrl } from "@/lib/kind-docs";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { TuningJob } from "@/types/k8s";

/** Tuning phase → badge tone. */
export function tuningTone(phase?: string): "success" | "destructive" | "accent" | "muted" {
  switch (phase) {
    case "Succeeded":
      return "success";
    case "Failed":
      return "destructive";
    case "Running":
      return "accent";
    default:
      return "muted";
  }
}

/** kind: TuningJob — hyperparameter tuning (SageMaker Automatic Model Tuning): a
 *  grid-search sweep that runs a Training Job per hyperparameter combination and keeps
 *  the best. */
export function TuningJobsPage() {
  const navigate = useNavigate();
  const columns = useMemo<ColumnDef<TuningJob, unknown>[]>(
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
        id: "phase",
        header: "Phase",
        accessorFn: (t) => t.status?.phase ?? "Pending",
        cell: ({ row }) => {
          const p = row.original.status?.phase ?? "Pending";
          return <StatusBadge status={p} tone={tuningTone(p)} />;
        },
        size: 130,
      },
      {
        id: "trials",
        header: "Trials",
        accessorFn: (t) => `${t.status?.trialsComplete ?? 0}/${t.status?.trialsTotal ?? 0}`,
        cell: ({ row }) => (
          <span className="text-xs text-muted-foreground">
            {row.original.status?.trialsComplete ?? 0}/{row.original.status?.trialsTotal ?? 0}
          </span>
        ),
        size: 90,
      },
      {
        id: "best",
        header: "Best value",
        accessorFn: (t) => t.status?.bestValue ?? "",
        cell: ({ row }) =>
          row.original.status?.bestValue ? (
            <code className="text-xs">{row.original.status.bestValue}</code>
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          ),
        size: 130,
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
    <ResourceTablePage<TuningJob>
      icon={<Target />}
      title="Tuning Jobs"
      description="Hyperparameter tuning — open-infra's SageMaker Automatic Model Tuning. Grid-search a training job over a parameter space; each trial runs as a Training Job, and the best is kept."
      listPath={openinfraPaths.tuningjobs}
      columns={columns}
      search={(t) => [t.metadata.name, t.metadata.namespace, t.spec?.training?.image]}
      singular="Tuning Job"
      plural="Tuning Jobs"
      emptyTitle="No tuning jobs yet"
      emptyDescription="Sweep a training job over a hyperparameter grid and keep the best by your objective metric."
      docsHref={kindDocsUrl("TuningJob")}
      headerActions={
        <Button onClick={() => navigate({ to: "/tuning/new" })}>
          <Plus className="size-4" />
          New Tuning Job
        </Button>
      }
      onRowClick={(t) =>
        navigate({
          to: "/tuning/$namespace/$name",
          params: { namespace: t.metadata.namespace ?? "default", name: t.metadata.name ?? "" },
        })
      }
    />
  );
}
