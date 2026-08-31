import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { Package, Plus } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { kindDocsUrl } from "@/lib/kind-docs";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { ModelPackage } from "@/types/k8s";

/** Approval status → badge tone. */
export function approvalTone(s?: string): "success" | "destructive" | "warning" | "muted" {
  switch (s) {
    case "Approved":
      return "success";
    case "Rejected":
      return "destructive";
    case "PendingManualApproval":
      return "warning";
    default:
      return "muted";
  }
}

/** kind: ModelPackage — the model registry: versioned, approvable records of trained
 *  model artifacts (SageMaker Model Registry). Promote an Approved package to a served
 *  Model. */
export function ModelPackagesPage() {
  const navigate = useNavigate();
  const columns = useMemo<ColumnDef<ModelPackage, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (p) => p.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 200,
      },
      {
        id: "model",
        header: "Model / version",
        accessorFn: (p) => `${p.spec?.modelName} ${p.spec?.version ?? ""}`,
        cell: ({ row }) => (
          <span>
            <span className="font-medium">{row.original.spec?.modelName}</span>
            <span className="ml-1 text-xs text-muted-foreground">v{row.original.spec?.version ?? "1"}</span>
          </span>
        ),
        size: 200,
      },
      {
        id: "framework",
        header: "Framework",
        accessorFn: (p) => p.spec?.framework ?? "—",
        cell: ({ row }) =>
          row.original.spec?.framework ? (
            <Badge variant="secondary">{row.original.spec.framework}</Badge>
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          ),
        size: 130,
      },
      {
        id: "approval",
        header: "Approval",
        accessorFn: (p) => p.spec?.approvalStatus ?? "PendingManualApproval",
        cell: ({ row }) => {
          const s = row.original.spec?.approvalStatus ?? "PendingManualApproval";
          return <StatusBadge status={s} tone={approvalTone(s)} />;
        },
        size: 190,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (p) => p.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 90,
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<ModelPackage>
      icon={<Package />}
      title="Model Registry"
      description="Versioned, approvable records of trained models — open-infra's SageMaker Model Registry. Register a trained artifact, approve it, then promote it to a served Model."
      listPath={openinfraPaths.modelpackages}
      columns={columns}
      search={(p) => [p.metadata.name, p.spec?.modelName, p.spec?.version, p.spec?.framework]}
      singular="Model Package"
      plural="Model Packages"
      emptyTitle="No model packages yet"
      emptyDescription="Register a trained model artifact (from a Training Job's output) to version and approve it."
      docsHref={kindDocsUrl("ModelPackage")}
      headerActions={
        <Button onClick={() => navigate({ to: "/model-registry/new" })}>
          <Plus className="size-4" />
          Register model
        </Button>
      }
      onRowClick={(p) =>
        navigate({
          to: "/model-registry/$namespace/$name",
          params: { namespace: p.metadata.namespace ?? "default", name: p.metadata.name ?? "" },
        })
      }
    />
  );
}
