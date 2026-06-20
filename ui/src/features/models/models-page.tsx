import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { BrainCircuit } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { claimHealth } from "@/lib/resource-health";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { Model } from "@/types/k8s";

export function ModelsPage() {
  const navigate = useNavigate();
  const columns = useMemo<ColumnDef<Model, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (m) => m.metadata.name,
        cell: ({ row }) => (
          <span className="font-medium">{row.original.metadata.name}</span>
        ),
        size: 200,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (m) => m.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {row.original.metadata.namespace}
          </span>
        ),
        size: 130,
      },
      {
        id: "model",
        header: "Model",
        accessorFn: (m) => m.spec?.model ?? "",
        cell: ({ row }) => (
          <code className="text-xs">{row.original.spec?.model ?? "—"}</code>
        ),
        size: 220,
      },
      {
        id: "gpu",
        header: "GPU",
        accessorFn: (m) => m.spec?.gpu ?? 1,
        cell: ({ row }) => (
          <span className="text-xs text-muted-foreground">
            {row.original.spec?.gpu ?? 1}×
          </span>
        ),
        size: 80,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (m) => claimHealth(m).label,
        cell: ({ row }) => {
          const h = claimHealth(row.original);
          return <StatusBadge status={h.label} tone={h.tone} />;
        },
        size: 150,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (m) => m.metadata.creationTimestamp ?? "",
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

  return (
    <ResourceTablePage<Model>
      icon={<BrainCircuit />}
      title="Models"
      description="Managed GPU inference — open-infra's Bedrock. A model name becomes a key-gated, OpenAI-compatible endpoint."
      listPath={openinfraPaths.models}
      columns={columns}
      search={(m) => [m.metadata.name, m.metadata.namespace, m.spec?.model]}
      singular="Model"
      plural="Models"
      emptyTitle="No Models yet"
      emptyDescription="Scaffold one with `open-infra init model` — a GPU-backed, OpenAI-compatible inference endpoint."
      onRowClick={(m) =>
        navigate({
          to: "/models/$namespace/$name",
          params: {
            namespace: m.metadata.namespace ?? "default",
            name: m.metadata.name ?? "",
          },
        })
      }
    />
  );
}
