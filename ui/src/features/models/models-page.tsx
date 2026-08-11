import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { BrainCircuit, Plus } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { kindDocsUrl } from "@/lib/kind-docs";
import { Button } from "@/components/ui/button";
import { modelHealth, modelDesiredReplicas } from "@/lib/resource-health";
import { useNodeHealth } from "@/hooks/use-node-health";
import { usePodNodeIndex, type PodNodeIndex } from "@/hooks/use-pod-node-index";
import { useNamespace } from "@/lib/namespace-context";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import { type Model } from "@/types/k8s";

/** Node-aware + replica-aware status for a Model row. */
function modelStatus(
  m: Model,
  podIndex: PodNodeIndex,
  offlineNodes: Set<string>,
) {
  return modelHealth(m, {
    nodes: podIndex.nodesForApp(m.metadata.namespace, m.metadata.name),
    offlineNodes,
    ready: podIndex.statsForApp(m.metadata.namespace, m.metadata.name).ready,
    desired: modelDesiredReplicas(m.spec?.highAvailability),
  });
}

export function ModelsPage() {
  const navigate = useNavigate();
  const { scoped } = useNamespace();
  const { offlineNodes } = useNodeHealth();
  const podIndex = usePodNodeIndex(scoped);
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
        id: "ha",
        header: "HA",
        accessorFn: (m) => (m.spec?.highAvailability ? "yes" : "no"),
        cell: ({ row }) => {
          const m = row.original;
          if (!m.spec?.highAvailability)
            return <span className="text-xs text-muted-foreground">—</span>;
          const desired = modelDesiredReplicas(true);
          const { ready } = podIndex.statsForApp(
            m.metadata.namespace,
            m.metadata.name,
          );
          return (
            <span className="font-mono text-xs">
              {ready}/{desired}
            </span>
          );
        },
        size: 70,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (m) => modelStatus(m, podIndex, offlineNodes).label,
        cell: ({ row }) => {
          const h = modelStatus(row.original, podIndex, offlineNodes);
          return <StatusBadge status={h.label} tone={h.tone} />;
        },
        size: 160,
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
    [offlineNodes, podIndex],
  );

  return (
    <>
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
        emptyDescription="Create one, or scaffold with `open-infra init model`."
        docsHref={kindDocsUrl("Model")}
        onRowClick={(m) =>
          navigate({
            to: "/models/$namespace/$name",
            params: {
              namespace: m.metadata.namespace ?? "default",
              name: m.metadata.name ?? "",
            },
          })
        }
        headerActions={
          <Button onClick={() => navigate({ to: "/models/new" })}>
            <Plus className="size-4" />
            New Model
          </Button>
        }
      />
    </>
  );
}
