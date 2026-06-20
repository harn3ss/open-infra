import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { BrainCircuit, Plus } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { NewResourceDialog } from "@/components/common/new-resource-dialog";
import { Button } from "@/components/ui/button";
import { claimHealth, nodeAwareHealth } from "@/lib/resource-health";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useNodeHealth } from "@/hooks/use-node-health";
import { usePodNodeIndex } from "@/hooks/use-pod-node-index";
import { useNamespace } from "@/lib/namespace-context";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import { MODELS_CRD_NAME, type K8sObject, type Model } from "@/types/k8s";

export function ModelsPage() {
  const navigate = useNavigate();
  const { scoped } = useNamespace();
  const [newOpen, setNewOpen] = useState(false);
  const { offlineNodes } = useNodeHealth();
  const podIndex = usePodNodeIndex(scoped);
  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = nsWatch.items
    .map((n) => n.metadata.name)
    .filter((n): n is string => Boolean(n))
    .sort((a, b) => a.localeCompare(b));
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
        accessorFn: (m) =>
          nodeAwareHealth(
            claimHealth(m),
            podIndex.nodesForApp(m.metadata.namespace, m.metadata.name),
            offlineNodes,
          ).label,
        cell: ({ row }) => {
          const m = row.original;
          const h = nodeAwareHealth(
            claimHealth(m),
            podIndex.nodesForApp(m.metadata.namespace, m.metadata.name),
            offlineNodes,
          );
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
          <Button onClick={() => setNewOpen(true)}>
            <Plus className="size-4" />
            New Model
          </Button>
        }
      />
      <NewResourceDialog
        open={newOpen}
        onOpenChange={setNewOpen}
        kind="Model"
        crdName={MODELS_CRD_NAME}
        createPath={openinfraPaths.models}
        listPath={openinfraPaths.models(scoped)}
        namespaces={namespaces}
        defaultNamespace={scoped}
        icon={<BrainCircuit className="size-5 text-primary" />}
        description="A GPU-backed, OpenAI-compatible inference endpoint. Set the model tag and GPU count."
      />
    </>
  );
}
