import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { Plus, Zap } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { NewResourceDialog } from "@/components/common/new-resource-dialog";
import { Button } from "@/components/ui/button";
import { claimHealth } from "@/lib/resource-health";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import {
  FUNCTIONS_CRD_NAME,
  type K8sObject,
  type OpenInfraFunction,
} from "@/types/k8s";

export function FunctionsPage() {
  const navigate = useNavigate();
  const { scoped } = useNamespace();
  const [newOpen, setNewOpen] = useState(false);
  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = nsWatch.items
    .map((n) => n.metadata.name)
    .filter((n): n is string => Boolean(n))
    .sort((a, b) => a.localeCompare(b));
  const columns = useMemo<ColumnDef<OpenInfraFunction, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (f) => f.metadata.name,
        cell: ({ row }) => (
          <span className="font-medium">{row.original.metadata.name}</span>
        ),
        size: 200,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (f) => f.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {row.original.metadata.namespace}
          </span>
        ),
        size: 130,
      },
      {
        id: "image",
        header: "Image",
        accessorFn: (f) => f.spec?.image ?? "",
        cell: ({ row }) => (
          <code className="block max-w-[20rem] truncate text-xs">
            {row.original.spec?.image ?? "—"}
          </code>
        ),
        size: 300,
      },
      {
        id: "scale",
        header: "Scale",
        accessorFn: (f) => `${f.spec?.scaling?.min ?? 0}`,
        cell: ({ row }) => {
          const s = row.original.spec?.scaling;
          const gpu = row.original.spec?.gpu ?? 0;
          return (
            <span className="text-xs text-muted-foreground">
              {s?.min ?? 0}–{s?.max ?? 10}
              {gpu > 0 ? ` · ${gpu}×GPU` : ""}
            </span>
          );
        },
        size: 140,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (f) => claimHealth(f).label,
        cell: ({ row }) => {
          const h = claimHealth(row.original);
          return <StatusBadge status={h.label} tone={h.tone} />;
        },
        size: 150,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (f) => f.metadata.creationTimestamp ?? "",
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
    <>
      <ResourceTablePage<OpenInfraFunction>
        icon={<Zap />}
        title="Functions"
        description="Serverless, scale-to-zero HTTP — open-infra's Lambda (Knative). Scales 0→N→0 with traffic; optional GPU."
        listPath={openinfraPaths.functions}
        columns={columns}
        search={(f) => [f.metadata.name, f.metadata.namespace, f.spec?.image]}
        singular="Function"
        plural="Functions"
        emptyTitle="No Functions yet"
        emptyDescription="Create one, or scaffold with `open-infra init function`."
        onRowClick={(f) =>
          navigate({
            to: "/functions/$namespace/$name",
            params: {
              namespace: f.metadata.namespace ?? "default",
              name: f.metadata.name ?? "",
            },
          })
        }
        headerActions={
          <Button onClick={() => setNewOpen(true)}>
            <Plus className="size-4" />
            New Function
          </Button>
        }
      />
      <NewResourceDialog
        open={newOpen}
        onOpenChange={setNewOpen}
        kind="Function"
        crdName={FUNCTIONS_CRD_NAME}
        createPath={openinfraPaths.functions}
        listPath={openinfraPaths.functions(scoped)}
        namespaces={namespaces}
        defaultNamespace={scoped}
        icon={<Zap className="size-5 text-primary" />}
        description="A scale-to-zero HTTP service (Knative). Set the image and scaling; optionally a GPU."
      />
    </>
  );
}
