import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { Workflow, Plus, Trash2 } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { k8sDelete } from "@/lib/api";
import { openinfraPaths, resourcePaths } from "@/lib/k8s-paths";
import { age, type StatusTone } from "@/lib/format";
import type { DataFlow } from "@/types/k8s";

function dfStatus(d: DataFlow): { label: string; tone: StatusTone } {
  const conds = d.status?.conditions ?? [];
  const ready = conds.find((c) => c.type === "Ready");
  const synced = conds.find((c) => c.type === "Synced");
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  if (synced?.status === "False") return { label: "Error", tone: "destructive" };
  return { label: "Provisioning", tone: "warning" };
}

export function DataFlowsPage() {
  const navigate = useNavigate();

  const remove = useMutation({
    mutationFn: async (d: DataFlow) => {
      const ns = d.metadata.namespace ?? "default";
      const name = d.metadata.name ?? "";
      await k8sDelete(openinfraPaths.dataflow(ns, name));
      await k8sDelete(resourcePaths.secret(ns, `${name}-creds`)).catch(() => {});
    },
  });

  const columns = useMemo<ColumnDef<DataFlow, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (d) => d.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 160,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (d) => d.metadata.namespace,
        cell: ({ row }) => <span className="text-muted-foreground">{row.original.metadata.namespace}</span>,
        size: 110,
      },
      {
        id: "topology",
        header: "Topology",
        accessorFn: (d) => (d.spec?.nodes ?? []).length,
        cell: ({ row }) => {
          const nodes = row.original.spec?.nodes ?? [];
          const edges = row.original.spec?.edges ?? [];
          const repl = edges.filter((e) => e.type === "replication").length;
          const mig = edges.length - repl;
          return (
            <span className="text-xs text-muted-foreground">
              {nodes.length} node{nodes.length === 1 ? "" : "s"}
              {repl ? `, ${repl} ⇄` : ""}
              {mig ? `, ${mig} →` : ""}
            </span>
          );
        },
        size: 160,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (d) => dfStatus(d).label,
        cell: ({ row }) => {
          const s = dfStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 110,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (d) => d.metadata.creationTimestamp ?? "",
        cell: ({ row }) => <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>,
        size: 70,
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => (
          <span className="flex justify-end">
            <Button
              size="sm"
              variant="outline"
              onClick={(e) => {
                e.stopPropagation();
                remove.mutate(row.original);
              }}
              disabled={remove.isPending}
              title="Delete this data flow (and its credential secret)"
            >
              <Trash2 className="size-4" />
            </Button>
          </span>
        ),
        size: 60,
      },
    ],
    [remove],
  );

  return (
    <ResourceTablePage<DataFlow>
      icon={<Workflow />}
      title="Data Flows"
      description="Design data movement visually: drag database engines onto a canvas, connect them, and deploy. Two-way edges are multi-master replication; one-way edges are migrations. Each node is a database you configure once; the whole topology is one resource."
      listPath={openinfraPaths.dataflows}
      columns={columns}
      search={(d) => [d.metadata.name, d.metadata.namespace]}
      singular="Data Flow"
      plural="Data Flows"
      emptyTitle="No data flows yet"
      emptyDescription="Open the canvas to drag database engines together into a topology."
      onRowClick={(d) =>
        navigate({
          to: "/dataflows/$namespace/$name",
          params: { namespace: d.metadata.namespace ?? "default", name: d.metadata.name ?? "" },
        })
      }
      headerActions={
        <Button onClick={() => navigate({ to: "/dataflows/new" })}>
          <Plus className="size-4" />
          New Data Flow
        </Button>
      }
    />
  );
}
