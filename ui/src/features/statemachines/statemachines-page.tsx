import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { Route, Plus } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { kindDocsUrl } from "@/lib/kind-docs";
import { claimHealth } from "@/lib/resource-health";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StateMachine } from "@/types/k8s";

/** kind: StateMachine — open-infra's Step Functions: an Amazon States Language
 *  workflow that orchestrates Functions with branching, retries and waits. Runs
 *  are kind: Execution, listed on each state machine's detail page. */
export function StateMachinesPage() {
  const navigate = useNavigate();
  const columns = useMemo<ColumnDef<StateMachine, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (s) => s.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 240,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (s) => s.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.metadata.namespace}</span>
        ),
        size: 150,
      },
      {
        id: "type",
        header: "Type",
        accessorFn: (s) => s.spec?.type ?? "Standard",
        cell: ({ row }) => <Badge variant="secondary">{row.original.spec?.type ?? "Standard"}</Badge>,
        size: 120,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (s) => claimHealth(s).label,
        cell: ({ row }) => {
          const h = claimHealth(row.original);
          return <StatusBadge status={h.label} tone={h.tone} />;
        },
        size: 150,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (s) => s.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 90,
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<StateMachine>
      icon={<Route />}
      title="State Machines"
      description="Orchestrate Functions into workflows — open-infra's Step Functions. Define states (Task, Choice, Wait, Parallel…) in Amazon States Language; run them as Executions."
      listPath={openinfraPaths.statemachines}
      columns={columns}
      search={(s) => [s.metadata.name, s.metadata.namespace, s.spec?.type]}
      singular="State Machine"
      plural="State Machines"
      emptyTitle="No State Machines yet"
      emptyDescription="Create a state machine from an Amazon States Language definition, then start executions against it."
      docsHref={kindDocsUrl("StateMachine")}
      headerActions={
        <Button onClick={() => navigate({ to: "/statemachines/new" })}>
          <Plus className="size-4" />
          New State Machine
        </Button>
      }
      onRowClick={(s) =>
        navigate({
          to: "/statemachines/$namespace/$name",
          params: { namespace: s.metadata.namespace ?? "default", name: s.metadata.name ?? "" },
        })
      }
    />
  );
}
