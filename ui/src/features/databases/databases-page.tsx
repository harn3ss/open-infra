import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { Database, Plus } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { NewDatabaseDialog } from "@/features/databases/new-database-dialog";
import { claimHealth } from "@/lib/resource-health";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { age } from "@/lib/format";
import type { Application, K8sObject } from "@/types/k8s";

/** Databases are provisioned by an Application's `database:` block — postgres
 *  (CloudNativePG) or mongo (FerretDB). We list them from their owning
 *  Application so both engines appear with the engine they use. */
function engineLabel(engine?: string): string {
  return engine === "mongo" ? "MongoDB (FerretDB)" : "PostgreSQL";
}

export function DatabasesPage() {
  const navigate = useNavigate();
  const { scoped } = useNamespace();
  const [newOpen, setNewOpen] = useState(false);
  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = nsWatch.items
    .map((n) => n.metadata.name)
    .filter((n): n is string => Boolean(n))
    .sort((a, b) => a.localeCompare(b));
  const columns = useMemo<ColumnDef<Application, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (a) => a.spec?.database?.name ?? a.metadata.name,
        cell: ({ row }) => (
          <span className="font-medium">
            {row.original.spec?.database?.name ?? row.original.metadata.name}
          </span>
        ),
        size: 190,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (a) => a.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {row.original.metadata.namespace}
          </span>
        ),
        size: 130,
      },
      {
        id: "engine",
        header: "Engine",
        accessorFn: (a) => engineLabel(a.spec?.database?.engine),
        cell: ({ row }) => (
          <Badge variant="secondary">
            {engineLabel(row.original.spec?.database?.engine)}
          </Badge>
        ),
        size: 170,
      },
      {
        id: "ha",
        header: "HA",
        accessorFn: (a) => (a.spec?.database?.highAvailability ? "yes" : "no"),
        cell: ({ row }) =>
          row.original.spec?.database?.highAvailability ? (
            <Badge variant="secondary">HA</Badge>
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          ),
        size: 70,
      },
      {
        id: "app",
        header: "Application",
        accessorFn: (a) => a.metadata.name,
        cell: ({ row }) => (
          <span className="text-xs text-muted-foreground">
            {row.original.metadata.name}
          </span>
        ),
        size: 150,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (a) => claimHealth(a).label,
        cell: ({ row }) => {
          const h = claimHealth(row.original);
          return <StatusBadge status={h.label} tone={h.tone} />;
        },
        size: 150,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (a) => a.metadata.creationTimestamp ?? "",
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
    <ResourceTablePage<Application>
      icon={<Database />}
      title="Databases"
      description="Managed databases — open-infra's RDS. Provisioned by an Application's `database:` block: postgres (CloudNativePG) or mongo (FerretDB)."
      listPath={openinfraPaths.applications}
      columns={columns}
      filter={(a) => Boolean(a.spec?.database)}
      search={(a) => [
        a.metadata.name,
        a.metadata.namespace,
        a.spec?.database?.name,
        a.spec?.database?.engine,
      ]}
      singular="Database"
      plural="Databases"
      emptyTitle="No Databases yet"
      emptyDescription="Add a `database:` block to an Application (engine: postgres or mongo), or click New Database."
      headerActions={
        <Button onClick={() => setNewOpen(true)}>
          <Plus className="size-4" />
          New Database
        </Button>
      }
      onRowClick={(a) => {
        const ns = a.metadata.namespace ?? "default";
        if ((a.spec?.database?.engine ?? "postgres") === "mongo") {
          // FerretDB detail keys off the owning Application name.
          navigate({
            to: "/databases/mongo/$namespace/$name",
            params: { namespace: ns, name: a.metadata.name ?? "" },
          });
        } else {
          // Postgres -> the CloudNativePG cluster detail (cluster <app>-db).
          navigate({
            to: "/databases/$namespace/$name",
            params: { namespace: ns, name: `${a.metadata.name}-db` },
          });
        }
      }}
    />
      <NewDatabaseDialog
        open={newOpen}
        onOpenChange={setNewOpen}
        namespaces={namespaces}
        defaultNamespace={scoped || "default"}
        listPath={openinfraPaths.applications(scoped)}
      />
    </>
  );
}
