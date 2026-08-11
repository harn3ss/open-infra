import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { Plus, Waypoints } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { Button } from "@/components/ui/button";
import { claimHealth } from "@/lib/resource-health";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import { type GraphQLApi } from "@/types/k8s";

export function GraphQLApisPage() {
  const navigate = useNavigate();
  const columns = useMemo<ColumnDef<GraphQLApi, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (g) => g.metadata.name,
        cell: ({ row }) => (
          <span className="font-medium">{row.original.metadata.name}</span>
        ),
        size: 200,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (g) => g.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {row.original.metadata.namespace}
          </span>
        ),
        size: 130,
      },
      {
        id: "resolvers",
        header: "Resolvers",
        accessorFn: (g) => g.spec?.resolvers?.length ?? 0,
        cell: ({ row }) => (
          <span className="text-xs text-muted-foreground">
            {row.original.spec?.resolvers?.length ?? 0}
          </span>
        ),
        size: 110,
      },
      {
        id: "dataSources",
        header: "Data sources",
        accessorFn: (g) => g.spec?.dataSources?.length ?? 0,
        cell: ({ row }) => (
          <span className="text-xs text-muted-foreground">
            {row.original.spec?.dataSources?.length ?? 0}
          </span>
        ),
        size: 120,
      },
      {
        id: "introspection",
        header: "Introspection",
        accessorFn: (g) => g.spec?.schema ? "on" : "off",
        cell: ({ row }) => (
          <span className="text-xs text-muted-foreground">
            {row.original.spec?.schema
              ? row.original.spec?.limits?.introspection ?? "enabled"
              : "no schema"}
          </span>
        ),
        size: 150,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (g) => claimHealth(g).label,
        cell: ({ row }) => {
          const h = claimHealth(row.original);
          return <StatusBadge status={h.label} tone={h.tone} />;
        },
        size: 150,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (g) => g.metadata.creationTimestamp ?? "",
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
      <ResourceTablePage<GraphQLApi>
        icon={<Waypoints />}
        title="GraphQL APIs"
        description="Resolver-first GraphQL — open-infra's AppSync (open-appsync). VTL/JS mapping templates over data sources, with introspection, subscriptions, and hostile-load guards."
        listPath={openinfraPaths.graphqlapis}
        columns={columns}
        search={(g) => [g.metadata.name, g.metadata.namespace]}
        singular="GraphQL API"
        plural="GraphQL APIs"
        emptyTitle="No GraphQL APIs yet"
        emptyDescription="Create one to serve a resolver-backed GraphQL schema."
        onRowClick={(g) =>
          navigate({
            to: "/graphql/$namespace/$name",
            params: {
              namespace: g.metadata.namespace ?? "default",
              name: g.metadata.name ?? "",
            },
          })
        }
        headerActions={
          <Button onClick={() => navigate({ to: "/graphql/new" })}>
            <Plus className="size-4" />
            New GraphQL API
          </Button>
        }
      />
    </>
  );
}
