import { useMemo } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { Share2, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { kindDocsUrl } from "@/lib/kind-docs";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import { type Condition, type TransitGateway } from "@/types/k8s";

function tgStatus(t: TransitGateway): { label: string; tone: StatusTone } {
  const ready = (t.status as { conditions?: Condition[] } | undefined)?.conditions?.find(
    (c) => c.type === "Ready",
  );
  if (ready?.status === "True" || t.status?.ready) return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

function spokeNames(t: TransitGateway): string[] {
  return (t.spec?.attachments ?? []).map((a) => a.vpc).filter(Boolean);
}

export function TransitGatewaysPage() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<TransitGateway, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (t) => t.metadata.name,
        cell: ({ row }) => (
          <Link
            to="/transit-gateways/$namespace/$name"
            params={{
              namespace: row.original.metadata.namespace ?? "default",
              name: row.original.metadata.name ?? "",
            }}
            className="font-medium text-primary hover:underline"
          >
            {row.original.metadata.name}
          </Link>
        ),
        size: 220,
      },
      {
        id: "attachments",
        header: "Attachments",
        accessorFn: (t) => t.spec?.attachments?.length ?? 0,
        cell: ({ row }) => {
          const n = row.original.spec?.attachments?.length ?? 0;
          return <span className="text-muted-foreground">{n === 1 ? "1 attachment" : `${n} attachments`}</span>;
        },
        size: 130,
      },
      {
        id: "spokes",
        header: "Spokes",
        accessorFn: (t) => spokeNames(t).join(", "),
        cell: ({ row }) => {
          const spokes = spokeNames(row.original);
          return (
            <span className="text-muted-foreground">{spokes.length ? spokes.join(", ") : "—"}</span>
          );
        },
        size: 280,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (t) => tgStatus(t).label,
        cell: ({ row }) => {
          const s = tgStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 110,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (t) => t.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<TransitGateway>
      icon={<Share2 />}
      title="Transit Gateways"
      description="A hub giving transitive routing between many VPCs — the property plain VPC peering lacks. Composed from kube-ovn primitives; each spoke also needs its own VPC peering + routes to the hub."
      listPath={openinfraPaths.transitgateways}
      columns={columns}
      onRowClick={(t) =>
        navigate({
          to: "/transit-gateways/$namespace/$name",
          params: {
            namespace: t.metadata.namespace ?? "default",
            name: t.metadata.name ?? "",
          },
        })
      }
      search={(t) => [t.metadata.name, t.metadata.namespace, ...spokeNames(t)]}
      singular="Transit Gateway"
      plural="Transit Gateways"
      emptyTitle="No transit gateways yet"
      emptyDescription="Create a transit gateway to route transitively between several VPCs (hub-and-spoke)."
      docsHref={kindDocsUrl("TransitGateway")}
      headerActions={
        <Button onClick={() => navigate({ to: "/transit-gateways/new" })}>
          <Plus className="size-4" /> New Transit Gateway
        </Button>
      }
    />
  );
}
