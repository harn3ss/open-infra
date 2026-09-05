import { useMemo } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { LayoutGrid, Plus, Lock, Globe } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { kindDocsUrl } from "@/lib/kind-docs";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import { type Condition, type Subnet } from "@/types/k8s";

function subnetStatus(s: Subnet): { label: string; tone: StatusTone } {
  const ready = (s.status as { conditions?: Condition[] } | undefined)?.conditions?.find(
    (c) => c.type === "Ready",
  );
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

export function SubnetsPage() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<Subnet, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (s) => s.metadata.name,
        cell: ({ row }) => (
          <Link
            to="/subnets/$namespace/$name"
            params={{
              namespace: row.original.metadata.namespace ?? "default",
              name: row.original.metadata.name ?? "",
            }}
            className="font-medium text-primary hover:underline"
          >
            {row.original.metadata.name}
          </Link>
        ),
        size: 200,
      },
      {
        id: "cidr",
        header: "CIDR",
        accessorFn: (s) => s.spec?.cidr ?? "",
        cell: ({ row }) => <code className="text-xs">{row.original.spec?.cidr ?? "—"}</code>,
        size: 140,
      },
      {
        id: "vpc",
        header: "VPC",
        accessorFn: (s) => s.spec?.vpc ?? "",
        cell: ({ row }) =>
          row.original.spec?.vpc ? (
            <Link
              to="/vpcs/$namespace/$name"
              params={{ namespace: row.original.metadata.namespace ?? "default", name: row.original.spec.vpc }}
              className="text-primary hover:underline"
            >
              {row.original.spec.vpc}
            </Link>
          ) : (
            <span className="text-muted-foreground">default (ovn-cluster)</span>
          ),
        size: 160,
      },
      {
        id: "isolation",
        header: "Isolation",
        accessorFn: (s) => (s.spec?.private === false ? "public" : "private"),
        cell: ({ row }) =>
          row.original.spec?.private === false ? (
            <span className="inline-flex items-center gap-1 text-muted-foreground">
              <Globe className="size-3.5" /> public
            </span>
          ) : (
            <span className="inline-flex items-center gap-1">
              <Lock className="size-3.5" /> private
            </span>
          ),
        size: 110,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (s) => subnetStatus(s).label,
        cell: ({ row }) => {
          const s = subnetStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 110,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (s) => s.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<Subnet>
      icon={<LayoutGrid />}
      title="Subnets"
      description="Topologically-isolated network segments (kube-ovn). Private by default — only the subnet itself and any allowSubnets may reach it, enforced by OVN, not simulated. Place a workload in one via its subnet field."
      listPath={openinfraPaths.subnets}
      columns={columns}
      onRowClick={(s) =>
        navigate({
          to: "/subnets/$namespace/$name",
          params: {
            namespace: s.metadata.namespace ?? "default",
            name: s.metadata.name ?? "",
          },
        })
      }
      search={(s) => [s.metadata.name, s.metadata.namespace, s.spec?.cidr, s.spec?.vpc]}
      singular="Subnet"
      plural="Subnets"
      emptyTitle="No subnets yet"
      emptyDescription="Create a subnet, then place workloads in it with spec.subnet."
      docsHref={kindDocsUrl("Subnet")}
      headerActions={
        <Button onClick={() => navigate({ to: "/subnets/new" })}>
          <Plus className="size-4" /> New Subnet
        </Button>
      }
    />
  );
}
