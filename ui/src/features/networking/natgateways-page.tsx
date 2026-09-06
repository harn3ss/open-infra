import { useMemo } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { Waypoints, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { type FilterPropertyDef } from "@/components/common/property-filter";
import { kindDocsUrl } from "@/lib/kind-docs";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import { type Condition, type NatGateway } from "@/types/k8s";

function natStatus(g: NatGateway): { label: string; tone: StatusTone } {
  const ready = (g.status as { conditions?: Condition[] } | undefined)?.conditions?.find(
    (c) => c.type === "Ready",
  );
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

export function NatGatewaysPage() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<NatGateway, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (g) => g.metadata.name,
        cell: ({ row }) => (
          <Link
            to="/nat-gateways/$namespace/$name"
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
        id: "vpc",
        header: "VPC",
        accessorFn: (g) => g.spec?.vpc ?? "",
        cell: ({ row }) =>
          row.original.spec?.vpc ? (
            <Link
              to="/vpcs/$namespace/$name"
              params={{
                namespace: row.original.metadata.namespace ?? "default",
                name: row.original.spec.vpc,
              }}
              className="text-primary hover:underline"
            >
              {row.original.spec.vpc}
            </Link>
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
        size: 150,
      },
      {
        id: "subnet",
        header: "Subnet",
        accessorFn: (g) => g.spec?.subnet ?? "",
        cell: ({ row }) =>
          row.original.spec?.subnet ? (
            <Link
              to="/subnets/$namespace/$name"
              params={{
                namespace: row.original.metadata.namespace ?? "default",
                name: row.original.spec.subnet,
              }}
              className="text-primary hover:underline"
            >
              {row.original.spec.subnet}
            </Link>
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
        size: 150,
      },
      {
        id: "internalIp",
        header: "Internal IP",
        accessorFn: (g) => g.spec?.internalIp ?? "",
        cell: ({ row }) => (
          <code className="text-xs">{row.original.spec?.internalIp ?? "—"}</code>
        ),
        size: 130,
      },
      {
        id: "egressIp",
        header: "Egress public IP",
        accessorFn: (g) => g.spec?.egress?.publicIp ?? "",
        cell: ({ row }) => {
          const ip = row.original.spec?.egress?.publicIp;
          return ip ? <code className="text-xs">{ip}</code> : <span className="text-muted-foreground">auto</span>;
        },
        size: 140,
      },
      {
        id: "egressSources",
        header: "Egress sources",
        accessorFn: (g) => (g.spec?.egress?.sourceCidrs ?? []).length,
        cell: ({ row }) => {
          const n = row.original.spec?.egress?.sourceCidrs?.length ?? 0;
          return (
            <span className="text-muted-foreground">{n ? `${n} CIDR${n === 1 ? "" : "s"}` : "—"}</span>
          );
        },
        size: 120,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (g) => natStatus(g).label,
        cell: ({ row }) => {
          const s = natStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 120,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (g) => g.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
    ],
    [],
  );

  const filterProperties = useMemo<FilterPropertyDef<NatGateway>[]>(
    () => [
      { key: "name", label: "Name", getValue: (g) => g.metadata.name },
      { key: "vpc", label: "VPC", getValue: (g) => g.spec?.vpc },
      { key: "subnet", label: "Subnet", getValue: (g) => g.spec?.subnet },
      {
        key: "status",
        label: "Status",
        getValue: (g) => natStatus(g).label,
        options: [{ value: "Ready" }, { value: "Provisioning" }],
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<NatGateway>
      icon={<Waypoints />}
      title="NAT Gateways"
      description="The border device for a VPC (kube-ovn) — it provides both internet egress (SNAT) and the routable ingress hop for Elastic IPs. There is no separate internet gateway object on this substrate; one NAT gateway plays both the NAT-gateway and internet-gateway roles."
      listPath={openinfraPaths.natgateways}
      columns={columns}
      onRowClick={(g) =>
        navigate({
          to: "/nat-gateways/$namespace/$name",
          params: {
            namespace: g.metadata.namespace ?? "default",
            name: g.metadata.name ?? "",
          },
        })
      }
      search={(g) => [g.metadata.name, g.metadata.namespace, g.spec?.vpc, g.spec?.subnet]}
      singular="NAT gateway"
      plural="NAT gateways"
      emptyTitle="No NAT gateways yet"
      emptyDescription="Create a NAT gateway to give a VPC internet egress and routable ingress, then allocate Elastic IPs on it."
      docsHref={kindDocsUrl("NatGateway")}
      filterProperties={filterProperties}
      enablePreferences
      enablePagination
      columnLabels={{
        vpc: "VPC",
        subnet: "Subnet",
        internalIp: "Internal IP",
        egressIp: "Egress public IP",
        egressSources: "Egress sources",
      }}
      headerActions={
        <Button onClick={() => navigate({ to: "/nat-gateways/new" })}>
          <Plus className="size-4" /> Create NAT gateway
        </Button>
      }
    />
  );
}
