import { useMemo } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { Globe, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { type FilterPropertyDef } from "@/components/common/property-filter";
import { kindDocsUrl } from "@/lib/kind-docs";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import { type Condition, type ElasticIp } from "@/types/k8s";

function eipStatus(e: ElasticIp): { label: string; tone: StatusTone } {
  const ready = (e.status as { conditions?: Condition[] } | undefined)?.conditions?.find(
    (c) => c.type === "Ready",
  );
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

function eipAddress(e: ElasticIp): string | undefined {
  return e.status?.address ?? e.spec?.address;
}

export function ElasticIpsPage() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<ElasticIp, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (e) => e.metadata.name,
        cell: ({ row }) => (
          <Link
            to="/elastic-ips/$namespace/$name"
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
        id: "address",
        header: "Address",
        accessorFn: (e) => eipAddress(e) ?? "",
        cell: ({ row }) => {
          const addr = eipAddress(row.original);
          return addr ? <code className="text-xs">{addr}</code> : <span className="text-muted-foreground">auto</span>;
        },
        size: 150,
      },
      {
        id: "natGateway",
        header: "NAT gateway",
        accessorFn: (e) => e.spec?.natGateway ?? "",
        cell: ({ row }) =>
          row.original.spec?.natGateway ? (
            <Link
              to="/nat-gateways/$namespace/$name"
              params={{
                namespace: row.original.metadata.namespace ?? "default",
                name: row.original.spec.natGateway,
              }}
              className="text-primary hover:underline"
            >
              {row.original.spec.natGateway}
            </Link>
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
        size: 170,
      },
      {
        id: "target",
        header: "Associated target",
        accessorFn: (e) => e.spec?.target ?? "",
        cell: ({ row }) => {
          const t = row.original.spec?.target;
          return t ? (
            <code className="text-xs">{t}</code>
          ) : (
            <span className="text-muted-foreground">— (allocated only)</span>
          );
        },
        size: 180,
      },
      {
        id: "mode",
        header: "Mode",
        accessorFn: (e) => e.spec?.mode ?? "fip",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.spec?.mode ?? "fip"}</span>
        ),
        size: 90,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (e) => eipStatus(e).label,
        cell: ({ row }) => {
          const s = eipStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 120,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (e) => e.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
    ],
    [],
  );

  const filterProperties = useMemo<FilterPropertyDef<ElasticIp>[]>(
    () => [
      { key: "name", label: "Name", getValue: (e) => e.metadata.name },
      { key: "natGateway", label: "NAT gateway", getValue: (e) => e.spec?.natGateway },
      { key: "address", label: "Address", getValue: (e) => eipAddress(e) },
      {
        key: "mode",
        label: "Mode",
        getValue: (e) => e.spec?.mode ?? "fip",
        options: [{ value: "fip" }, { value: "dnat" }],
      },
      {
        key: "status",
        label: "Status",
        getValue: (e) => eipStatus(e).label,
        options: [{ value: "Ready" }, { value: "Provisioning" }],
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<ElasticIp>
      icon={<Globe />}
      title="Elastic IPs"
      description="Static public IPs (kube-ovn). Unlike AWS's account-level pool, an Elastic IP is allocated on a NAT gateway, then associated with a workload — as a 1:1 floating IP (fip) or a per-port forward (dnat). The target must sit on a public subnet."
      listPath={openinfraPaths.elasticips}
      columns={columns}
      onRowClick={(e) =>
        navigate({
          to: "/elastic-ips/$namespace/$name",
          params: {
            namespace: e.metadata.namespace ?? "default",
            name: e.metadata.name ?? "",
          },
        })
      }
      search={(e) => [e.metadata.name, e.metadata.namespace, e.spec?.natGateway, e.spec?.target, eipAddress(e)]}
      singular="Elastic IP"
      plural="Elastic IPs"
      emptyTitle="No Elastic IPs yet"
      emptyDescription="Allocate an Elastic IP on a NAT gateway, then associate it with a workload on a public subnet."
      docsHref={kindDocsUrl("ElasticIp")}
      filterProperties={filterProperties}
      enablePreferences
      enablePagination
      columnLabels={{
        natGateway: "NAT gateway",
        target: "Associated target",
        address: "Address",
        mode: "Mode",
      }}
      headerActions={
        <Button onClick={() => navigate({ to: "/elastic-ips/new" })}>
          <Plus className="size-4" /> Allocate Elastic IP
        </Button>
      }
    />
  );
}
