import { useMemo } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { Network, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { kindDocsUrl } from "@/lib/kind-docs";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import { type Condition, type Vpc } from "@/types/k8s";

function vpcStatus(v: Vpc): { label: string; tone: StatusTone } {
  const ready = (v.status as { conditions?: Condition[] } | undefined)?.conditions?.find(
    (c) => c.type === "Ready",
  );
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

export function VpcsPage() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<Vpc, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (v) => v.metadata.name,
        cell: ({ row }) => (
          <Link
            to="/vpcs/$namespace/$name"
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
        id: "namespaces",
        header: "Namespaces",
        accessorFn: (v) => (v.spec?.namespaces ?? []).join(", "),
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {row.original.spec?.namespaces?.length ? row.original.spec.namespaces.join(", ") : "—"}
          </span>
        ),
        size: 260,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (v) => vpcStatus(v).label,
        cell: ({ row }) => {
          const s = vpcStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 110,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (v) => v.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<Vpc>
      icon={<Network />}
      title="VPCs"
      description="Isolated network domains (kube-ovn). A VPC groups subnets into a private routing domain — the AWS VPC model, OVN-enforced. Subnets reference their VPC via spec.vpc."
      listPath={openinfraPaths.vpcs}
      columns={columns}
      onRowClick={(v) =>
        navigate({
          to: "/vpcs/$namespace/$name",
          params: {
            namespace: v.metadata.namespace ?? "default",
            name: v.metadata.name ?? "",
          },
        })
      }
      search={(v) => [v.metadata.name, v.metadata.namespace]}
      singular="VPC"
      plural="VPCs"
      emptyTitle="No VPCs yet"
      emptyDescription="Create a VPC, then add subnets that reference it."
      docsHref={kindDocsUrl("Vpc")}
      headerActions={
        <Button onClick={() => navigate({ to: "/vpcs/new" })}>
          <Plus className="size-4" /> New VPC
        </Button>
      }
    />
  );
}
