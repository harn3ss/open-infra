import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { CopyPlus, Plus } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { InstanceTypeLabel } from "@/components/common/instance-type-label";
import { EC2_INSTANCE_TYPES } from "@/lib/instance-types";
import { kindDocsUrl } from "@/lib/kind-docs";
import { claimHealth } from "@/lib/resource-health";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { AutoScalingGroup } from "@/types/k8s";
import { osLabel } from "@/features/vms/vm-shared";

/** kind: AutoScalingGroup — a self-healing group of identical VMs kept at a desired capacity (an EC2
 *  Auto Scaling Group), backed by a KubeVirt VirtualMachinePool. Capacity + members are on the detail
 *  page. */
export function AutoScalingGroupsPage() {
  const navigate = useNavigate();
  const columns = useMemo<ColumnDef<AutoScalingGroup, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (a) => a.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 200,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (a) => a.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.metadata.namespace}</span>
        ),
        size: 130,
      },
      {
        id: "instanceType",
        header: "Instance type",
        accessorFn: (a) => a.spec?.launchTemplate?.os ?? "",
        cell: ({ row }) => {
          const lt = row.original.spec?.launchTemplate;
          return (
            <span className="flex flex-col gap-0.5">
              <span className="text-xs">{osLabel(lt?.os)}</span>
              <InstanceTypeLabel
                compact
                groups={EC2_INSTANCE_TYPES}
                spec={lt as Record<string, unknown> | undefined}
                detail={`${lt?.cpu ?? 2} vCPU · ${lt?.memory ?? "2Gi"}`}
              />
            </span>
          );
        },
        size: 190,
      },
      {
        id: "capacity",
        header: "Capacity",
        accessorFn: (a) => a.status?.desiredCapacity ?? a.spec?.desiredCapacity ?? 0,
        cell: ({ row }) => {
          const sp = row.original.spec;
          const desired = row.original.status?.desiredCapacity ?? sp?.desiredCapacity ?? 0;
          const ready = row.original.status?.readyReplicas;
          return (
            <span className="flex flex-col gap-0.5 text-xs">
              <span className="font-medium">
                {ready !== undefined ? `${ready} / ${desired}` : `${desired}`} desired
              </span>
              <span className="text-muted-foreground">
                min {sp?.minSize ?? 0} · max {sp?.maxSize ?? desired}
              </span>
            </span>
          );
        },
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
        size: 140,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (a) => a.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 90,
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<AutoScalingGroup>
      icon={<CopyPlus />}
      title="Auto Scaling Groups"
      description="Self-healing groups of identical VMs kept at a desired capacity — open-infra's EC2 Auto Scaling Groups. Define a launch template and a capacity; the platform keeps that many members running and replaces unhealthy ones."
      listPath={openinfraPaths.autoscalinggroups}
      columns={columns}
      search={(a) => [a.metadata.name, a.metadata.namespace, a.spec?.launchTemplate?.os]}
      singular="Auto Scaling Group"
      plural="Auto Scaling Groups"
      emptyTitle="No Auto Scaling Groups yet"
      emptyDescription="Create a group from a launch template (one machine's recipe) and a desired capacity; the platform keeps the members healthy at that count."
      docsHref={kindDocsUrl("AutoScalingGroup")}
      headerActions={
        <Button onClick={() => navigate({ to: "/auto-scaling-groups/new" })}>
          <Plus className="size-4" />
          New Auto Scaling Group
        </Button>
      }
      onRowClick={(a) =>
        navigate({
          to: "/auto-scaling-groups/$namespace/$name",
          params: { namespace: a.metadata.namespace ?? "default", name: a.metadata.name ?? "" },
        })
      }
    />
  );
}
