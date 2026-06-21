import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { Disc, Monitor, Plus } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { Button } from "@/components/ui/button";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { corePaths, kubevirtPaths, openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import { type K8sObject, type VirtualMachine, type Vmi } from "@/types/k8s";
import { NewVmDialog } from "./new-vm-dialog";
import { osLabel, vmIp, vmKey, vmStatus } from "./vm-shared";

export function VmsPage() {
  const navigate = useNavigate();
  const { scoped } = useNamespace();
  const [newOpen, setNewOpen] = useState(false);

  // Live guest status (IP, phase) keyed by namespace/name.
  const vmiWatch = useK8sWatch<Vmi>(kubevirtPaths.vmis(scoped));
  const vmiByKey = useMemo(() => {
    const m = new Map<string, Vmi>();
    for (const v of vmiWatch.items)
      m.set(vmKey(v.metadata.namespace, v.metadata.name), v);
    return m;
  }, [vmiWatch.items]);

  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = nsWatch.items
    .map((n) => n.metadata.name)
    .filter((n): n is string => Boolean(n))
    .sort((a, b) => a.localeCompare(b));

  const columns = useMemo<ColumnDef<VirtualMachine, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (vm) => vm.metadata.name,
        cell: ({ row }) => (
          <span className="font-medium">{row.original.metadata.name}</span>
        ),
        size: 180,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (vm) => vm.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {row.original.metadata.namespace}
          </span>
        ),
        size: 120,
      },
      {
        id: "os",
        header: "OS",
        accessorFn: (vm) => vm.spec?.os ?? "",
        cell: ({ row }) => (
          <span className="text-sm">{osLabel(row.original.spec?.os)}</span>
        ),
        size: 180,
      },
      {
        id: "size",
        header: "Size",
        accessorFn: (vm) => vm.spec?.cpu ?? 0,
        cell: ({ row }) => (
          <span className="font-mono text-xs text-muted-foreground">
            {row.original.spec?.cpu ?? 2} vCPU · {row.original.spec?.memory ?? "2Gi"}
          </span>
        ),
        size: 150,
      },
      {
        id: "ip",
        header: "IP",
        accessorFn: (vm) =>
          vmIp(vmiByKey.get(vmKey(vm.metadata.namespace, vm.metadata.name))) ??
          "",
        cell: ({ row }) => {
          const ip = vmIp(
            vmiByKey.get(
              vmKey(row.original.metadata.namespace, row.original.metadata.name),
            ),
          );
          return ip ? (
            <code className="text-xs">{ip}</code>
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          );
        },
        size: 120,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (vm) =>
          vmStatus(
            vm,
            vmiByKey.get(vmKey(vm.metadata.namespace, vm.metadata.name)),
          ).label,
        cell: ({ row }) => {
          const s = vmStatus(
            row.original,
            vmiByKey.get(
              vmKey(row.original.metadata.namespace, row.original.metadata.name),
            ),
          );
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 140,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (vm) => vm.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {age(row.original.metadata.creationTimestamp)}
          </span>
        ),
        size: 80,
      },
    ],
    [vmiByKey],
  );

  return (
    <>
      <ResourceTablePage<VirtualMachine>
        icon={<Monitor />}
        title="Virtual Machines"
        description="Real VMs on the cluster — open-infra's EC2. Pick an OS and get a persistent disk, SSH (Linux) or RDP (Windows), and an optional LAN IP."
        listPath={openinfraPaths.virtualmachines}
        columns={columns}
        search={(vm) => [vm.metadata.name, vm.metadata.namespace, vm.spec?.os]}
        singular="Virtual Machine"
        plural="Virtual Machines"
        emptyTitle="No Virtual Machines yet"
        emptyDescription="Create one, or scaffold with `open-infra init vm`."
        onRowClick={(vm) =>
          navigate({
            to: "/vms/$namespace/$name",
            params: {
              namespace: vm.metadata.namespace ?? "default",
              name: vm.metadata.name ?? "",
            },
          })
        }
        headerActions={
          <div className="flex gap-2">
            <Button
              variant="outline"
              onClick={() => navigate({ to: "/vms/images" })}
            >
              <Disc className="size-4" />
              VM Images
            </Button>
            <Button onClick={() => setNewOpen(true)}>
              <Plus className="size-4" />
              New VM
            </Button>
          </div>
        }
      />
      <NewVmDialog
        open={newOpen}
        onOpenChange={setNewOpen}
        namespaces={namespaces}
        defaultNamespace={scoped}
        listPath={openinfraPaths.virtualmachines(scoped)}
      />
    </>
  );
}
