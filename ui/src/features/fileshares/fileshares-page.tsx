import { useMemo } from "react";
import { useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { FolderTree, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import {
  type Condition,
  type FileShare,
  type K8sObject,
} from "@/types/k8s";

type SvcStatus = K8sObject<unknown, { loadBalancer?: { ingress?: { ip?: string }[] } }>;


function fsStatus(f: FileShare): { label: string; tone: StatusTone } {
  const ready = (f.status as { conditions?: Condition[] } | undefined)?.conditions?.find(
    (c) => c.type === "Ready",
  );
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

export function FileSharesPage() {
  const { scoped } = useNamespace();
  const navigate = useNavigate();

  // LAN IPs from the per-share LoadBalancer Service (svc name == share name).
  const svcWatch = useK8sWatch<SvcStatus>(corePaths.services(scoped));
  const ipByName = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of svcWatch.items) {
      const ip = s.status?.loadBalancer?.ingress?.[0]?.ip;
      if (ip && s.metadata.name) m.set(`${s.metadata.namespace}/${s.metadata.name}`, ip);
    }
    return m;
  }, [svcWatch.items]);
  const lanIp = (f: FileShare) =>
    ipByName.get(`${f.metadata.namespace}/${f.metadata.name}`);


  const columns = useMemo<ColumnDef<FileShare, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (f) => f.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 180,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (f) => f.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.metadata.namespace}</span>
        ),
        size: 110,
      },
      {
        id: "size",
        header: "Size",
        accessorFn: (f) => f.spec?.size ?? "",
        cell: ({ row }) => <span className="font-mono text-xs">{row.original.spec?.size ?? "—"}</span>,
        size: 90,
      },
      {
        id: "endpoint",
        header: "SMB endpoint",
        accessorFn: (f) => lanIp(f) ?? "",
        cell: ({ row }) => {
          const ip = lanIp(row.original);
          return ip ? (
            <code className="text-xs">\\{ip}\{row.original.metadata.name}</code>
          ) : (
            <span className="text-xs text-muted-foreground">pending IP…</span>
          );
        },
        size: 220,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (f) => fsStatus(f).label,
        cell: ({ row }) => {
          const s = fsStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 120,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (f) => f.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
    ],
    [ipByName],
  );

  return (
    <ResourceTablePage<FileShare>
      icon={<FolderTree />}
      title="File Shares"
      description="Shared SMB file storage — open-infra's FSx. Mount from Windows (net use) or Linux (mount -t cifs); multiple machines can share one. Backed by Longhorn."
      listPath={openinfraPaths.fileshares}
      columns={columns}
      onRowClick={(f) =>
        navigate({
          to: "/fileshares/$namespace/$name",
          params: {
            namespace: f.metadata.namespace ?? "default",
            name: f.metadata.name ?? "",
          },
        })
      }
      search={(f) => [f.metadata.name, f.metadata.namespace, f.spec?.size]}
      singular="File Share"
      plural="File Shares"
      emptyTitle="No file shares yet"
      emptyDescription="Create one, then mount it from your VMs."
      headerActions={
        <Button onClick={() => navigate({ to: "/fileshares/new" })}>
          <Plus className="size-4" /> New File Share
        </Button>
      }
    />
  );
}
