import { useMemo } from "react";
import { useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { Building2, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { kindDocsUrl } from "@/lib/kind-docs";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import {
  type Condition,
  type Directory,
  type K8sObject,
} from "@/types/k8s";

type SvcStatus = K8sObject<
  { clusterIP?: string },
  { loadBalancer?: { ingress?: { ip?: string }[] } }
>;


function dirStatus(d: Directory): { label: string; tone: StatusTone } {
  const ready = (d.status as { conditions?: Condition[] } | undefined)?.conditions?.find(
    (c) => c.type === "Ready",
  );
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

export function DirectoriesPage() {
  const { scoped } = useNamespace();
  const navigate = useNavigate();

  // The DC's reachable address comes from its Service (svc name == directory
  // name): the LAN LoadBalancer IP when exposed, else the in-cluster ClusterIP.
  const svcWatch = useK8sWatch<SvcStatus>(corePaths.services(scoped));
  const ipByName = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of svcWatch.items) {
      const ip = s.status?.loadBalancer?.ingress?.[0]?.ip ?? s.spec?.clusterIP;
      if (ip && s.metadata.name) m.set(`${s.metadata.namespace}/${s.metadata.name}`, ip);
    }
    return m;
  }, [svcWatch.items]);
  const dcIp = (d: Directory) =>
    ipByName.get(`${d.metadata.namespace}/${d.metadata.name}`);


  const columns = useMemo<ColumnDef<Directory, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (d) => d.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 170,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (d) => d.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.metadata.namespace}</span>
        ),
        size: 110,
      },
      {
        id: "domain",
        header: "Domain",
        accessorFn: (d) => d.spec?.domain ?? "",
        cell: ({ row }) => (
          <code className="text-xs">{row.original.spec?.domain ?? "—"}</code>
        ),
        size: 190,
      },
      {
        id: "dc",
        header: "DC address",
        accessorFn: (d) => dcIp(d) ?? "",
        cell: ({ row }) => {
          const ip = dcIp(row.original);
          return ip ? (
            <code className="text-xs">{ip}</code>
          ) : (
            <span className="text-xs text-muted-foreground">pending…</span>
          );
        },
        size: 150,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (d) => dirStatus(d).label,
        cell: ({ row }) => {
          const s = dirStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 120,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (d) => d.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
    ],
    [ipByName],
  );

  return (
    <ResourceTablePage<Directory>
      icon={<Building2 />}
      title="Active Directory"
      description="Managed Active Directory domains — open-infra's Directory Service (Samba AD DC, the open-source path; no Microsoft licensing). Windows and Linux machines domain-join it — click Join for the per-machine steps."
      listPath={openinfraPaths.directories}
      columns={columns}
      onRowClick={(d) =>
        navigate({
          to: "/directories/$namespace/$name",
          params: {
            namespace: d.metadata.namespace ?? "default",
            name: d.metadata.name ?? "",
          },
        })
      }
      search={(d) => [d.metadata.name, d.metadata.namespace, d.spec?.domain]}
      singular="Directory"
      plural="Directories"
      emptyTitle="No directories yet"
      emptyDescription="Create a domain, then join VMs to it."
      docsHref={kindDocsUrl("Directory")}
      headerActions={
        <Button onClick={() => navigate({ to: "/directories/new" })}>
          <Plus className="size-4" /> New Directory
        </Button>
      }
    />
  );
}
