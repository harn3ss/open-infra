import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { useMutation } from "@tanstack/react-query";
import { FolderTree, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { ApiError, k8sCreate } from "@/lib/api";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import {
  OPENINFRA_GROUP,
  OPENINFRA_VERSION,
  type Condition,
  type FileShare,
  type K8sObject,
} from "@/types/k8s";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

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
  const [newOpen, setNewOpen] = useState(false);

  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = nsWatch.items
    .map((n) => n.metadata.name)
    .filter((n): n is string => Boolean(n))
    .sort((a, b) => a.localeCompare(b));

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
    <>
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
          <Button onClick={() => setNewOpen(true)}>
            <Plus className="size-4" /> New File Share
          </Button>
        }
      />
      <NewFileShareDialog
        open={newOpen}
        onOpenChange={setNewOpen}
        namespaces={namespaces}
        defaultNamespace={scoped}
      />
    </>
  );
}



function NewFileShareDialog({
  open,
  onOpenChange,
  namespaces,
  defaultNamespace,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  namespaces: string[];
  defaultNamespace?: string;
}) {
  const [name, setName] = useState("");
  const [size, setSize] = useState("50Gi");
  const [namespace, setNamespace] = useState(defaultNamespace ?? "default");

  const create = useMutation({
    mutationFn: () =>
      k8sCreate(openinfraPaths.fileshares(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "FileShare",
        metadata: { name, namespace },
        spec: { size: size || "50Gi" },
      } as K8sObject),
    onSuccess: () => {
      setName("");
      setSize("50Gi");
      onOpenChange(false);
    },
  });

  return (
    <Dialog open={open} onOpenChange={(o) => !create.isPending && onOpenChange(o)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New File Share</DialogTitle>
          <DialogDescription>
            An SMB share backed by Longhorn, on its own LAN IP. Mount it from any VM.
          </DialogDescription>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1.5">
            <Label htmlFor="fs-name">Name</Label>
            <Input id="fs-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="team-share" autoFocus />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="fs-size">Size</Label>
            <Input id="fs-size" value={size} onChange={(e) => setSize(e.target.value)} placeholder="50Gi" />
          </div>
          <div className="space-y-1.5 col-span-2">
            <Label htmlFor="fs-ns">Namespace</Label>
            <Select value={namespace} onValueChange={setNamespace}>
              <SelectTrigger id="fs-ns"><SelectValue placeholder="Namespace" /></SelectTrigger>
              <SelectContent>
                {(namespaces.length ? namespaces : [namespace]).map((ns) => (
                  <SelectItem key={ns} value={ns}>{ns}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
        {create.error ? (
          <p className="text-sm text-destructive">
            {create.error instanceof ApiError ? create.error.message : "Failed to create the share."}
          </p>
        ) : null}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={create.isPending}>Cancel</Button>
          <Button onClick={() => create.mutate()} disabled={create.isPending || !RFC1123.test(name)}>
            {create.isPending ? "Creating…" : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
