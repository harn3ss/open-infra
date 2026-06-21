import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Building2, Plus, Plug, Trash2 } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { StatusBadge } from "@/components/common/status-badge";
import { CopyButton } from "@/components/common/copy-button";
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
import { ApiError, k8sCreate, k8sDelete, k8sGet } from "@/lib/api";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import {
  OPENINFRA_GROUP,
  OPENINFRA_VERSION,
  type Condition,
  type Directory,
  type K8sObject,
} from "@/types/k8s";

// A domain FQDN: at least two dot-separated labels, lowercase.
const FQDN = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)+$/;
// The k8s resource name — a single RFC1123 label, distinct from the domain FQDN.
const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

type SvcStatus = K8sObject<
  { clusterIP?: string },
  { loadBalancer?: { ingress?: { ip?: string }[] } }
>;

function decode(v?: string): string {
  if (!v) return "";
  try {
    return atob(v);
  } catch {
    return "";
  }
}

function dirStatus(d: Directory): { label: string; tone: StatusTone } {
  const ready = (d.status as { conditions?: Condition[] } | undefined)?.conditions?.find(
    (c) => c.type === "Ready",
  );
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

export function DirectoriesPage() {
  const { scoped } = useNamespace();
  const [newOpen, setNewOpen] = useState(false);
  const [join, setJoin] = useState<{ dir: Directory; ip?: string } | null>(null);

  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = nsWatch.items
    .map((n) => n.metadata.name)
    .filter((n): n is string => Boolean(n))
    .sort((a, b) => a.localeCompare(b));

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

  const remove = useMutation({
    mutationFn: (d: Directory) =>
      k8sDelete(openinfraPaths.directory(d.metadata.namespace ?? "default", d.metadata.name ?? "")),
  });

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
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => (
          <span className="flex justify-end gap-1">
            <Button
              size="sm"
              variant="outline"
              onClick={() => setJoin({ dir: row.original, ip: dcIp(row.original) })}
              title="How to join this domain"
            >
              <Plug className="size-4" /> Join
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => remove.mutate(row.original)}
              disabled={remove.isPending}
              title="Delete this directory"
            >
              <Trash2 className="size-4" />
            </Button>
          </span>
        ),
        size: 130,
      },
    ],
    [ipByName, remove],
  );

  return (
    <>
      <ResourceTablePage<Directory>
        icon={<Building2 />}
        title="Active Directory"
        description="Managed Active Directory domains — open-infra's Directory Service (Samba AD DC, the open-source path; no Microsoft licensing). Windows and Linux machines domain-join it; new VMs can auto-join by picking a domain at create time."
        listPath={openinfraPaths.directories}
        columns={columns}
        search={(d) => [d.metadata.name, d.metadata.namespace, d.spec?.domain]}
        singular="Directory"
        plural="Directories"
        emptyTitle="No directories yet"
        emptyDescription="Create a domain, then join VMs to it."
        headerActions={
          <Button onClick={() => setNewOpen(true)}>
            <Plus className="size-4" /> New Directory
          </Button>
        }
      />
      <NewDirectoryDialog
        open={newOpen}
        onOpenChange={setNewOpen}
        namespaces={namespaces}
        defaultNamespace={scoped}
      />
      <JoinDialog join={join} onClose={() => setJoin(null)} />
    </>
  );
}

function JoinDialog({
  join,
  onClose,
}: {
  join: { dir: Directory; ip?: string } | null;
  onClose: () => void;
}) {
  const dir = join?.dir;
  const ns = dir?.metadata.namespace ?? "default";
  const name = dir?.metadata.name ?? "";
  const { data: secret } = useQuery({
    queryKey: ["directory-secret", ns, name],
    enabled: Boolean(dir),
    queryFn: () =>
      k8sGet<K8sObject & { data?: Record<string, string> }>(
        `/api/v1/namespaces/${ns}/secrets/${name}-directory`,
      ),
    retry: false,
  });
  const domain = dir?.spec?.domain ?? decode(secret?.data?.DOMAIN);
  const netbios = decode(secret?.data?.NETBIOS) || domain.split(".")[0]?.toUpperCase();
  const user = decode(secret?.data?.ADMIN_USER) || "Administrator";
  const pass = decode(secret?.data?.ADMIN_PASSWORD);
  const dc = join?.ip ?? "<DC address>";
  // Windows: point DNS at the DC, then join (rename + join atomically).
  const winCmd = `netsh interface ip set dns name="Ethernet" static ${dc}; Add-Computer -DomainName ${domain} -Credential (New-Object System.Management.Automation.PSCredential("${netbios}\\${user}",(ConvertTo-SecureString "${pass}" -AsPlainText -Force))) -Restart`;
  // Linux: realmd join.
  const linCmd = `echo "${pass}" | sudo realm join --user=${user} ${domain}`;

  return (
    <Dialog open={Boolean(dir)} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Join {domain}</DialogTitle>
          <DialogDescription>
            {join?.ip
              ? "Point the machine's DNS at the DC, then join with the admin credentials below. New VMs can auto-join by selecting this domain at create time."
              : "DC address pending — give it a moment to get an IP."}
          </DialogDescription>
        </DialogHeader>
        <div className="min-w-0 space-y-3 text-sm">
          <Row label="Domain" value={domain} />
          <Row label="DC address (use as the client's DNS)" value={dc} />
          <Row label="Admin user" value={`${netbios}\\${user}`} />
          <Row label="Admin password" value={pass || "—"} />
          <Row label="Windows (PowerShell, admin)" value={winCmd} />
          <Row label="Linux (realmd)" value={linCmd} />
        </div>
        <DialogFooter>
          <Button onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 space-y-1">
      <Label className="text-xs text-muted-foreground">{label}</Label>
      <div className="flex min-w-0 items-center gap-1">
        <code
          title={value}
          className="min-w-0 flex-1 truncate rounded bg-muted px-2 py-1 text-xs"
        >
          {value}
        </code>
        <CopyButton value={value} />
      </div>
    </div>
  );
}

function NewDirectoryDialog({
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
  const [domain, setDomain] = useState("");
  const [size, setSize] = useState("5Gi");
  const [namespace, setNamespace] = useState(defaultNamespace ?? "default");

  const create = useMutation({
    mutationFn: () =>
      k8sCreate(openinfraPaths.directories(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "Directory",
        metadata: { name, namespace },
        spec: { domain, size: size || "5Gi" },
      } as K8sObject),
    onSuccess: () => {
      setName("");
      setDomain("");
      setSize("5Gi");
      onOpenChange(false);
    },
  });

  return (
    <Dialog open={open} onOpenChange={(o) => !create.isPending && onOpenChange(o)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New Directory</DialogTitle>
          <DialogDescription>
            A managed Active Directory domain (Samba AD DC) on its own LAN IP. Join
            VMs and desktops to it; new VMs can auto-join at create time.
          </DialogDescription>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1.5">
            <Label htmlFor="dir-name">Name</Label>
            <Input id="dir-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="corp" autoFocus />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="dir-size">Size</Label>
            <Input id="dir-size" value={size} onChange={(e) => setSize(e.target.value)} placeholder="5Gi" />
          </div>
          <div className="space-y-1.5 col-span-2">
            <Label htmlFor="dir-domain">Domain (FQDN)</Label>
            <Input id="dir-domain" value={domain} onChange={(e) => setDomain(e.target.value.toLowerCase())} placeholder="corp.openinfra.lan" />
            <p className="text-xs text-muted-foreground">
              Lowercase, at least two labels — e.g. <code>corp.openinfra.lan</code>. The Kerberos realm + NetBIOS name are derived from it.
            </p>
          </div>
          <div className="space-y-1.5 col-span-2">
            <Label htmlFor="dir-ns">Namespace</Label>
            <Select value={namespace} onValueChange={setNamespace}>
              <SelectTrigger id="dir-ns"><SelectValue placeholder="Namespace" /></SelectTrigger>
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
            {create.error instanceof ApiError ? create.error.message : "Failed to create the directory."}
          </p>
        ) : null}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={create.isPending}>Cancel</Button>
          <Button
            onClick={() => create.mutate()}
            disabled={create.isPending || !RFC1123.test(name) || !FQDN.test(domain)}
          >
            {create.isPending ? "Creating…" : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
