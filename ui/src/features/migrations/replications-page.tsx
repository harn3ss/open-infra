import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { Repeat, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { ApiError, k8sCreate } from "@/lib/api";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { age, type StatusTone } from "@/lib/format";
import { OPENINFRA_GROUP, OPENINFRA_VERSION } from "@/types/k8s";
import type { Replication, K8sObject } from "@/types/k8s";

const ENGINES = ["postgres", "mysql", "mariadb", "sqlserver"];
const PORTS: Record<string, string> = { postgres: "5432", mysql: "3306", mariadb: "3306", sqlserver: "1433" };
const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

function replStatus(r: Replication): { label: string; tone: StatusTone } {
  const conds = r.status?.conditions ?? [];
  const ready = conds.find((c) => c.type === "Ready");
  const synced = conds.find((c) => c.type === "Synced");
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  if (synced?.status === "False") return { label: "Error", tone: "destructive" };
  return { label: "Provisioning", tone: "warning" };
}

export function ReplicationsPage() {
  const { scoped } = useNamespace();
  const navigate = useNavigate();
  const [newOpen, setNewOpen] = useState(false);


  const columns = useMemo<ColumnDef<Replication, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (r) => r.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 150,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (r) => r.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.metadata.namespace}</span>
        ),
        size: 110,
      },
      {
        id: "topology",
        header: "Sites",
        accessorFn: (r) => r.spec?.siteA?.engine ?? "",
        cell: ({ row }) => {
          const a = row.original.spec?.siteA;
          const b = row.original.spec?.siteB;
          return (
            <span className="text-xs">
              <code>{a?.engine}</code> <span className="text-muted-foreground">{a?.name}</span>
              {" ⇄ "}
              <code>{b?.engine}</code> <span className="text-muted-foreground">{b?.name}</span>
            </span>
          );
        },
        size: 280,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (r) => replStatus(r).label,
        cell: ({ row }) => {
          const s = replStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 110,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (r) => r.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
    ],
    [],
  );

  return (
    <>
      <ResourceTablePage<Replication>
        icon={<Repeat />}
        title="Replication"
        description="Bidirectional / multi-master replication — keep two databases in sync both ways (each is source and target), even across engines (e.g. SQL Server ⇄ Postgres). Loop-prevented, with last-write-wins conflict resolution. Open one to watch live lag, per-table throughput, and dead-letters."
        listPath={openinfraPaths.replications}
        columns={columns}
        search={(r) => [r.metadata.name, r.metadata.namespace, r.spec?.siteA?.engine, r.spec?.siteB?.engine]}
        singular="Replication"
        plural="Replications"
        emptyTitle="No replications yet"
        emptyDescription="Create a bidirectional replication between two databases."
        onRowClick={(r) =>
          navigate({
            to: "/replications/$namespace/$name",
            params: {
              namespace: r.metadata.namespace ?? "default",
              name: r.metadata.name ?? "",
            },
          })
        }
        headerActions={
          <Button onClick={() => setNewOpen(true)}>
            <Plus className="size-4" />
            New Replication
          </Button>
        }
      />
      <NewReplicationDialog open={newOpen} onOpenChange={setNewOpen} defaultNs={scoped} />
    </>
  );
}

function SiteFields({
  prefix,
  state,
  set,
}: {
  prefix: string;
  state: Site;
  set: (s: Partial<Site>) => void;
}) {
  return (
    <div className="space-y-2 rounded-md border p-3">
      <div className="text-sm font-medium">{prefix}</div>
      <div className="grid grid-cols-2 gap-2">
        <div className="space-y-1">
          <Label className="text-xs">Site id (origin marker)</Label>
          <Input value={state.site} onChange={(e) => set({ site: e.target.value })} placeholder="east" />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Engine</Label>
          <Select value={state.engine} onValueChange={(v) => set({ engine: v, port: PORTS[v] ?? "5432" })}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              {ENGINES.map((e) => <SelectItem key={e} value={e}>{e}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Host</Label>
          <Input value={state.host} onChange={(e) => set({ host: e.target.value })} placeholder="pg.ns.svc" />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Port</Label>
          <Input value={state.port} onChange={(e) => set({ port: e.target.value })} />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Database</Label>
          <Input value={state.db} onChange={(e) => set({ db: e.target.value })} />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Username</Label>
          <Input value={state.user} onChange={(e) => set({ user: e.target.value })} />
        </div>
        <div className="space-y-1 col-span-2">
          <Label className="text-xs">Password</Label>
          <Input type="password" value={state.pass} onChange={(e) => set({ pass: e.target.value })} />
        </div>
      </div>
    </div>
  );
}

interface Site {
  site: string;
  engine: string;
  host: string;
  port: string;
  db: string;
  user: string;
  pass: string;
}
const emptySite = (site: string, engine = "postgres"): Site => ({
  site,
  engine,
  host: "",
  port: "5432",
  db: "",
  user: "",
  pass: "",
});

function NewReplicationDialog({
  open,
  onOpenChange,
  defaultNs,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  defaultNs?: string;
}) {
  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState(defaultNs ?? "default");
  const [a, setA] = useState<Site>(emptySite("a"));
  const [b, setB] = useState<Site>(emptySite("b"));
  const [tables, setTables] = useState("");

  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = nsWatch.items
    .map((n) => n.metadata.name)
    .filter((n): n is string => Boolean(n))
    .sort((x, y) => x.localeCompare(y));

  const siteSpec = (s: Site, key: string) => ({
    name: s.site.trim(),
    engine: s.engine,
    host: s.host.trim(),
    port: Number(s.port) || 5432,
    database: s.db.trim(),
    username: s.user.trim(),
    passwordSecretRef: { name: `${name}-creds`, key },
    schema: s.engine === "sqlserver" ? "dbo" : "public",
  });

  const create = useMutation({
    mutationFn: async () => {
      await k8sCreate(corePaths.secrets(namespace), {
        apiVersion: "v1",
        kind: "Secret",
        metadata: { name: `${name}-creds`, namespace },
        stringData: { "a-password": a.pass, "b-password": b.pass },
      } as K8sObject);
      const spec: Record<string, unknown> = {
        siteA: siteSpec(a, "a-password"),
        siteB: siteSpec(b, "b-password"),
        tables: tables.split(",").map((t) => t.trim()).filter(Boolean),
      };
      await k8sCreate(openinfraPaths.replications(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "Replication",
        metadata: { name, namespace },
        spec,
      } as K8sObject);
    },
    onSuccess: () => {
      setName("");
      setA(emptySite("a"));
      setB(emptySite("b"));
      setTables("");
      onOpenChange(false);
    },
  });

  const siteValid = (s: Site) =>
    Boolean(s.site.trim() && s.host.trim() && s.db.trim() && s.user.trim() && s.pass);
  const valid =
    RFC1123.test(name) &&
    Boolean(namespace) &&
    siteValid(a) &&
    siteValid(b) &&
    a.site.trim() !== b.site.trim() &&
    tables.trim().length > 0;

  return (
    <Dialog open={open} onOpenChange={(o) => !create.isPending && onOpenChange(o)}>
      <DialogContent className="sm:max-w-[680px]">
        <DialogHeader>
          <DialogTitle>New Replication</DialogTitle>
          <DialogDescription>
            Keep two databases in sync both ways. Each site needs CDC enabled (Postgres
            wal_level=logical; MySQL binlog; SQL Server CDC + Agent) and the tables must exist on
            both with the same primary key.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-3">
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <Label className="text-xs">Name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="east-west" />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">Namespace</Label>
              <Select value={namespace} onValueChange={setNamespace}>
                <SelectTrigger><SelectValue placeholder="Namespace" /></SelectTrigger>
                <SelectContent>
                  {namespaces.map((ns) => <SelectItem key={ns} value={ns}>{ns}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <SiteFields prefix="Site A" state={a} set={(s) => setA({ ...a, ...s })} />
            <SiteFields prefix="Site B" state={b} set={(s) => setB({ ...b, ...s })} />
          </div>
          <div className="space-y-1">
            <Label className="text-xs">Tables (comma-separated, must exist on both sites)</Label>
            <Input value={tables} onChange={(e) => setTables(e.target.value)} placeholder="customers, orders" />
          </div>
          {create.isError ? (
            <p className="text-sm text-destructive">
              {create.error instanceof ApiError ? create.error.message : "Failed to create the replication."}
            </p>
          ) : null}
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={create.isPending}>
            Cancel
          </Button>
          <Button onClick={() => create.mutate()} disabled={!valid || create.isPending}>
            {create.isPending ? "Creating…" : "Create Replication"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
