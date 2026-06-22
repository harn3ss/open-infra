import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useMutation } from "@tanstack/react-query";
import { ArrowRightLeft, Plus, Trash2 } from "lucide-react";
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
import { ApiError, k8sCreate, k8sDelete } from "@/lib/api";
import { corePaths, openinfraPaths, batchPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import {
  OPENINFRA_GROUP,
  OPENINFRA_VERSION,
  type Job,
  type Migration,
  type K8sObject,
} from "@/types/k8s";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
// Sources pgloader can full-load into PostgreSQL (the v1 target).
const SOURCE_ENGINES = ["postgres", "mysql", "mariadb", "sqlite", "mssql"];

// A Migration's run status is derived from its pgloader Job.
function migStatus(job?: Job): { label: string; tone: StatusTone } {
  const s = job?.status;
  if (!s) return { label: "Pending", tone: "muted" };
  if ((s.succeeded ?? 0) > 0) return { label: "Migrated", tone: "success" };
  if ((s.active ?? 0) > 0) return { label: "Running", tone: "warning" };
  if ((s.failed ?? 0) > 0) return { label: "Failed", tone: "destructive" };
  return { label: "Pending", tone: "muted" };
}

export function MigrationsPage() {
  const { scoped } = useNamespace();
  const [newOpen, setNewOpen] = useState(false);

  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = nsWatch.items
    .map((n) => n.metadata.name)
    .filter((n): n is string => Boolean(n))
    .sort((a, b) => a.localeCompare(b));

  // The pgloader Job for each migration (Job name == <migration>-migration).
  const jobWatch = useK8sWatch<Job>(batchPaths.jobs(scoped));
  const jobByMig = useMemo(() => {
    const m = new Map<string, Job>();
    for (const j of jobWatch.items) {
      const n = j.metadata.name ?? "";
      if (n.endsWith("-migration"))
        m.set(`${j.metadata.namespace}/${n.replace(/-migration$/, "")}`, j);
    }
    return m;
  }, [jobWatch.items]);
  const jobFor = (mig: Migration) =>
    jobByMig.get(`${mig.metadata.namespace}/${mig.metadata.name}`);

  const remove = useMutation({
    mutationFn: (mig: Migration) =>
      k8sDelete(openinfraPaths.migration(mig.metadata.namespace ?? "default", mig.metadata.name ?? "")),
  });

  const columns = useMemo<ColumnDef<Migration, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (m) => m.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 150,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (m) => m.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.metadata.namespace}</span>
        ),
        size: 110,
      },
      {
        id: "source",
        header: "Source",
        accessorFn: (m) => m.spec?.source?.engine ?? "",
        cell: ({ row }) => (
          <span className="text-xs">
            <code>{row.original.spec?.source?.engine}</code>{" "}
            <span className="text-muted-foreground">{row.original.spec?.source?.secretRef}</span>
          </span>
        ),
        size: 190,
      },
      {
        id: "target",
        header: "Target",
        accessorFn: (m) => m.spec?.target?.secretRef ?? "",
        cell: ({ row }) => (
          <span className="text-xs">
            <code>postgres</code>{" "}
            <span className="text-muted-foreground">{row.original.spec?.target?.secretRef}</span>
          </span>
        ),
        size: 180,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (m) => migStatus(jobFor(m)).label,
        cell: ({ row }) => {
          const s = migStatus(jobFor(row.original));
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 110,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (m) => m.metadata.creationTimestamp ?? "",
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
              onClick={() => remove.mutate(row.original)}
              disabled={remove.isPending}
              title="Delete this migration"
            >
              <Trash2 className="size-4" />
            </Button>
          </span>
        ),
        size: 80,
      },
    ],
    [jobByMig, remove],
  );

  return (
    <>
      <ResourceTablePage<Migration>
        icon={<ArrowRightLeft />}
        title="Migrations"
        description="Database migrations — open-infra's DMS. Full-load a source database (Postgres, MySQL, MariaDB, SQLite, MS SQL Server) into a managed Postgres via pgloader. Source + target are connection-secret references (key: uri)."
        listPath={openinfraPaths.migrations}
        columns={columns}
        search={(m) => [m.metadata.name, m.metadata.namespace, m.spec?.source?.engine]}
        singular="Migration"
        plural="Migrations"
        emptyTitle="No migrations yet"
        emptyDescription="Create one to full-load a source database into a managed Postgres."
        headerActions={
          <Button onClick={() => setNewOpen(true)}>
            <Plus className="size-4" /> New Migration
          </Button>
        }
      />
      <NewMigrationDialog
        open={newOpen}
        onOpenChange={setNewOpen}
        namespaces={namespaces}
        defaultNamespace={scoped}
      />
    </>
  );
}

function NewMigrationDialog({
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
  const [namespace, setNamespace] = useState(defaultNamespace ?? "default");
  const [srcEngine, setSrcEngine] = useState("postgres");
  const [srcSecret, setSrcSecret] = useState("");
  const [tgtSecret, setTgtSecret] = useState("");

  const create = useMutation({
    mutationFn: () =>
      k8sCreate(openinfraPaths.migrations(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "Migration",
        metadata: { name, namespace },
        spec: {
          source: { engine: srcEngine, secretRef: srcSecret.trim() },
          target: { engine: "postgres", secretRef: tgtSecret.trim() },
          mode: "full-load",
        },
      } as K8sObject),
    onSuccess: () => {
      setName("");
      setSrcSecret("");
      setTgtSecret("");
      onOpenChange(false);
    },
  });

  const valid = RFC1123.test(name) && Boolean(srcSecret.trim()) && Boolean(tgtSecret.trim());

  return (
    <Dialog open={open} onOpenChange={(o) => !create.isPending && onOpenChange(o)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New Migration</DialogTitle>
          <DialogDescription>
            Full-load a source database into a managed Postgres (pgloader). Give the source and
            target as the names of Secrets holding a connection URI (key <code>uri</code>) — a
            managed DB is just its <code>&lt;app&gt;-db-app</code> secret.
          </DialogDescription>
        </DialogHeader>
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1.5">
            <Label htmlFor="mig-name">Name</Label>
            <Input id="mig-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="legacy-import" autoFocus />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="mig-ns">Namespace</Label>
            <Select value={namespace} onValueChange={setNamespace}>
              <SelectTrigger id="mig-ns"><SelectValue placeholder="Namespace" /></SelectTrigger>
              <SelectContent>
                {(namespaces.length ? namespaces : [namespace]).map((ns) => (
                  <SelectItem key={ns} value={ns}>{ns}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="mig-src-engine">Source engine</Label>
            <Select value={srcEngine} onValueChange={setSrcEngine}>
              <SelectTrigger id="mig-src-engine"><SelectValue /></SelectTrigger>
              <SelectContent>
                {SOURCE_ENGINES.map((e) => (<SelectItem key={e} value={e}>{e}</SelectItem>))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="mig-src-secret">Source secret</Label>
            <Input id="mig-src-secret" value={srcSecret} onChange={(e) => setSrcSecret(e.target.value)} placeholder="src-conn" />
          </div>
          <div className="space-y-1.5 col-span-2">
            <Label htmlFor="mig-tgt-secret">Target Postgres secret</Label>
            <Input id="mig-tgt-secret" value={tgtSecret} onChange={(e) => setTgtSecret(e.target.value)} placeholder="myapp-db-app" />
            <p className="text-xs text-muted-foreground">
              A managed Postgres connection secret (key <code>uri</code>) — e.g. an app's <code>&lt;app&gt;-db-app</code>.
            </p>
          </div>
        </div>
        {create.error ? (
          <p className="text-sm text-destructive">
            {create.error instanceof ApiError ? create.error.message : "Failed to create the migration."}
          </p>
        ) : null}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={create.isPending}>Cancel</Button>
          <Button onClick={() => create.mutate()} disabled={create.isPending || !valid}>
            {create.isPending ? "Creating…" : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
