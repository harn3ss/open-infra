import { useMemo, useState, type ReactNode } from "react";
import { useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { useMutation } from "@tanstack/react-query";
import { Radio, Plus } from "lucide-react";
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
  type Stream,
  type K8sObject,
} from "@/types/k8s";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const ENGINES = ["postgres", "mysql", "mariadb", "sqlserver", "mongodb"];
const ENGINE_LABELS: Record<string, string> = {
  postgres: "PostgreSQL",
  mysql: "MySQL",
  mariadb: "MariaDB",
  sqlserver: "SQL Server",
  mongodb: "MongoDB",
};
const ENGINE_PORTS: Record<string, string> = {
  postgres: "5432",
  mysql: "3306",
  mariadb: "3306",
  sqlserver: "1433",
  mongodb: "27017",
};
const usesSchemas = (e: string) => e === "postgres" || e === "sqlserver";
const cdcHint = (e: string): string => {
  switch (e) {
    case "postgres":
      return "Postgres: wal_level=logical (Debezium manages the slot/publication).";
    case "mysql":
    case "mariadb":
      return "MySQL/MariaDB: binlog_format=ROW + a user with REPLICATION rights.";
    case "sqlserver":
      return "SQL Server: CDC enabled (sp_cdc_enable_db) + SQL Server Agent.";
    case "mongodb":
      return "MongoDB: a replica set (Debezium reads change streams).";
    default:
      return "";
  }
};

function streamStatus(s: Stream): { label: string; tone: StatusTone } {
  const conds = s.status?.conditions ?? [];
  const ready = conds.find((c) => c.type === "Ready");
  const synced = conds.find((c) => c.type === "Synced");
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  if (synced?.status === "False") return { label: "Error", tone: "destructive" };
  return { label: "Provisioning", tone: "warning" };
}

export function StreamsPage() {
  const { scoped } = useNamespace();
  const navigate = useNavigate();
  const [newOpen, setNewOpen] = useState(false);

  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = nsWatch.items
    .map((n) => n.metadata.name)
    .filter((n): n is string => Boolean(n))
    .sort((a, b) => a.localeCompare(b));


  const columns = useMemo<ColumnDef<Stream, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (s) => s.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 150,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (s) => s.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.metadata.namespace}</span>
        ),
        size: 110,
      },
      {
        id: "source",
        header: "Source",
        accessorFn: (s) => s.spec?.source?.engine ?? "",
        cell: ({ row }) => {
          const src = row.original.spec?.source;
          return (
            <span className="text-xs">
              <code>{src?.engine}</code>{" "}
              <span className="text-muted-foreground">{src?.host}</span>
            </span>
          );
        },
        size: 240,
      },
      {
        id: "subjects",
        header: "Subjects (JetStream)",
        accessorFn: (s) => s.metadata.name,
        cell: ({ row }) => (
          <code className="text-xs text-muted-foreground">cdc.{row.original.metadata.name}.&gt;</code>
        ),
        size: 200,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (s) => streamStatus(s).label,
        cell: ({ row }) => {
          const s = streamStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 110,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (s) => s.metadata.creationTimestamp ?? "",
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
      <ResourceTablePage<Stream>
        icon={<Radio />}
        title="Streams"
        description="Change-data-capture streams — open-infra's 'Kinesis'. A Stream taps a source database's change log (Debezium) and publishes every row change as a real-time event onto NATS JetStream (subjects cdc.<name>.<schema>.<table>), where apps, Functions, and sinks subscribe."
        listPath={openinfraPaths.streams}
        columns={columns}
        onRowClick={(s) =>
          navigate({
            to: "/streams/$namespace/$name",
            params: {
              namespace: s.metadata.namespace ?? "default",
              name: s.metadata.name ?? "",
            },
          })
        }
        search={(s) => [s.metadata.name, s.metadata.namespace, s.spec?.source?.engine, s.spec?.source?.host]}
        singular="Stream"
        plural="Streams"
        emptyTitle="No streams yet"
        emptyDescription="Create one to publish a database's changes onto JetStream in real time."
        headerActions={
          <Button onClick={() => setNewOpen(true)}>
            <Plus className="size-4" /> New Stream
          </Button>
        }
      />
      <NewStreamDialog
        open={newOpen}
        onOpenChange={setNewOpen}
        namespaces={namespaces}
        defaultNamespace={scoped}
      />
    </>
  );
}

function NewStreamDialog({
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
  const [engine, setEngine] = useState("postgres");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("5432");
  const [database, setDatabase] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [schemas, setSchemas] = useState("public");
  const [tables, setTables] = useState("");
  const [ssl, setSsl] = useState("disable");

  function reset() {
    setName(""); setEngine("postgres"); setHost(""); setPort("5432");
    setDatabase(""); setUsername(""); setPassword(""); setSchemas("public");
    setTables(""); setSsl("disable");
  }
  function onEngineChange(e: string) {
    setEngine(e);
    setPort(ENGINE_PORTS[e] ?? "5432");
    setSchemas(e === "sqlserver" ? "dbo" : "public");
  }

  const create = useMutation({
    mutationFn: async () => {
      await k8sCreate(corePaths.secrets(namespace), {
        apiVersion: "v1",
        kind: "Secret",
        metadata: { name: `${name}-stream-creds`, namespace },
        stringData: { password },
      } as K8sObject);
      const source: Record<string, unknown> = {
        engine,
        host: host.trim(),
        port: Number(port) || 5432,
        database: database.trim(),
        username: username.trim(),
        passwordSecretRef: { name: `${name}-stream-creds`, key: "password" },
        ssl: ssl === "require",
      };
      if (usesSchemas(engine)) {
        source.schemas = schemas.split(",").map((s) => s.trim()).filter(Boolean);
      }
      const t = tables.split(",").map((s) => s.trim()).filter(Boolean);
      if (t.length) source.tables = t;
      await k8sCreate(openinfraPaths.streams(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "Stream",
        metadata: { name, namespace },
        spec: { source },
      } as K8sObject);
    },
    onSuccess: () => {
      reset();
      onOpenChange(false);
    },
  });

  const valid =
    RFC1123.test(name) &&
    Boolean(namespace && host.trim() && database.trim() && username.trim() && password);

  function close(o: boolean) {
    if (create.isPending) return;
    if (!o) reset();
    onOpenChange(o);
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-[600px]">
        <DialogHeader>
          <DialogTitle>New Stream</DialogTitle>
          <DialogDescription>
            Tap a source database's change log and publish row changes onto NATS JetStream
            (subjects <code>cdc.{name || "<name>"}.&gt;</code>). Powered by a headless Debezium Server.
          </DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-2 gap-3 py-1">
          <Field label="Name">
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="orders-cdc" autoFocus />
          </Field>
          <Field label="Namespace">
            <Select value={namespace} onValueChange={setNamespace}>
              <SelectTrigger><SelectValue placeholder="Namespace" /></SelectTrigger>
              <SelectContent>
                {(namespaces.length ? namespaces : [namespace]).map((ns) => (
                  <SelectItem key={ns} value={ns}>{ns}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field label="Engine">
            <Select value={engine} onValueChange={onEngineChange}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {ENGINES.map((e) => (<SelectItem key={e} value={e}>{ENGINE_LABELS[e] ?? e}</SelectItem>))}
              </SelectContent>
            </Select>
          </Field>
          <Field label="TLS">
            <Select value={ssl} onValueChange={setSsl}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="disable">Disabled</SelectItem>
                <SelectItem value="require">Required</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field label="Host" className="col-span-2">
            <Input value={host} onChange={(e) => setHost(e.target.value)} placeholder="mydb-rw.myapp.svc" />
          </Field>
          <Field label="Port">
            <Input value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" />
          </Field>
          <Field label="Database">
            <Input value={database} onChange={(e) => setDatabase(e.target.value)} placeholder="app" />
          </Field>
          <Field label="Username">
            <Input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="cdc" />
          </Field>
          <Field label="Password">
            <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
          {usesSchemas(engine) && (
            <Field label="Schemas (comma-separated)" className="col-span-2">
              <Input value={schemas} onChange={(e) => setSchemas(e.target.value)} placeholder={engine === "sqlserver" ? "dbo" : "public"} />
            </Field>
          )}
          <Field label="Tables / collections (comma-separated, optional)" className="col-span-2">
            <Input value={tables} onChange={(e) => setTables(e.target.value)} placeholder="(blank = all)" />
          </Field>
          <p className="col-span-2 text-xs text-muted-foreground">CDC prereq — {cdcHint(engine)}</p>
        </div>

        {create.error ? (
          <p className="text-sm text-destructive">
            {create.error instanceof ApiError ? create.error.message : "Failed to create the stream."}
          </p>
        ) : null}

        <DialogFooter className="sm:justify-between">
          <Button variant="outline" onClick={() => close(false)} disabled={create.isPending}>Cancel</Button>
          <Button onClick={() => create.mutate()} disabled={create.isPending || !valid}>
            {create.isPending ? "Creating…" : "Create stream"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Field({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return (
    <div className={`space-y-1.5 ${className ?? ""}`}>
      <Label className="text-xs">{label}</Label>
      {children}
    </div>
  );
}
