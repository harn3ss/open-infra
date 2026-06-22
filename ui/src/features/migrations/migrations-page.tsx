import { useMemo, useState, type ReactNode } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ArrowRightLeft, Check, Play, Plus, Trash2 } from "lucide-react";
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
import {
  ApiError,
  k8sCreate,
  k8sDelete,
  triggerMigrationSync,
  discoverTables,
} from "@/lib/api";
import { corePaths, openinfraPaths, resourcePaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import {
  OPENINFRA_GROUP,
  OPENINFRA_VERSION,
  type Migration,
  type K8sObject,
} from "@/types/k8s";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const SOURCE_ENGINES = ["postgres", "mysql"];
const MODES = [
  { value: "full-load", label: "Full load — one-shot copy of existing data" },
  { value: "cdc", label: "CDC — ongoing change-data-capture sync only" },
  { value: "full-load-and-cdc", label: "Full load + CDC — copy, then keep in sync" },
];
const STEPS = ["Source", "Target", "Task", "Review"];

// A Migration's status, derived from the claim's Crossplane conditions.
function migStatus(m: Migration): { label: string; tone: StatusTone } {
  const conds = m.status?.conditions ?? [];
  const ready = conds.find((c) => c.type === "Ready");
  const synced = conds.find((c) => c.type === "Synced");
  if (ready?.status === "True") return { label: "Ready", tone: "success" };
  if (synced?.status === "False") return { label: "Error", tone: "destructive" };
  return { label: "Provisioning", tone: "warning" };
}

export function MigrationsPage() {
  const { scoped } = useNamespace();
  const [newOpen, setNewOpen] = useState(false);
  const [syncMsg, setSyncMsg] = useState<{ tone: "ok" | "err"; text: string } | null>(null);

  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = nsWatch.items
    .map((n) => n.metadata.name)
    .filter((n): n is string => Boolean(n))
    .sort((a, b) => a.localeCompare(b));

  const remove = useMutation({
    mutationFn: async (m: Migration) => {
      const ns = m.metadata.namespace ?? "default";
      const name = m.metadata.name ?? "";
      await k8sDelete(openinfraPaths.migration(ns, name));
      // Best-effort cleanup of the wizard-created credential Secret.
      await k8sDelete(resourcePaths.secret(ns, `${name}-creds`)).catch(() => {});
    },
  });

  const runSync = useMutation({
    mutationFn: (m: Migration) =>
      triggerMigrationSync(m.metadata.namespace ?? "default", m.metadata.name ?? ""),
    onSuccess: (_d, m) =>
      setSyncMsg({ tone: "ok", text: `Sync started for ${m.metadata.name}.` }),
    onError: (e, m) =>
      setSyncMsg({
        tone: "err",
        text: `Couldn't sync ${m.metadata.name}: ${e instanceof ApiError ? e.message : "error"}`,
      }),
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
        id: "mode",
        header: "Type",
        accessorFn: (m) => m.spec?.mode ?? "full-load",
        cell: ({ row }) => <span className="text-xs">{row.original.spec?.mode ?? "full-load"}</span>,
        size: 130,
      },
      {
        id: "route",
        header: "Route",
        accessorFn: (m) => m.spec?.source?.engine ?? "",
        cell: ({ row }) => {
          const s = row.original.spec?.source;
          const t = row.original.spec?.target;
          return (
            <span className="text-xs">
              <code>{s?.engine}</code>{" "}
              <span className="text-muted-foreground">{s?.host}</span>
              {" → "}
              <code>postgres</code>{" "}
              <span className="text-muted-foreground">{t?.host}</span>
            </span>
          );
        },
        size: 280,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (m) => migStatus(m).label,
        cell: ({ row }) => {
          const s = migStatus(row.original);
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
              onClick={() => runSync.mutate(row.original)}
              disabled={
                runSync.isPending &&
                runSync.variables?.metadata?.name === row.original.metadata.name
              }
              title="Run a sync now"
            >
              <Play className="size-4" />
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => remove.mutate(row.original)}
              disabled={remove.isPending}
              title="Delete this migration (and its credential secret)"
            >
              <Trash2 className="size-4" />
            </Button>
          </span>
        ),
        size: 80,
      },
    ],
    [remove, runSync],
  );

  return (
    <>
      {syncMsg && (
        <button
          onClick={() => setSyncMsg(null)}
          className={`mb-2 block w-full rounded-md px-3 py-2 text-left text-sm ${
            syncMsg.tone === "ok"
              ? "bg-primary/10 text-foreground"
              : "bg-destructive/10 text-destructive"
          }`}
        >
          {syncMsg.text}
        </button>
      )}
      <ResourceTablePage<Migration>
        icon={<ArrowRightLeft />}
        title="Migrations"
        description="Database migrations — open-infra's DMS. Full-load and/or ongoing CDC sync from a source database (Postgres, MySQL) into a managed Postgres. Like AWS DMS: define source + target endpoints, pick a task type, and it keeps your data flowing."
        listPath={openinfraPaths.migrations}
        columns={columns}
        search={(m) => [m.metadata.name, m.metadata.namespace, m.spec?.source?.engine, m.spec?.source?.host]}
        singular="Migration"
        plural="Migrations"
        emptyTitle="No migrations yet"
        emptyDescription="Create one to full-load or continuously sync a source database into a managed Postgres."
        headerActions={
          <Button onClick={() => setNewOpen(true)}>
            <Plus className="size-4" /> New Migration
          </Button>
        }
      />
      <NewMigrationWizard
        open={newOpen}
        onOpenChange={setNewOpen}
        namespaces={namespaces}
        defaultNamespace={scoped}
      />
    </>
  );
}

function NewMigrationWizard({
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
  const [step, setStep] = useState(0);
  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState(defaultNamespace ?? "default");
  const [mode, setMode] = useState("full-load");
  const [tableMode, setTableMode] = useState<"all" | "choose">("all");
  const [selectedTables, setSelectedTables] = useState<Set<string>>(new Set());
  // source
  const [srcEngine, setSrcEngine] = useState("postgres");
  const [srcHost, setSrcHost] = useState("");
  const [srcPort, setSrcPort] = useState("5432");
  const [srcDb, setSrcDb] = useState("");
  const [srcUser, setSrcUser] = useState("");
  const [srcPass, setSrcPass] = useState("");
  const [srcSchemas, setSrcSchemas] = useState("public");
  const [srcSsl, setSrcSsl] = useState("disable");
  // target
  const [tgtHost, setTgtHost] = useState("");
  const [tgtPort, setTgtPort] = useState("5432");
  const [tgtDb, setTgtDb] = useState("");
  const [tgtUser, setTgtUser] = useState("");
  const [tgtPass, setTgtPass] = useState("");
  const [tgtSchema, setTgtSchema] = useState("public");
  const [tgtSsl, setTgtSsl] = useState("disable");

  function reset() {
    setStep(0);
    setName("");
    setMode("full-load");
    setTableMode("all");
    setSelectedTables(new Set());
    setSrcEngine("postgres");
    setSrcHost(""); setSrcPort("5432"); setSrcDb(""); setSrcUser(""); setSrcPass(""); setSrcSchemas("public"); setSrcSsl("disable");
    setTgtHost(""); setTgtPort("5432"); setTgtDb(""); setTgtUser(""); setTgtPass(""); setTgtSchema("public"); setTgtSsl("disable");
  }

  function onEngineChange(e: string) {
    setSrcEngine(e);
    setSrcPort(e === "mysql" ? "3306" : "5432");
  }

  const create = useMutation({
    mutationFn: async () => {
      // One Secret per Migration holding both endpoint passwords.
      await k8sCreate(corePaths.secrets(namespace), {
        apiVersion: "v1",
        kind: "Secret",
        metadata: { name: `${name}-creds`, namespace },
        stringData: { "src-password": srcPass, "tgt-password": tgtPass },
      } as K8sObject);
      const source: Record<string, unknown> = {
        engine: srcEngine,
        host: srcHost.trim(),
        port: Number(srcPort) || 5432,
        database: srcDb.trim(),
        username: srcUser.trim(),
        passwordSecretRef: { name: `${name}-creds`, key: "src-password" },
        ssl: srcSsl === "require",
      };
      if (srcEngine === "postgres") {
        source.schemas = srcSchemas.split(",").map((s) => s.trim()).filter(Boolean);
      }
      const spec: Record<string, unknown> = {
        mode,
        source,
        target: {
          engine: "postgres",
          host: tgtHost.trim(),
          port: Number(tgtPort) || 5432,
          database: tgtDb.trim(),
          username: tgtUser.trim(),
          passwordSecretRef: { name: `${name}-creds`, key: "tgt-password" },
          schema: tgtSchema.trim() || "public",
          ssl: tgtSsl === "require",
        },
      };
      if (tableMode === "choose" && selectedTables.size) {
        spec.tables = Array.from(selectedTables);
      }
      await k8sCreate(openinfraPaths.migrations(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "Migration",
        metadata: { name, namespace },
        spec,
      } as K8sObject);
    },
    onSuccess: () => {
      reset();
      onOpenChange(false);
    },
  });

  const sourceValid = Boolean(srcHost.trim() && srcDb.trim() && srcUser.trim() && srcPass);
  const targetValid = Boolean(tgtHost.trim() && tgtDb.trim() && tgtUser.trim() && tgtPass);

  // Discover the source's tables for the picker (connects to the source DB via the BFF).
  const discover = useQuery({
    queryKey: ["dms-discover", srcEngine, srcHost, srcPort, srcDb, srcSchemas, srcSsl],
    queryFn: () =>
      discoverTables({
        engine: srcEngine,
        host: srcHost.trim(),
        port: Number(srcPort) || 5432,
        database: srcDb.trim(),
        username: srcUser.trim(),
        password: srcPass,
        schemas:
          srcEngine === "postgres"
            ? srcSchemas.split(",").map((s) => s.trim()).filter(Boolean)
            : undefined,
        ssl: srcSsl === "require",
      }),
    enabled: open && tableMode === "choose" && sourceValid,
    retry: false,
    staleTime: 30_000,
  });

  const tablesValid = tableMode === "all" || selectedTables.size > 0;
  const taskValid =
    RFC1123.test(name) && Boolean(namespace) && Boolean(mode) && tablesValid;
  const stepValid = [sourceValid, targetValid, taskValid, true][step];

  function close(o: boolean) {
    if (create.isPending) return;
    if (!o) reset();
    onOpenChange(o);
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-[640px]">
        <DialogHeader>
          <DialogTitle>New Migration</DialogTitle>
          <DialogDescription>
            Define the source + target database endpoints and a task type, like AWS DMS. open-infra
            runs it on the headless Airbyte engine.
          </DialogDescription>
        </DialogHeader>

        {/* Stepper */}
        <div className="flex items-center gap-1 text-xs">
          {STEPS.map((s, i) => (
            <div key={s} className="flex items-center gap-1">
              <span
                className={`flex size-5 items-center justify-center rounded-full text-[10px] ${
                  i < step
                    ? "bg-primary text-primary-foreground"
                    : i === step
                      ? "bg-primary/20 text-foreground ring-1 ring-primary"
                      : "bg-muted text-muted-foreground"
                }`}
              >
                {i < step ? <Check className="size-3" /> : i + 1}
              </span>
              <span className={i === step ? "font-medium" : "text-muted-foreground"}>{s}</span>
              {i < STEPS.length - 1 && <span className="mx-1 text-muted-foreground">/</span>}
            </div>
          ))}
        </div>

        <div className="min-h-[260px] py-1">
          {step === 0 && (
            <div className="grid grid-cols-2 gap-3">
              <Field label="Engine">
                <Select value={srcEngine} onValueChange={onEngineChange}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {SOURCE_ENGINES.map((e) => (<SelectItem key={e} value={e}>{e}</SelectItem>))}
                  </SelectContent>
                </Select>
              </Field>
              <Field label="TLS">
                <Select value={srcSsl} onValueChange={setSrcSsl}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="disable">Disabled</SelectItem>
                    <SelectItem value="require">Required</SelectItem>
                  </SelectContent>
                </Select>
              </Field>
              <Field label="Host" className="col-span-2">
                <Input value={srcHost} onChange={(e) => setSrcHost(e.target.value)} placeholder="olddb.example.com" autoFocus />
              </Field>
              <Field label="Port">
                <Input value={srcPort} onChange={(e) => setSrcPort(e.target.value)} inputMode="numeric" />
              </Field>
              <Field label="Database">
                <Input value={srcDb} onChange={(e) => setSrcDb(e.target.value)} placeholder="app" />
              </Field>
              <Field label="Username">
                <Input value={srcUser} onChange={(e) => setSrcUser(e.target.value)} placeholder="migrator" />
              </Field>
              <Field label="Password">
                <Input type="password" value={srcPass} onChange={(e) => setSrcPass(e.target.value)} />
              </Field>
              {srcEngine === "postgres" && (
                <Field label="Schemas (comma-separated)" className="col-span-2">
                  <Input value={srcSchemas} onChange={(e) => setSrcSchemas(e.target.value)} placeholder="public" />
                </Field>
              )}
            </div>
          )}

          {step === 1 && (
            <div className="grid grid-cols-2 gap-3">
              <Field label="Engine">
                <Input value="postgres" disabled />
              </Field>
              <Field label="TLS">
                <Select value={tgtSsl} onValueChange={setTgtSsl}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="disable">Disabled</SelectItem>
                    <SelectItem value="require">Required</SelectItem>
                  </SelectContent>
                </Select>
              </Field>
              <Field label="Host" className="col-span-2">
                <Input value={tgtHost} onChange={(e) => setTgtHost(e.target.value)} placeholder="myapp-db-rw.myapp.svc" autoFocus />
              </Field>
              <Field label="Port">
                <Input value={tgtPort} onChange={(e) => setTgtPort(e.target.value)} inputMode="numeric" />
              </Field>
              <Field label="Database">
                <Input value={tgtDb} onChange={(e) => setTgtDb(e.target.value)} placeholder="app" />
              </Field>
              <Field label="Username">
                <Input value={tgtUser} onChange={(e) => setTgtUser(e.target.value)} placeholder="app" />
              </Field>
              <Field label="Password">
                <Input type="password" value={tgtPass} onChange={(e) => setTgtPass(e.target.value)} />
              </Field>
              <Field label="Target schema" className="col-span-2">
                <Input value={tgtSchema} onChange={(e) => setTgtSchema(e.target.value)} placeholder="public" />
              </Field>
            </div>
          )}

          {step === 2 && (
            <div className="grid grid-cols-2 gap-3">
              <Field label="Name">
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="legacy-import" autoFocus />
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
              <Field label="Task type" className="col-span-2">
                <Select value={mode} onValueChange={setMode}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {MODES.map((m) => (<SelectItem key={m.value} value={m.value}>{m.label}</SelectItem>))}
                  </SelectContent>
                </Select>
              </Field>
              <div className="col-span-2 space-y-1.5">
                <Label className="text-xs">Tables</Label>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    size="sm"
                    variant={tableMode === "all" ? "default" : "outline"}
                    onClick={() => setTableMode("all")}
                  >
                    All tables
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant={tableMode === "choose" ? "default" : "outline"}
                    onClick={() => setTableMode("choose")}
                  >
                    Choose tables
                  </Button>
                </div>
                {tableMode === "all" ? (
                  <p className="text-xs text-muted-foreground">
                    Every table in the source schema will be replicated.
                  </p>
                ) : (
                  <div className="rounded-md border">
                    {discover.isFetching && (
                      <p className="px-2 py-2 text-xs text-muted-foreground">Discovering tables…</p>
                    )}
                    {discover.isError && (
                      <p className="px-2 py-2 text-xs text-destructive">
                        {discover.error instanceof ApiError
                          ? discover.error.message
                          : "Couldn't read the source."}{" "}
                        — check the Source step.
                      </p>
                    )}
                    {discover.data && !discover.isFetching && (
                      <>
                        <div className="flex items-center gap-2 border-b px-2 py-1 text-xs">
                          <button
                            type="button"
                            className="text-primary hover:underline"
                            onClick={() => setSelectedTables(new Set(discover.data?.tables ?? []))}
                          >
                            Select all
                          </button>
                          <button
                            type="button"
                            className="text-primary hover:underline"
                            onClick={() => setSelectedTables(new Set())}
                          >
                            Clear
                          </button>
                          <span className="ml-auto text-muted-foreground">
                            {selectedTables.size}/{discover.data.tables.length}
                          </span>
                        </div>
                        <div className="max-h-40 overflow-auto">
                          {discover.data.tables.map((t) => {
                            const on = selectedTables.has(t);
                            return (
                              <button
                                type="button"
                                key={t}
                                onClick={() =>
                                  setSelectedTables((prev) => {
                                    const n = new Set(prev);
                                    if (n.has(t)) n.delete(t);
                                    else n.add(t);
                                    return n;
                                  })
                                }
                                className="flex w-full items-center gap-2 px-2 py-1 text-left text-sm hover:bg-muted"
                              >
                                <span
                                  className={`flex size-4 shrink-0 items-center justify-center rounded border ${
                                    on
                                      ? "border-primary bg-primary text-primary-foreground"
                                      : "border-input"
                                  }`}
                                >
                                  {on && <Check className="size-3" />}
                                </span>
                                {t}
                              </button>
                            );
                          })}
                          {discover.data.tables.length === 0 && (
                            <p className="px-2 py-2 text-xs text-muted-foreground">
                              No tables found in the source.
                            </p>
                          )}
                        </div>
                      </>
                    )}
                  </div>
                )}
              </div>
              {(mode === "cdc" || mode === "full-load-and-cdc") && (
                <p className="col-span-2 text-xs text-muted-foreground">
                  CDC requires a CDC-ready source — Postgres: <code>wal_level=logical</code> + a replication
                  slot/publication; MySQL: <code>binlog_format=ROW</code>.
                </p>
              )}
            </div>
          )}

          {step === 3 && (
            <div className="space-y-2 text-sm">
              <Row k="Name" v={`${name} (${namespace})`} />
              <Row k="Task type" v={mode} />
              <Row
                k="Source"
                v={`${srcEngine} · ${srcUser}@${srcHost}:${srcPort}/${srcDb}${srcEngine === "postgres" ? ` · schemas ${srcSchemas}` : ""}`}
              />
              <Row k="Target" v={`postgres · ${tgtUser}@${tgtHost}:${tgtPort}/${tgtDb} · schema ${tgtSchema}`} />
              <Row
                k="Tables"
                v={
                  tableMode === "all"
                    ? "All tables"
                    : Array.from(selectedTables).join(", ") || "(none selected)"
                }
              />
              <p className="pt-1 text-xs text-muted-foreground">
                Creates a Secret <code>{name}-creds</code> with the endpoint passwords and the Migration that
                references it.
              </p>
            </div>
          )}
        </div>

        {create.error ? (
          <p className="text-sm text-destructive">
            {create.error instanceof ApiError ? create.error.message : "Failed to create the migration."}
          </p>
        ) : null}

        <DialogFooter className="sm:justify-between">
          <Button
            variant="outline"
            onClick={() => (step === 0 ? close(false) : setStep(step - 1))}
            disabled={create.isPending}
          >
            {step === 0 ? "Cancel" : "Back"}
          </Button>
          {step < STEPS.length - 1 ? (
            <Button onClick={() => setStep(step + 1)} disabled={!stepValid}>
              Next
            </Button>
          ) : (
            <Button onClick={() => create.mutate()} disabled={create.isPending || !taskValid}>
              {create.isPending ? "Creating…" : "Create migration"}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Field({
  label,
  children,
  className,
}: {
  label: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`space-y-1.5 ${className ?? ""}`}>
      <Label className="text-xs">{label}</Label>
      {children}
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex gap-2">
      <span className="w-24 shrink-0 text-muted-foreground">{k}</span>
      <span className="min-w-0 break-words font-medium">{v}</span>
    </div>
  );
}
