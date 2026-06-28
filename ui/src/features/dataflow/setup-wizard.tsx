import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { Plus, Trash2, Database, Sprout, GitMerge, ArrowLeftRight, Info } from "lucide-react";
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
import { ApiError, k8sCreate } from "@/lib/api";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { OPENINFRA_GROUP, OPENINFRA_VERSION } from "@/types/k8s";
import type { K8sObject } from "@/types/k8s";

const ENGINES = ["postgres", "mysql", "mariadb", "sqlserver"];
const ENGINE_LABEL: Record<string, string> = { postgres: "PostgreSQL", mysql: "MySQL", mariadb: "MariaDB", sqlserver: "SQL Server" };
const PORTS: Record<string, string> = { postgres: "5432", mysql: "3306", mariadb: "3306", sqlserver: "1433" };
const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

interface DbEntry {
  id: string;
  engine: string;
  host: string;
  port: string;
  db: string;
  user: string;
  pass: string;
  hasData: boolean; // already contains the tables/rows?
}
const emptyDb = (id: string): DbEntry => ({
  id,
  engine: "postgres",
  host: "",
  port: "5432",
  db: "app",
  user: "postgres",
  pass: "",
  hasData: false,
});

export function SetupWizard({
  open,
  onOpenChange,
  defaultNs,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  defaultNs?: string;
}) {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState(defaultNs ?? "default");
  const [tables, setTables] = useState("");
  const [dbs, setDbs] = useState<DbEntry[]>([emptyDb("east"), emptyDb("west")]);

  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = nsWatch.items
    .map((n) => n.metadata.name)
    .filter((n): n is string => Boolean(n))
    .sort((x, y) => x.localeCompare(y));

  function patch(i: number, p: Partial<DbEntry>) {
    setDbs((ds) => ds.map((d, j) => (j === i ? { ...d, ...p } : d)));
  }
  function addDb() {
    setDbs((ds) => [...ds, emptyDb(`db${ds.length + 1}`)]);
  }
  function removeDb(i: number) {
    setDbs((ds) => ds.filter((_, j) => j !== i));
  }

  // ── the plan: one seed (a db with data) syncs with every other db ──────────
  const seed = dbs.find((d) => d.hasData);
  const targets = dbs.filter((d) => d.id !== seed?.id);
  const tableList = tables.split(",").map((t) => t.trim()).filter(Boolean);

  const dbValid = (d: DbEntry) =>
    RFC1123.test(d.id) && Boolean(d.host.trim() && d.db.trim() && d.user.trim() && d.pass);
  const ids = dbs.map((d) => d.id);
  const step1Valid =
    RFC1123.test(name) &&
    Boolean(namespace) &&
    dbs.length >= 2 &&
    dbs.every(dbValid) &&
    new Set(ids).size === ids.length &&
    tableList.length > 0 &&
    Boolean(seed); // at least one db must already hold the data

  const deploy = useMutation({
    mutationFn: async () => {
      if (!seed) throw new Error("At least one database must already contain the data.");
      const stringData: Record<string, string> = {};
      for (const d of dbs) stringData[`${d.id}-password`] = d.pass;
      await k8sCreate(corePaths.secrets(namespace), {
        apiVersion: "v1",
        kind: "Secret",
        metadata: { name: `${name}-creds`, namespace },
        stringData,
      });
      const nodeOf = (d: DbEntry, x: number, y: number) => ({
        name: d.id,
        engine: d.engine,
        host: d.host.trim(),
        port: Number(d.port) || 5432,
        database: d.db.trim(),
        username: d.user.trim(),
        passwordSecretRef: { name: `${name}-creds`, key: `${d.id}-password` },
        schema: d.engine === "sqlserver" ? "dbo" : "public",
        x,
        y,
      });
      const nodes = [
        nodeOf(seed, 120, 200),
        ...targets.map((d, i) => nodeOf(d, 520, 80 + i * 140)),
      ];
      // star topology: every other db links to the seed; empty ones get bootstrapped
      const edges = targets.map((d) => ({
        from: seed.id,
        to: d.id,
        type: "replication",
        ...(d.hasData ? {} : { bootstrap: true }),
      }));
      await k8sCreate(openinfraPaths.dataflows(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "DataFlow",
        metadata: { name, namespace },
        spec: { nodes, edges, tables: tableList },
      });
    },
    onSuccess: () => {
      onOpenChange(false);
      navigate({ to: "/dataflows/$namespace/$name", params: { namespace, name } });
    },
  });

  return (
    <Dialog open={open} onOpenChange={(o) => !deploy.isPending && onOpenChange(o)}>
      <DialogContent className="sm:max-w-[720px]">
        <DialogHeader>
          <DialogTitle>Set up replication</DialogTitle>
          <DialogDescription>
            Keep any number of databases in sync. Add each one and tell us whether it already has the
            data — we'll figure out the rest and show you exactly what will happen.
          </DialogDescription>
        </DialogHeader>

        {step === 1 ? (
          <div className="grid max-h-[60vh] gap-3 overflow-y-auto pr-1">
            <div className="grid grid-cols-3 gap-2">
              <div className="space-y-1">
                <Label className="text-xs">Name</Label>
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="customers-sync" />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Namespace</Label>
                <Select value={namespace} onValueChange={setNamespace}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {namespaces.map((ns) => <SelectItem key={ns} value={ns}>{ns}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Tables to sync</Label>
                <Input value={tables} onChange={(e) => setTables(e.target.value)} placeholder="customers, orders" />
              </div>
            </div>

            {dbs.map((d, i) => (
              <div key={i} className="space-y-2 rounded-md border p-3">
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-1.5 text-sm font-medium">
                    <Database className="size-4 text-muted-foreground" /> Database {i + 1}
                  </span>
                  {dbs.length > 2 ? (
                    <Button size="sm" variant="ghost" onClick={() => removeDb(i)}><Trash2 className="size-3.5" /></Button>
                  ) : null}
                </div>
                <div className="grid grid-cols-3 gap-2">
                  <Field label="Name / id"><Input value={d.id} onChange={(e) => patch(i, { id: e.target.value })} /></Field>
                  <Field label="Engine">
                    <Select value={d.engine} onValueChange={(v) => patch(i, { engine: v, port: PORTS[v] ?? "5432" })}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>{ENGINES.map((e) => <SelectItem key={e} value={e}>{ENGINE_LABEL[e]}</SelectItem>)}</SelectContent>
                    </Select>
                  </Field>
                  <Field label="Host"><Input value={d.host} onChange={(e) => patch(i, { host: e.target.value })} placeholder="pg.ns.svc" /></Field>
                  <Field label="Port"><Input value={d.port} onChange={(e) => patch(i, { port: e.target.value })} /></Field>
                  <Field label="Database"><Input value={d.db} onChange={(e) => patch(i, { db: e.target.value })} /></Field>
                  <Field label="Username"><Input value={d.user} onChange={(e) => patch(i, { user: e.target.value })} /></Field>
                  <Field label="Password"><Input type="password" value={d.pass} onChange={(e) => patch(i, { pass: e.target.value })} /></Field>
                  <div className="col-span-2 space-y-1">
                    <Label className="text-xs">Current state</Label>
                    <Select value={d.hasData ? "data" : "empty"} onValueChange={(v) => patch(i, { hasData: v === "data" })}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="data">Already has the data</SelectItem>
                        <SelectItem value="empty">Empty — set it up for me</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </div>
            ))}
            <Button variant="outline" onClick={addDb} className="justify-self-start">
              <Plus className="size-4" /> Add another database
            </Button>
            {!seed && dbs.length >= 2 ? (
              <p className="flex items-center gap-1.5 text-sm text-amber-600">
                <Info className="size-4" /> At least one database must already contain the data to copy from.
              </p>
            ) : null}
          </div>
        ) : (
          <PlanStep
            seed={seed}
            targets={targets}
            tableList={tableList}
            error={deploy.isError ? (deploy.error instanceof ApiError ? deploy.error.message : "Failed to deploy.") : null}
          />
        )}

        <DialogFooter>
          {step === 2 ? (
            <Button variant="ghost" onClick={() => setStep(1)} disabled={deploy.isPending}>Back</Button>
          ) : (
            <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
          )}
          {step === 1 ? (
            <Button onClick={() => setStep(2)} disabled={!step1Valid}>Review the plan</Button>
          ) : (
            <Button onClick={() => deploy.mutate()} disabled={deploy.isPending}>
              {deploy.isPending ? "Deploying…" : "Deploy & sync"}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function PlanStep({
  seed,
  targets,
  tableList,
  error,
}: {
  seed?: DbEntry;
  targets: DbEntry[];
  tableList: string[];
  error: string | null;
}) {
  const empties = targets.filter((d) => !d.hasData);
  const merges = targets.filter((d) => d.hasData);
  return (
    <div className="grid max-h-[60vh] gap-3 overflow-y-auto pr-1 text-sm">
      <p className="text-muted-foreground">
        Here's what will happen when you deploy. <strong>{seed?.id}</strong> already has the data, so
        it's the source of truth everything else is brought in line with.
      </p>

      <div className="space-y-2">
        {empties.map((d) => (
          <PlanLine key={d.id} icon={<Sprout className="size-4 text-emerald-600" />}>
            <strong>{d.id}</strong> is empty — we'll <strong>create its tables and copy the data</strong>{" "}
            from <strong>{seed?.id}</strong>, then keep the two in sync both ways.
          </PlanLine>
        ))}
        {merges.map((d) => (
          <PlanLine key={d.id} icon={<GitMerge className="size-4 text-amber-600" />}>
            <strong>{d.id}</strong> already has data — we'll <strong>merge</strong> it with{" "}
            <strong>{seed?.id}</strong>. If the same record was changed in both, the{" "}
            <strong>most recent change wins</strong> (last-write-wins).
          </PlanLine>
        ))}
        <PlanLine icon={<ArrowLeftRight className="size-4 text-sky-600" />}>
          From then on, a change to <strong>any</strong> database is copied to the others — for{" "}
          {tableList.length === 1 ? "the table " : "the tables "}
          <code>{tableList.join(", ")}</code>. Loops are prevented automatically.
        </PlanLine>
      </div>

      <div className="rounded-md border bg-muted/40 p-3 text-xs text-muted-foreground">
        <div className="mb-1 font-medium text-foreground">Before you deploy, each database needs:</div>
        <ul className="list-inside list-disc space-y-0.5">
          <li>Change-data-capture enabled — Postgres <code>wal_level=logical</code>, MySQL binlog (ROW), SQL Server CDC + Agent.</li>
          <li>A primary key on every table being synced.</li>
        </ul>
      </div>

      {error ? <p className="text-destructive">{error}</p> : null}
    </div>
  );
}

function PlanLine({ icon, children }: { icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2 rounded-md border p-2.5">
      <span className="mt-0.5 shrink-0">{icon}</span>
      <span>{children}</span>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <Label className="text-xs">{label}</Label>
      {children}
    </div>
  );
}
