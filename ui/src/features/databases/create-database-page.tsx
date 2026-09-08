import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Database } from "lucide-react";
import { CreateShell } from "@/components/create/create-shell";
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { k8sCreate, getEncryptionKeys } from "@/lib/api";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { useK8sWatch, watchQueryKey } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { OPENINFRA_GROUP, OPENINFRA_VERSION, type K8sObject } from "@/types/k8s";
import { RDS_INSTANCE_CLASS_GROUPS, RDS_INSTANCE_CLASSES, formatRdsInstanceClass } from "@/lib/rds-instance-classes";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

// Sentinel for "let the engine operator pick" — omits cpu/memory from the submitted spec so the
// XRD honors each engine's default sizing (RDS makes you pick a class; open-infra also allows none).
const DEFAULT_CLASS = "default";

// Per-engine storage default, from the Application XRD's spec.database.size description. Shown as
// the storage input's placeholder so an empty field reads as "engine default", not "0".
function engineDefaultStorageGiB(engine: string): number {
  return engine === "babelfish" ? 10 : 5;
}

/**
 * Single-page create for a managed database (issue #96) — a *data-only* Application (no image) the
 * platform compiles into just the database. Mirrors AWS RDS create: engine, DB instance class
 * (sizing) and allocated storage, plus HA, LAN access and (postgres) storage encryption (#111/#114).
 */
export function CreateDatabasePage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { scoped } = useNamespace();
  const nsWatch = useK8sWatch<K8sObject>(corePaths.namespaces());
  const namespaces = useMemo(
    () => nsWatch.items.map((n) => n.metadata.name).filter(Boolean).sort() as string[],
    [nsWatch.items],
  );

  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState(scoped ?? "default");
  const [engine, setEngine] = useState("postgres");
  const [instanceClass, setInstanceClass] = useState(DEFAULT_CLASS);
  const [storage, setStorage] = useState("");
  const [ha, setHa] = useState(false);
  const [expose, setExpose] = useState(false);
  const [storageEncrypted, setStorageEncrypted] = useState(false);
  const [encryptionKey, setEncryptionKey] = useState("");
  const [touched, setTouched] = useState(false);

  // Encryption keys are customer kind: EncryptionKey (Vault Transit) — cluster-scoped, listed by the
  // BFF. Only needed for the postgres-only encryption path, but the query is cheap and cached.
  const keysQ = useQuery({ queryKey: ["encryption-keys"], queryFn: getEncryptionKeys });
  const encryptionKeys = keysQ.data ?? [];

  const encryptionEligible = engine === "postgres";
  const encOn = encryptionEligible && storageEncrypted;

  const storageNum = storage.trim() === "" ? null : Number(storage);
  const storageOk = storageNum === null || (Number.isFinite(storageNum) && storageNum >= 1);

  const create = useMutation({
    mutationFn: () => {
      const db: Record<string, unknown> = { engine, name, highAvailability: ha, expose };
      // Instance class -> cpu/memory. Omit both when "default" so engine defaults apply (don't send
      // empty strings that would override the operator default).
      if (instanceClass !== DEFAULT_CLASS) {
        const cls = RDS_INSTANCE_CLASSES[instanceClass];
        if (cls) {
          db.cpu = cls.cpu;
          db.memory = cls.memory;
        }
      }
      // Allocated storage -> spec.database.size (GiB). Omit when empty so the engine default applies.
      if (storageNum !== null) db.size = `${storageNum}Gi`;
      // Storage encryption (postgres only per the XRD). Omit entirely otherwise.
      if (encOn) {
        db.storageEncrypted = true;
        if (encryptionKey) db.encryptionKey = encryptionKey;
      }
      return k8sCreate<K8sObject>(openinfraPaths.applications(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "Application",
        metadata: { name, namespace },
        spec: { database: db },
      } as K8sObject);
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: watchQueryKey(openinfraPaths.applications()) });
      navigate({ to: "/databases" });
    },
  });

  const nameOk = RFC1123.test(name);
  const encKeyMissing = encOn && !encryptionKey;
  const canSubmit = nameOk && storageOk && !encKeyMissing;
  const submit = () => {
    setTouched(true);
    if (!canSubmit) return;
    create.mutate();
  };

  return (
    <CreateShell
      icon={<Database className="size-6 text-primary" />}
      title="Create Database"
      description="Provisions a managed database directly — no Application YAML needed. It is compiled into a data-only Application (just the database, no workload)."
      onCancel={() => navigate({ to: "/databases" })}
      onSubmit={submit}
      submitLabel="Create Database"
      pending={create.isPending}
      error={create.error}
      dirty={name.length > 0}
    >
      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">Database</h3>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="db-name">Name</Label>
            <Input id="db-name" value={name} onChange={(e) => setName(e.target.value)} onBlur={() => setTouched(true)} placeholder="my-db" autoFocus />
            {touched && !nameOk ? <p className="text-xs text-destructive">Lowercase letters, numbers and hyphens; must start/end alphanumeric.</p> : null}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="db-ns">Namespace</Label>
            <Select value={namespace} onValueChange={setNamespace}>
              <SelectTrigger id="db-ns"><SelectValue placeholder="Namespace" /></SelectTrigger>
              <SelectContent>
                {(namespaces.length ? namespaces : [namespace]).map((ns) => (
                  <SelectItem key={ns} value={ns}>{ns}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="db-engine">Engine</Label>
            <Select value={engine} onValueChange={setEngine}>
              <SelectTrigger id="db-engine"><SelectValue placeholder="Engine" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="postgres">PostgreSQL (relational)</SelectItem>
                <SelectItem value="mysql">MySQL / MariaDB (relational)</SelectItem>
                <SelectItem value="mongo">MongoDB / FerretDB (document)</SelectItem>
                <SelectItem value="babelfish">SQL Server–compatible · Babelfish (experimental)</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label>High availability</Label>
            <label className="flex h-9 items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={ha && engine !== "babelfish"}
                disabled={engine === "babelfish"}
                onChange={(e) => setHa(e.target.checked)}
                className="size-4 accent-primary disabled:opacity-50"
              />
              <span className="text-muted-foreground">
                {engine === "babelfish"
                  ? "Single instance (experimental — no HA yet)"
                  : engine === "mongo"
                    ? "2 FerretDB replicas (proxy tier)"
                    : engine === "mysql"
                      ? "Galera 3-node cluster (synchronous)"
                      : "Primary + standby, auto-failover"}
              </span>
            </label>
          </div>
        </div>
      </div>

      <div className="space-y-4 rounded-lg border border-border p-4">
        <div>
          <h3 className="text-sm font-semibold">Instance sizing</h3>
          <p className="text-xs text-muted-foreground">
            Pick a DB instance class (vCPU/RAM) and allocated storage, like AWS RDS. Sizing maps to
            dedicated CPU/memory requests — burst credits, EBS-optimized throughput and Aurora storage
            are not modeled.
          </p>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="db-class">DB instance class</Label>
            <Select value={instanceClass} onValueChange={setInstanceClass}>
              <SelectTrigger id="db-class"><SelectValue placeholder="Instance class" /></SelectTrigger>
              <SelectContent>
                <SelectItem value={DEFAULT_CLASS}>Default (engine default sizing)</SelectItem>
                {RDS_INSTANCE_CLASS_GROUPS.map((g) => (
                  <SelectGroup key={g.label}>
                    <SelectLabel>{g.label}</SelectLabel>
                    {g.classes.map((c) => (
                      <SelectItem key={c.id} value={c.id}>{formatRdsInstanceClass(c)}</SelectItem>
                    ))}
                  </SelectGroup>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              {instanceClass === DEFAULT_CLASS
                ? "cpu/memory left unset — the engine operator's default sizing applies."
                : `Requests ${RDS_INSTANCE_CLASSES[instanceClass]?.cpu} vCPU / ${RDS_INSTANCE_CLASSES[instanceClass]?.memory} of memory.`}
            </p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="db-storage">Allocated storage (GiB)</Label>
            <Input
              id="db-storage"
              type="number"
              min={1}
              step={1}
              value={storage}
              onChange={(e) => setStorage(e.target.value)}
              placeholder={`${engineDefaultStorageGiB(engine)} (engine default)`}
            />
            {touched && !storageOk ? (
              <p className="text-xs text-destructive">Enter a whole number of GiB (1 or more), or leave empty for the engine default.</p>
            ) : (
              <p className="text-xs text-muted-foreground">
                Empty = engine default ({engine === "babelfish" ? "10" : "5"} GiB). Maps to the data volume size.
              </p>
            )}
          </div>
        </div>
      </div>

      <details className="rounded-lg border border-border p-4 [&_summary]:cursor-pointer">
        <summary className="text-sm font-semibold">Storage encryption (advanced)</summary>
        <div className="mt-4 space-y-3">
          {!encryptionEligible ? (
            <p className="text-xs text-muted-foreground">
              At-rest storage encryption is available for the PostgreSQL engine only (v1, CloudNativePG).
              The {engine} engine ignores it — switch the engine to PostgreSQL to enable.
            </p>
          ) : (
            <>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={storageEncrypted}
                  onChange={(e) => setStorageEncrypted(e.target.checked)}
                  className="size-4 accent-primary"
                />
                <span className="text-muted-foreground">
                  Encrypt storage at rest with LUKS, keyed by a customer kind: EncryptionKey. Requires the
                  opt-in encryption component. Destroying the key crypto-erases the data.
                </span>
              </label>
              {storageEncrypted ? (
                <div className="space-y-1.5">
                  <Label htmlFor="db-enckey">Encryption key</Label>
                  {keysQ.isLoading ? (
                    <p className="text-xs text-muted-foreground">Loading encryption keys…</p>
                  ) : encryptionKeys.length === 0 ? (
                    <p className="text-xs text-destructive">
                      No kind: EncryptionKey found. Create one first (Encryption Keys page / GitOps) — see
                      docs/encryption.md — then return here.
                    </p>
                  ) : (
                    <>
                      <Select value={encryptionKey} onValueChange={setEncryptionKey}>
                        <SelectTrigger id="db-enckey"><SelectValue placeholder="Select an encryption key" /></SelectTrigger>
                        <SelectContent>
                          {encryptionKeys.map((k) => (
                            <SelectItem key={k.name} value={k.name} disabled={!k.provisioned}>
                              {k.name}{k.provisioned ? "" : " (not provisioned)"}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      {encKeyMissing && touched ? (
                        <p className="text-xs text-destructive">Select an encryption key, or turn off storage encryption.</p>
                      ) : null}
                    </>
                  )}
                </div>
              ) : null}
            </>
          )}
        </div>
      </details>

      <div className="space-y-4 rounded-lg border border-border p-4">
        <h3 className="text-sm font-semibold">Connectivity</h3>
        <div className="space-y-1.5">
          <Label>LAN access</Label>
          <label className="flex h-9 items-center gap-2 text-sm">
            <input type="checkbox" checked={expose} onChange={(e) => setExpose(e.target.checked)} className="size-4 accent-primary" />
            <span className="text-muted-foreground">Expose on a LAN IP (MetalLB) for workstation access</span>
          </label>
        </div>
      </div>
    </CreateShell>
  );
}
