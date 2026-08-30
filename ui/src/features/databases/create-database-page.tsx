import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Database } from "lucide-react";
import { CreateShell } from "@/components/create/create-shell";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { k8sCreate } from "@/lib/api";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { useK8sWatch, watchQueryKey } from "@/hooks/use-k8s-watch";
import { useNamespace } from "@/lib/namespace-context";
import { OPENINFRA_GROUP, OPENINFRA_VERSION, type K8sObject } from "@/types/k8s";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/**
 * Single-page create for a managed database (issue #96) — a *data-only* Application (no image) the
 * platform compiles into just the database. Same knobs as the old dialog: name, engine, HA, LAN access.
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
  const [ha, setHa] = useState(false);
  const [expose, setExpose] = useState(false);
  const [touched, setTouched] = useState(false);

  const create = useMutation({
    mutationFn: () =>
      k8sCreate<K8sObject>(openinfraPaths.applications(namespace), {
        apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
        kind: "Application",
        metadata: { name, namespace },
        spec: { database: { engine, name, highAvailability: ha, expose } },
      } as K8sObject),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: watchQueryKey(openinfraPaths.applications()) });
      navigate({ to: "/databases" });
    },
  });

  const nameOk = RFC1123.test(name);
  const submit = () => {
    setTouched(true);
    if (!nameOk) return;
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
          <div className="space-y-1.5">
            <Label>LAN access</Label>
            <label className="flex h-9 items-center gap-2 text-sm">
              <input type="checkbox" checked={expose} onChange={(e) => setExpose(e.target.checked)} className="size-4 accent-primary" />
              <span className="text-muted-foreground">Expose on a LAN IP (MetalLB) for workstation access</span>
            </label>
          </div>
        </div>
      </div>
    </CreateShell>
  );
}
