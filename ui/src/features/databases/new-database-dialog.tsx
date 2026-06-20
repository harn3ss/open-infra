import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Database, Rocket } from "lucide-react";
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
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/common/states";
import { ApiError, k8sCreate } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import { watchQueryKey } from "@/hooks/use-k8s-watch";
import {
  OPENINFRA_GROUP,
  OPENINFRA_VERSION,
  type K8sObject,
} from "@/types/k8s";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/**
 * Hand-roll a database without writing an Application YAML: pick a name, engine
 * (postgres / mongo) and HA. Creates a *data-only* Application (no image), which
 * the platform compiles into just the database.
 */
export function NewDatabaseDialog({
  open,
  onOpenChange,
  namespaces,
  defaultNamespace,
  listPath,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  namespaces: string[];
  defaultNamespace?: string;
  listPath: string;
}) {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState(defaultNamespace ?? "default");
  const [engine, setEngine] = useState("postgres");
  const [ha, setHa] = useState(false);
  const [touched, setTouched] = useState(false);

  function reset() {
    setName("");
    setEngine("postgres");
    setHa(false);
    setTouched(false);
    createMutation.reset();
  }

  const createMutation = useMutation({
    mutationFn: (manifest: K8sObject) =>
      k8sCreate<K8sObject>(openinfraPaths.applications(namespace), manifest),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: watchQueryKey(listPath) });
      reset();
      onOpenChange(false);
    },
  });

  const nameError =
    touched && !RFC1123.test(name)
      ? "Lowercase letters, numbers and hyphens; must start/end alphanumeric."
      : null;

  const submit = () => {
    if (!RFC1123.test(name)) {
      setTouched(true);
      return;
    }
    createMutation.mutate({
      apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
      kind: "Application",
      metadata: { name, namespace },
      // Data-only Application: just a database, no workload.
      spec: { database: { engine, name, highAvailability: ha } },
    } as K8sObject);
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (createMutation.isPending) return;
        if (!o) reset();
        onOpenChange(o);
      }}
    >
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Database className="size-5 text-primary" />
            New Database
          </DialogTitle>
          <DialogDescription>
            Provisions a managed database directly — no Application YAML needed.
          </DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="db-name">Name</Label>
            <Input
              id="db-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onBlur={() => setTouched(true)}
              placeholder="my-db"
              autoFocus
            />
            {nameError ? (
              <p className="text-xs text-destructive">{nameError}</p>
            ) : null}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="db-ns">Namespace</Label>
            <Select value={namespace} onValueChange={setNamespace}>
              <SelectTrigger id="db-ns">
                <SelectValue placeholder="Namespace" />
              </SelectTrigger>
              <SelectContent>
                {(namespaces.length ? namespaces : [namespace]).map((ns) => (
                  <SelectItem key={ns} value={ns}>
                    {ns}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="db-engine">Engine</Label>
            <Select value={engine} onValueChange={setEngine}>
              <SelectTrigger id="db-engine">
                <SelectValue placeholder="Engine" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="postgres">PostgreSQL (relational)</SelectItem>
                <SelectItem value="mysql">MySQL / MariaDB (relational)</SelectItem>
                <SelectItem value="mongo">MongoDB / FerretDB (document)</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label>High availability</Label>
            <label className="flex h-9 items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={ha}
                onChange={(e) => setHa(e.target.checked)}
                className="size-4 accent-primary"
              />
              <span className="text-muted-foreground">
                {engine === "mongo"
                  ? "2 FerretDB replicas (proxy tier)"
                  : engine === "mysql"
                    ? "not yet supported for MySQL (single instance)"
                    : "Primary + standby, auto-failover"}
              </span>
            </label>
          </div>
        </div>

        {createMutation.error ? (
          <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
            {createMutation.error instanceof ApiError
              ? createMutation.error.message
              : "Failed to create the database."}
          </div>
        ) : null}

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={createMutation.isPending}
          >
            Cancel
          </Button>
          <Button
            onClick={submit}
            disabled={createMutation.isPending || !RFC1123.test(name)}
          >
            {createMutation.isPending ? (
              <Spinner className="text-current" />
            ) : (
              <Rocket className="size-4" />
            )}
            Create Database
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
