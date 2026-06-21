import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Monitor, Rocket } from "lucide-react";
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
import { ApiError, k8sCreate, k8sList } from "@/lib/api";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { watchQueryKey } from "@/hooks/use-k8s-watch";
import {
  OPENINFRA_GROUP,
  OPENINFRA_VERSION,
  type K8sObject,
} from "@/types/k8s";
import { OS_CATALOG, osFamily } from "./vm-shared";

const RFC1123 = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

/**
 * Provision a VM without writing YAML: name, OS (from the catalog), size, an SSH
 * key (Linux) and optional LAN exposure. Creates a kind: VirtualMachine claim.
 */
export function NewVmDialog({
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
  const [os, setOs] = useState("ubuntu-24.04");
  const [cpu, setCpu] = useState("2");
  const [memory, setMemory] = useState("2Gi");
  const [diskSize, setDiskSize] = useState("20Gi");
  const [sshKey, setSshKey] = useState("");
  const [expose, setExpose] = useState(false);
  const [network, setNetwork] = useState("masquerade");
  const [touched, setTouched] = useState(false);

  const isWindows = osFamily(os) === "windows";

  // Bridge mode only works once an operator has enabled it (Multus + a node
  // labelled openinfra.dev/vm-lan=true). Without that, a bridge VM can't schedule,
  // so gate the option instead of letting it hang.
  const nodesQuery = useQuery({
    queryKey: ["nodes-vmlan"],
    queryFn: () => k8sList<K8sObject>(corePaths.nodes()),
    enabled: open,
    staleTime: 60_000,
  });
  const bridgeReady = (nodesQuery.data?.items ?? []).some(
    (n) => n.metadata?.labels?.["openinfra.dev/vm-lan"] === "true",
  );

  function reset() {
    setName("");
    setOs("ubuntu-24.04");
    setCpu("2");
    setMemory("2Gi");
    setDiskSize("20Gi");
    setSshKey("");
    setExpose(false);
    setNetwork("masquerade");
    setTouched(false);
    createMutation.reset();
  }

  const createMutation = useMutation({
    mutationFn: (manifest: K8sObject) =>
      k8sCreate<K8sObject>(openinfraPaths.virtualmachines(namespace), manifest),
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
      kind: "VirtualMachine",
      metadata: { name, namespace },
      spec: {
        os,
        cpu: Number(cpu) || 2,
        memory: memory || "2Gi",
        diskSize: diskSize || "20Gi",
        ...(sshKey.trim() && !isWindows ? { sshKey: sshKey.trim() } : {}),
        expose,
        // Never submit bridge unless it's actually enabled (option is also gated).
        network: bridgeReady ? network : "masquerade",
      },
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
            <Monitor className="size-5 text-primary" />
            New Virtual Machine
          </DialogTitle>
          <DialogDescription>
            A real VM with a persistent disk — no YAML needed.
          </DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="vm-name">Name</Label>
            <Input
              id="vm-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onBlur={() => setTouched(true)}
              placeholder="dev-box"
              autoFocus
            />
            {nameError ? (
              <p className="text-xs text-destructive">{nameError}</p>
            ) : null}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="vm-ns">Namespace</Label>
            <Select value={namespace} onValueChange={setNamespace}>
              <SelectTrigger id="vm-ns">
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
          <div className="space-y-1.5 sm:col-span-2">
            <Label htmlFor="vm-os">Operating system</Label>
            <Select value={os} onValueChange={setOs}>
              <SelectTrigger id="vm-os">
                <SelectValue placeholder="OS" />
              </SelectTrigger>
              <SelectContent>
                {OS_CATALOG.map((o) => (
                  <SelectItem key={o.value} value={o.value}>
                    {o.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="vm-cpu">vCPU</Label>
            <Input
              id="vm-cpu"
              type="number"
              min={1}
              value={cpu}
              onChange={(e) => setCpu(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="vm-mem">Memory</Label>
            <Input
              id="vm-mem"
              value={memory}
              onChange={(e) => setMemory(e.target.value)}
              placeholder="2Gi"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="vm-disk">Disk size</Label>
            <Input
              id="vm-disk"
              value={diskSize}
              onChange={(e) => setDiskSize(e.target.value)}
              placeholder="20Gi"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="vm-net">Network</Label>
            <Select value={network} onValueChange={setNetwork}>
              <SelectTrigger id="vm-net">
                <SelectValue placeholder="Network" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="masquerade">Pod NAT (default)</SelectItem>
                <SelectItem value="bridge" disabled={!bridgeReady}>
                  Bridged to LAN (direct IP){!bridgeReady ? " — not enabled" : ""}
                </SelectItem>
              </SelectContent>
            </Select>
            {!bridgeReady ? (
              <p className="text-xs text-muted-foreground">
                Needs enabling: <code>scripts/enable-vm-lan.sh</code> + a node
                labelled <code>openinfra.dev/vm-lan</code>.
              </p>
            ) : null}
          </div>
          <div className="space-y-1.5">
            <Label>LAN access</Label>
            <label className="flex h-9 items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={expose}
                disabled={network === "bridge"}
                onChange={(e) => setExpose(e.target.checked)}
                className="size-4 accent-primary disabled:opacity-50"
              />
              <span className="text-muted-foreground">
                {network === "bridge"
                  ? "already on the LAN (bridged)"
                  : `${isWindows ? "RDP (3389)" : "SSH (22)"} on a LAN IP`}
              </span>
            </label>
          </div>
          {isWindows ? (
            <div className="sm:col-span-2 rounded-md border border-warning/40 bg-warning/10 p-3 text-xs text-muted-foreground">
              Windows clones a golden image you build once from an eval ISO (see
              docs). Login is <span className="font-medium">Administrator</span> +
              a generated password (revealable on the VM page); connect with{" "}
              <code>mstsc</code> over RDP.
            </div>
          ) : (
            <div className="space-y-1.5 sm:col-span-2">
              <Label htmlFor="vm-ssh">SSH public key</Label>
              <Input
                id="vm-ssh"
                value={sshKey}
                onChange={(e) => setSshKey(e.target.value)}
                placeholder="ssh-ed25519 AAAA… (optional — else use the generated password)"
              />
            </div>
          )}
        </div>

        {createMutation.error ? (
          <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
            {createMutation.error instanceof ApiError
              ? createMutation.error.message
              : "Failed to create the VM."}
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
            Create VM
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
