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
import { SecurityGroupPicker } from "@/components/common/security-group-picker";
import { ApiError, k8sCreate, k8sList } from "@/lib/api";
import { corePaths, openinfraPaths } from "@/lib/k8s-paths";
import { watchQueryKey } from "@/hooks/use-k8s-watch";
import {
  OPENINFRA_GROUP,
  OPENINFRA_VERSION,
  type K8sObject,
} from "@/types/k8s";
import { IMAGES_NAMESPACE, OS_CATALOG, osFamily } from "./vm-shared";

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
  // One cohesive reachability choice (maps to network + expose at submit):
  //   internal = pod network only · lan = MetalLB LAN IP · bridge = direct DHCP
  const [access, setAccess] = useState("internal");
  const [securityGroups, setSecurityGroups] = useState<string[]>([]);
  // Launch-wizard firewall: by default open the OS access port (SSH 22 / RDP 3389),
  // like AWS. Creates a "<name>-access" SecurityGroup attached to the VM.
  const [allowAccess, setAllowAccess] = useState(true);
  const [accessSource, setAccessSource] = useState("anywhere"); // anywhere | cidr
  const [accessCidr, setAccessCidr] = useState("");
  const [allowHttp, setAllowHttp] = useState(false);
  const [allowHttps, setAllowHttps] = useState(false);
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

  // Windows versions are only selectable once their golden image is built (the
  // <os>-golden PVC exists). Build them on the VM Images page.
  const goldenQuery = useQuery({
    queryKey: ["vm-goldens"],
    queryFn: () => k8sList<K8sObject>(corePaths.pvcs(IMAGES_NAMESPACE)),
    enabled: open,
    staleTime: 60_000,
  });
  const builtWindows = new Set(
    (goldenQuery.data?.items ?? [])
      .map((p) => p.metadata?.name ?? "")
      .filter((n) => n.endsWith("-golden"))
      .map((n) => n.replace(/-golden$/, "")),
  );
  const hasUnbuiltWindows = OS_CATALOG.some(
    (o) => o.family === "windows" && !builtWindows.has(o.value),
  );

  function reset() {
    setName("");
    setOs("ubuntu-24.04");
    setCpu("2");
    setMemory("2Gi");
    setDiskSize("20Gi");
    setSshKey("");
    setAccess("internal");
    setSecurityGroups([]);
    setAllowAccess(true);
    setAccessSource("anywhere");
    setAccessCidr("");
    setAllowHttp(false);
    setAllowHttps(false);
    setTouched(false);
    createMutation.reset();
  }

  const accessPort = isWindows ? 3389 : 22;
  const useFirewall = allowAccess || allowHttp || allowHttps;
  const accessSgName = `${name}-access`;

  const createMutation = useMutation({
    mutationFn: async (manifest: K8sObject) => {
      // Launch-wizard convenience: create a "<name>-access" SecurityGroup opening
      // the OS access port (+ optional HTTP/HTTPS) and intra-namespace traffic,
      // then attach it (+ any picked SGs) to the VM. Default-deny otherwise.
      const attached = [...(useFirewall ? [accessSgName] : []), ...securityGroups];
      if (useFirewall) {
        const peer =
          accessSource === "cidr" && accessCidr.trim()
            ? { cidr: accessCidr.trim() }
            : { cidr: "0.0.0.0/0" };
        const ingress: Record<string, unknown>[] = [
          // keep the VM reachable in-cluster (platform, same-namespace workloads)
          { from: [{ namespace }] },
        ];
        if (allowAccess) ingress.push({ protocol: "TCP", ports: [accessPort], from: [peer] });
        if (allowHttp) ingress.push({ protocol: "TCP", ports: [80], from: [{ cidr: "0.0.0.0/0" }] });
        if (allowHttps) ingress.push({ protocol: "TCP", ports: [443], from: [{ cidr: "0.0.0.0/0" }] });
        try {
          await k8sCreate<K8sObject>(openinfraPaths.securitygroups(namespace), {
            apiVersion: `${OPENINFRA_GROUP}/${OPENINFRA_VERSION}`,
            kind: "SecurityGroup",
            metadata: { name: accessSgName, namespace },
            spec: { ingress },
          } as K8sObject);
        } catch (e) {
          // Reuse a pre-existing access group (e.g. recreating a VM of the same name).
          if (!(e instanceof ApiError && e.status === 409)) throw e;
        }
      }
      const spec = (manifest.spec ?? {}) as Record<string, unknown>;
      return k8sCreate<K8sObject>(openinfraPaths.virtualmachines(namespace), {
        ...manifest,
        spec: { ...spec, ...(attached.length ? { securityGroups: attached } : {}) },
      } as K8sObject);
    },
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
        // Linux only: the composition fixes the Windows root at 70Gi regardless.
        ...(!isWindows ? { diskSize: diskSize || "20Gi" } : {}),
        ...(sshKey.trim() && !isWindows ? { sshKey: sshKey.trim() } : {}),
        // Derive network + expose from the single access choice.
        expose: access === "lan",
        network: access === "bridge" && bridgeReady ? "bridge" : "masquerade",
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
                {OS_CATALOG.map((o) => {
                  const win = o.family === "windows";
                  const built = !win || builtWindows.has(o.value);
                  return (
                    <SelectItem key={o.value} value={o.value} disabled={!built}>
                      {o.label}
                      {win && !built ? " — not built" : ""}
                    </SelectItem>
                  );
                })}
              </SelectContent>
            </Select>
            {hasUnbuiltWindows ? (
              <p className="text-xs text-muted-foreground">
                Greyed-out Windows versions need building first on the{" "}
                <strong>VM Images</strong> page.
              </p>
            ) : null}
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
          {/* Disk size is Linux-only: cloud-init grows the rootfs to fit. The
              Windows root is fixed at 70Gi (its C: can't be auto-grown); extra
              Windows storage comes from attachable volumes. */}
          {!isWindows ? (
            <div className="space-y-1.5">
              <Label htmlFor="vm-disk">Disk size</Label>
              <Input
                id="vm-disk"
                value={diskSize}
                onChange={(e) => setDiskSize(e.target.value)}
                placeholder="20Gi"
              />
            </div>
          ) : null}
          <div className="space-y-1.5 sm:col-span-2">
            <Label htmlFor="vm-access">Network access</Label>
            <Select value={access} onValueChange={setAccess}>
              <SelectTrigger id="vm-access">
                <SelectValue placeholder="Network access" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="internal">
                  In-cluster only (default)
                </SelectItem>
                <SelectItem value="lan">
                  LAN IP — reach {isWindows ? "RDP (3389)" : "SSH (22)"} from your
                  network (MetalLB)
                </SelectItem>
                {/* Bridge is an advanced cluster-CNI mode; only offer it when an
                    operator has enabled it. Everyday LAN access is "LAN IP" above,
                    which needs no setup. */}
                {bridgeReady ? (
                  <SelectItem value="bridge">
                    Direct on LAN — real DHCP address
                  </SelectItem>
                ) : null}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2 sm:col-span-2 rounded-md border p-3">
            <div className="text-sm font-medium">Firewall</div>
            <p className="text-xs text-muted-foreground">
              A <code>{(name || "<name>") + "-access"}</code> security group is created
              and attached, allowing what you pick below (default-deny otherwise). Edit it
              anytime on the VM's <strong>Network</strong> tab.
            </p>
            <label className="flex flex-wrap items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={allowAccess}
                onChange={(e) => setAllowAccess(e.target.checked)}
                className="size-4 accent-primary"
              />
              Allow {isWindows ? "RDP (3389)" : "SSH (22)"} from
              <Select value={accessSource} onValueChange={setAccessSource} disabled={!allowAccess}>
                <SelectTrigger className="h-8 w-44"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="anywhere">Anywhere (0.0.0.0/0)</SelectItem>
                  <SelectItem value="cidr">Custom IP / CIDR</SelectItem>
                </SelectContent>
              </Select>
            </label>
            {allowAccess && accessSource === "cidr" ? (
              <Input
                value={accessCidr}
                onChange={(e) => setAccessCidr(e.target.value)}
                placeholder="192.0.2.0/24"
                className="h-8 w-56"
              />
            ) : null}
            {allowAccess && accessSource === "anywhere" ? (
              <p className="text-xs text-warning">
                Open to the whole internet — fine for a quick test; scope the source for
                anything real.
              </p>
            ) : null}
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={allowHttp} onChange={(e) => setAllowHttp(e.target.checked)} className="size-4 accent-primary" />
              Allow HTTP (80) from anywhere
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={allowHttps} onChange={(e) => setAllowHttps(e.target.checked)} className="size-4 accent-primary" />
              Allow HTTPS (443) from anywhere
            </label>
            <div className="pt-1">
              <Label className="text-xs text-muted-foreground">Additional security groups</Label>
              <div className="mt-1.5">
                <SecurityGroupPicker
                  namespace={namespace}
                  value={securityGroups}
                  onChange={setSecurityGroups}
                />
              </div>
            </div>
          </div>
          {isWindows ? (
            <div className="sm:col-span-2 rounded-md border border-warning/40 bg-warning/10 p-3 text-xs text-muted-foreground">
              Windows clones a golden image you build once from an eval ISO (see
              docs). The root disk is fixed at <strong>70&nbsp;GiB</strong> — add
              more storage with attachable volumes, not a bigger C:. Login is{" "}
              <span className="font-medium">Administrator</span> + a generated
              password (revealable on the VM page); connect with <code>mstsc</code>{" "}
              over RDP.
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
