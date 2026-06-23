import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { DetailRow } from "@/components/common/detail-row";
import { SecurityGroupPicker } from "@/components/common/security-group-picker";
import { k8sGet, k8sReplace } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { VirtualMachine } from "@/types/k8s";

type Port = { port: number; protocol?: string };

/**
 * Network tab: manage the extra ports published on the VM's LAN IP (spec.ports).
 * They ride the same MetalLB IP as SSH/RDP — one LAN IP, the ports you pick.
 */
export function VmNetworkTab({
  namespace,
  vmName,
  ports,
  securityGroups,
  lanIp,
  accessPort,
  accessLabel,
  onChange,
}: {
  namespace: string;
  vmName: string;
  ports: Port[];
  securityGroups: string[];
  lanIp?: string;
  accessPort: string;
  accessLabel: string;
  onChange: () => void;
}) {
  const [newPort, setNewPort] = useState("");
  const [newProto, setNewProto] = useState("TCP");
  const vmPath = openinfraPaths.virtualmachine(namespace, vmName);

  const save = useMutation({
    mutationFn: async (next: Port[]) => {
      // GET-then-PUT so we don't clobber other spec fields (cf. Start/Stop).
      const cur = await k8sGet<VirtualMachine>(vmPath);
      return k8sReplace<VirtualMachine>(vmPath, {
        ...cur,
        spec: { ...(cur.spec ?? {}), ports: next },
      } as VirtualMachine);
    },
    onSuccess: () => onChange(),
  });

  const saveSgs = useMutation({
    mutationFn: async (next: string[]) => {
      const cur = await k8sGet<VirtualMachine>(vmPath);
      return k8sReplace<VirtualMachine>(vmPath, {
        ...cur,
        spec: { ...(cur.spec ?? {}), securityGroups: next },
      } as VirtualMachine);
    },
    onSuccess: () => onChange(),
  });

  const same = (a: Port, b: Port) =>
    a.port === b.port && (a.protocol ?? "TCP") === (b.protocol ?? "TCP");

  function add() {
    const p = Number(newPort);
    if (!p || p < 1 || p > 65535) return;
    const candidate: Port = { port: p, protocol: newProto };
    if (ports.some((x) => same(x, candidate))) return;
    save.mutate([...ports, candidate]);
    setNewPort("");
  }

  return (
    <div className="space-y-4 max-w-2xl">
      <DetailRow label="LAN IP">
        {lanIp ? (
          <code className="text-xs">{lanIp}</code>
        ) : (
          <span className="text-muted-foreground text-sm">
            none yet — publish a port (below) to give this VM a LAN IP
          </span>
        )}
      </DetailRow>

      <div>
        <div className="mb-2 text-sm font-medium">Published ports</div>
        <div className="divide-y rounded-md border">
          {/* The access port (SSH/RDP) is always published; it can't be removed here. */}
          <div className="flex items-center gap-3 px-3 py-2 text-sm">
            <code className="w-24">{accessPort}/TCP</code>
            <span className="text-muted-foreground">{accessLabel}</span>
            {lanIp && (
              <span className="ml-auto text-xs text-muted-foreground">{lanIp}:{accessPort}</span>
            )}
          </div>
          {ports.map((pt) => (
            <div key={`${pt.port}-${pt.protocol ?? "TCP"}`} className="flex items-center gap-3 px-3 py-2 text-sm">
              <code className="w-24">{pt.port}/{pt.protocol ?? "TCP"}</code>
              {lanIp && (
                <span className="ml-auto text-xs text-muted-foreground">{lanIp}:{pt.port}</span>
              )}
              <Button
                size="sm"
                variant="ghost"
                onClick={() => save.mutate(ports.filter((x) => !same(x, pt)))}
                disabled={save.isPending}
                title="Unpublish this port"
              >
                <Trash2 className="size-4" />
              </Button>
            </div>
          ))}
          {!ports.length && (
            <div className="px-3 py-2 text-xs text-muted-foreground">
              No extra ports. Add one to publish it on the VM's LAN IP.
            </div>
          )}
        </div>
      </div>

      <div className="flex items-end gap-2">
        <div className="space-y-1">
          <label className="text-xs">Port</label>
          <Input
            value={newPort}
            onChange={(e) => setNewPort(e.target.value)}
            placeholder="80"
            inputMode="numeric"
            className="w-28"
          />
        </div>
        <div className="space-y-1">
          <label className="text-xs">Protocol</label>
          <Select value={newProto} onValueChange={setNewProto}>
            <SelectTrigger className="w-24"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="TCP">TCP</SelectItem>
              <SelectItem value="UDP">UDP</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <Button onClick={add} disabled={save.isPending || !newPort}>
          <Plus className="size-4" /> Publish port
        </Button>
      </div>

      <p className="text-xs text-muted-foreground">
        Ports ride the VM's single LAN IP alongside SSH/RDP (MetalLB) — the guest must be
        listening on the port. Publishing the first port also gives the VM a LAN IP. For a
        full LAN host (all ports, real DHCP IP) use <code>network: bridge</code> instead.
      </p>
      {save.error ? (
        <p className="text-sm text-destructive">Couldn't update ports — try again.</p>
      ) : null}

      <div className="border-t pt-4">
        <div className="mb-2 text-sm font-medium">Security groups</div>
        <p className="mb-3 text-xs text-muted-foreground">
          Attach firewall rule sets to control who can reach this VM (e.g. restrict
          SSH/RDP to a CIDR). Click to attach/detach — changes apply immediately.
        </p>
        <SecurityGroupPicker
          namespace={namespace}
          value={securityGroups}
          onChange={(next) => saveSgs.mutate(next)}
          disabled={saveSgs.isPending}
        />
        {saveSgs.error ? (
          <p className="mt-2 text-sm text-destructive">Couldn't update security groups — try again.</p>
        ) : null}
      </div>
    </div>
  );
}
