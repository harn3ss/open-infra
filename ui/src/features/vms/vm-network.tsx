import { useEffect, useMemo, useRef } from "react";
import { useMutation } from "@tanstack/react-query";
import { DetailRow } from "@/components/common/detail-row";
import { SecurityGroupPicker } from "@/components/common/security-group-picker";
import { Badge } from "@/components/ui/badge";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { k8sGet, k8sReplace } from "@/lib/api";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { SecurityGroup, VirtualMachine } from "@/types/k8s";

type Port = { port: number; protocol?: string };

const sig = (ps: Port[]) =>
  [...ps]
    .map((p) => `${p.port}/${p.protocol ?? "TCP"}`)
    .sort()
    .join(",");

/**
 * Network tab. The VM's reachable LAN ports are NOT edited here directly — they
 * are *derived from the attached security groups*. Opening a port means adding an
 * inbound rule to a security group (on the Security Groups page); the LB listener
 * (spec.ports) then follows automatically. This keeps access control in one place
 * (security groups) instead of an out-of-band "publish port" control.
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
  const vmPath = openinfraPaths.virtualmachine(namespace, vmName);
  const accessPortNum = Number(accessPort) || 0;

  const { items: sgs } = useK8sWatch<SecurityGroup>(openinfraPaths.securitygroups(namespace));
  const sgByName = useMemo(
    () => new Map(sgs.map((s) => [s.metadata.name ?? "", s])),
    [sgs],
  );

  // Ports to publish on the LB = the specific inbound ports across the attached
  // SGs (the base access port is published by the composition itself).
  const allLoaded = securityGroups.every((n) => sgByName.has(n));
  const derived = useMemo(() => {
    const map = new Map<string, { port: number; protocol: string; sg: string }>();
    for (const n of securityGroups) {
      const sg = sgByName.get(n);
      for (const rule of sg?.spec?.ingress ?? []) {
        const protocol = rule.protocol === "UDP" ? "UDP" : "TCP";
        for (const p of rule.ports ?? []) {
          if (!p) continue;
          if (p === accessPortNum && protocol === "TCP") continue; // base access port
          map.set(`${p}/${protocol}`, { port: p, protocol, sg: n });
        }
      }
    }
    return Array.from(map.values()).sort((a, b) => a.port - b.port);
  }, [securityGroups, sgByName, accessPortNum]);

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

  const syncPorts = useMutation({
    mutationFn: async (next: Port[]) => {
      const cur = await k8sGet<VirtualMachine>(vmPath);
      return k8sReplace<VirtualMachine>(vmPath, {
        ...cur,
        spec: { ...(cur.spec ?? {}), ports: next },
      } as VirtualMachine);
    },
    onSuccess: () => onChange(),
  });

  // Keep the published LB ports (spec.ports) aligned with what the security groups
  // allow. Runs only once the attached SGs have loaded, and only on real drift.
  const desired: Port[] = derived.map((d) => ({ port: d.port, protocol: d.protocol }));
  const lastSynced = useRef<string | null>(null);
  useEffect(() => {
    if (!allLoaded) return;
    const want = sig(desired);
    if (sig(ports) === want) {
      lastSynced.current = want;
      return;
    }
    if (lastSynced.current === want) return; // already pushed this set; await refetch
    lastSynced.current = want;
    syncPorts.mutate(desired);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allLoaded, sig(desired), sig(ports)]);

  return (
    <div className="space-y-4 max-w-2xl">
      <DetailRow label="LAN IP">
        {lanIp ? (
          <code className="text-xs">{lanIp}</code>
        ) : (
          <span className="text-muted-foreground text-sm">
            none yet — attach a security group that allows inbound traffic
          </span>
        )}
      </DetailRow>

      <div>
        <div className="mb-2 text-sm font-medium">Reachable ports</div>
        <div className="divide-y rounded-md border">
          {/* The access port (SSH/RDP) is always published by the platform. */}
          <div className="flex items-center gap-3 px-3 py-2 text-sm">
            <code className="w-24">{accessPort}/TCP</code>
            <span className="text-muted-foreground">{accessLabel}</span>
            {lanIp && (
              <span className="ml-auto text-xs text-muted-foreground">{lanIp}:{accessPort}</span>
            )}
          </div>
          {derived.map((d) => (
            <div key={`${d.port}-${d.protocol}`} className="flex items-center gap-3 px-3 py-2 text-sm">
              <code className="w-24">{d.port}/{d.protocol}</code>
              <span className="text-xs text-muted-foreground">
                via <Badge variant="outline" className="font-mono text-[10px]">{d.sg}</Badge>
              </span>
              {lanIp && (
                <span className="ml-auto text-xs text-muted-foreground">{lanIp}:{d.port}</span>
              )}
            </div>
          ))}
          {!derived.length && (
            <div className="px-3 py-2 text-xs text-muted-foreground">
              Only {accessLabel} is reachable. Open more ports by adding inbound rules to a
              security group below.
            </div>
          )}
        </div>
        <p className="mt-2 text-xs text-muted-foreground">
          Ports are controlled by the attached security groups — to publish one, add an
          inbound rule (e.g. <code>HTTP</code>) to a security group on the{" "}
          <strong>Security Groups</strong> page. The LAN listener follows automatically.
        </p>
      </div>

      <div className="border-t pt-4">
        <div className="mb-2 text-sm font-medium">Security groups</div>
        <p className="mb-3 text-xs text-muted-foreground">
          The firewall for this VM — they decide which ports are open and who may reach
          them (e.g. restrict RDP to a CIDR). Click to attach/detach.
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
