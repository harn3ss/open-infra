import { useMemo } from "react";
import { DetailRow } from "@/components/common/detail-row";
import { Badge } from "@/components/ui/badge";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { openinfraPaths } from "@/lib/k8s-paths";
import { publicPorts, reachability } from "@/lib/vm-reachability";
import type { SecurityGroup, VirtualMachineSpec } from "@/types/k8s";

/**
 * Network tab: the instance's addresses, the ports its public IPv4 address carries, and who its security
 * groups admit to each. It only reads. The ports are the instance's own (set at launch, or by its
 * CloudFormation stack from the security groups of an instance with an Elastic IP or a public address in
 * a VPC with an internet gateway); a security group rule never gives an instance a public address, as on
 * AWS. A test (src/lib/vm-reachability.test.ts) holds this file to reading only.
 */
export function VmNetworkTab({
  namespace,
  spec,
  lanIp,
  privateIp,
  accessPort,
  accessLabel,
}: {
  namespace: string;
  spec?: VirtualMachineSpec;
  lanIp?: string;
  privateIp?: string;
  accessPort: string;
  accessLabel: string;
}) {
  const accessPortNum = Number(accessPort) || 0;
  const groupNames = spec?.securityGroups ?? [];

  const { items: sgs, isLoading: sgsLoading } = useK8sWatch<SecurityGroup>(openinfraPaths.securitygroups(namespace));
  const sgByName = useMemo(() => new Map(sgs.map((s) => [s.metadata.name ?? "", s])), [sgs]);

  const ports = publicPorts(spec, accessPortNum);
  const reach = reachability(ports, accessPortNum, groupNames, sgByName);

  return (
    <div className="space-y-4 max-w-2xl">
      <DetailRow label="Public IPv4 address">
        {ports.length ? (
          lanIp ? (
            <code className="text-xs">{lanIp}</code>
          ) : (
            <span className="text-xs text-muted-foreground">pending…</span>
          )
        ) : (
          <span className="text-sm text-muted-foreground">
            none — reach the instance from your network through a network load balancer, or associate an
            Elastic IP in a VPC with an internet gateway
          </span>
        )}
      </DetailRow>
      <DetailRow label="Private IPv4 address">
        {privateIp ? <code className="text-xs">{privateIp}</code> : <span className="text-sm text-muted-foreground">—</span>}
      </DetailRow>

      {ports.length > 0 && (
        <div>
          <div className="mb-2 text-sm font-medium">Ports on the public address</div>
          <div className="divide-y rounded-md border">
            {reach.map((r) => (
              <div key={`${r.port}/${r.protocol}`} className="flex flex-wrap items-center gap-3 px-3 py-2 text-sm">
                <code className="w-24">
                  {r.port}/{r.protocol}
                </code>
                {r.access && <span className="text-muted-foreground">{accessLabel}</span>}
                <span className="text-xs text-muted-foreground">
                  {sgsLoading && !r.open ? (
                    "…"
                  ) : r.open ? (
                    "any source"
                  ) : r.sources.length ? (
                    r.sources.map((s, i) => (
                      <span key={i} className="mr-2 inline-flex items-center gap-1">
                        <code>{s.cidr}</code>
                        <span>via</span>
                        <Badge variant="outline" className="font-mono text-[10px]">
                          {s.group}
                        </Badge>
                      </span>
                    ))
                  ) : (
                    "no inbound rule allows a source on this port"
                  )}
                </span>
                {lanIp && (
                  <span className="ml-auto text-xs text-muted-foreground">
                    {lanIp}:{r.port}
                  </span>
                )}
              </div>
            ))}
          </div>
          <p className="mt-2 text-xs text-muted-foreground">
            Who may reach each port is decided by the inbound rules of the instance's security groups (the{" "}
            <strong>Security</strong> tab) with an address-range source. A rule whose source is a security
            group admits that group's members over the private network, not the public address.
          </p>
        </div>
      )}
    </div>
  );
}
