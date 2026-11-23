// What reaches an instance's public IPv4 address, read from the instance and its security groups: pure
// helpers (no React, and nothing written), so node's test runner checks them directly.
//
// The ports an address carries are the instance's own (its access port and spec.ports), set when it is
// launched or by its CloudFormation stack; viewing an instance never changes them. Who may use each port
// is its security groups' inbound rules with an address-range source: a rule whose source is a security
// group or a namespace admits those members over the private network, never a client of the public
// address.

import type { SecurityGroup, VirtualMachineSpec } from "@/types/k8s";

export type Protocol = "TCP" | "UDP";

export interface PublishedPort {
  port: number;
  protocol: Protocol;
}

/** One source allowed to a published port, and the group whose inbound rule allows it. */
export interface PortSource {
  group: string;
  cidr: string;
  description?: string;
}

export interface PortReach extends PublishedPort {
  /** The instance's access port (SSH 22 / RDP 3389), which every public address carries. */
  access: boolean;
  /** Every source may use the port: the instance has no security group, or one restricts no inbound. */
  open: boolean;
  sources: PortSource[];
}

const proto = (p?: string): Protocol => (p?.toUpperCase() === "UDP" ? "UDP" : "TCP");

/**
 * The ports on the instance's public address: its access port first, then its spec.ports, each once. An
 * instance gets a public address only when it is exposed (spec.expose or any spec.ports); otherwise none.
 */
export function publicPorts(spec: VirtualMachineSpec | undefined, accessPort: number): PublishedPort[] {
  const extra = spec?.ports ?? [];
  if (!spec?.expose && extra.length === 0) return [];
  const seen = new Set<string>();
  const out: PublishedPort[] = [];
  const add = (port: number, protocol: Protocol) => {
    const k = `${port}/${protocol}`;
    if (!port || seen.has(k)) return;
    seen.add(k);
    out.push({ port, protocol });
  };
  add(accessPort, "TCP");
  for (const p of extra) add(p.port, proto(p.protocol));
  return out;
}

/**
 * For each published port, who may reach it through the public address. groupNames are the instance's
 * security groups; groups holds those loaded (a group not loaded contributes nothing).
 */
export function reachability(
  ports: PublishedPort[],
  accessPort: number,
  groupNames: string[],
  groups: Map<string, SecurityGroup>,
): PortReach[] {
  const unrestricted = groupNames.length === 0 || groupNames.some((n) => groups.get(n) && !groups.get(n)?.spec?.ingress);
  return ports.map((p) => {
    const sources: PortSource[] = [];
    for (const name of groupNames) {
      for (const rule of groups.get(name)?.spec?.ingress ?? []) {
        const rp = (rule.protocol ?? "TCP").toUpperCase();
        if (rp !== "ALL" && proto(rp) !== p.protocol) continue;
        if (rule.ports?.length && !rule.ports.includes(p.port)) continue;
        for (const peer of rule.from ?? []) {
          if (peer.cidr) sources.push({ group: name, cidr: peer.cidr, description: rule.description });
        }
      }
    }
    return { ...p, access: p.port === accessPort && p.protocol === "TCP", open: unrestricted, sources };
  });
}
