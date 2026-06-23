import type {
  SecurityGroupPeer,
  SecurityGroupRule,
} from "@/types/k8s";

/**
 * AWS-style "Type" presets: picking one auto-fills protocol + ports, so the user
 * only has to answer "who can reach it" (the source/destination). Mirrors the
 * EC2 security-group rule editor's Type dropdown.
 */
export interface RuleTypePreset {
  id: string;
  label: string;
  protocol: "TCP" | "UDP";
  ports: number[]; // [] = all ports
  custom?: boolean; // port is user-editable
}

export const RULE_TYPES: RuleTypePreset[] = [
  { id: "ssh", label: "SSH", protocol: "TCP", ports: [22] },
  { id: "rdp", label: "RDP", protocol: "TCP", ports: [3389] },
  { id: "http", label: "HTTP", protocol: "TCP", ports: [80] },
  { id: "https", label: "HTTPS", protocol: "TCP", ports: [443] },
  { id: "postgres", label: "PostgreSQL", protocol: "TCP", ports: [5432] },
  { id: "mysql", label: "MySQL / Aurora", protocol: "TCP", ports: [3306] },
  { id: "mssql", label: "MS SQL", protocol: "TCP", ports: [1433] },
  { id: "redis", label: "Redis", protocol: "TCP", ports: [6379] },
  { id: "mongo", label: "MongoDB", protocol: "TCP", ports: [27017] },
  { id: "dns-udp", label: "DNS (UDP)", protocol: "UDP", ports: [53] },
  { id: "all-tcp", label: "All TCP", protocol: "TCP", ports: [] },
  { id: "all-udp", label: "All UDP", protocol: "UDP", ports: [] },
  { id: "custom-tcp", label: "Custom TCP", protocol: "TCP", ports: [], custom: true },
  { id: "custom-udp", label: "Custom UDP", protocol: "UDP", ports: [], custom: true },
];

export function ruleTypeById(id: string): RuleTypePreset {
  return RULE_TYPES.find((t) => t.id === id) ?? RULE_TYPES[0]!;
}

/** Source/destination presets — "who can reach it". */
export type PeerKind = "anywhere" | "cidr" | "securityGroup" | "namespace";

export const PEER_KINDS: { id: PeerKind; label: string; needsValue: boolean; placeholder?: string }[] = [
  { id: "anywhere", label: "Anywhere (0.0.0.0/0)", needsValue: false },
  { id: "cidr", label: "Custom IP / CIDR", needsValue: true, placeholder: "192.0.2.0/24" },
  { id: "securityGroup", label: "Security group", needsValue: true, placeholder: "web" },
  { id: "namespace", label: "Namespace", needsValue: true, placeholder: "team-a" },
];

/** One editable row in the rule editor. */
export interface RuleRow {
  id: string; // local key
  typeId: string;
  customPort: string; // used when the type is custom
  peerKind: PeerKind;
  peerValue: string;
}

export function emptyRow(seed: string): RuleRow {
  return { id: seed, typeId: "ssh", customPort: "", peerKind: "anywhere", peerValue: "" };
}

function rowToPeer(row: RuleRow): SecurityGroupPeer | null {
  switch (row.peerKind) {
    case "anywhere":
      return { cidr: "0.0.0.0/0" };
    case "cidr":
      return row.peerValue.trim() ? { cidr: row.peerValue.trim() } : null;
    case "securityGroup":
      return row.peerValue.trim() ? { securityGroup: row.peerValue.trim() } : null;
    case "namespace":
      return row.peerValue.trim() ? { namespace: row.peerValue.trim() } : null;
  }
}

/** Build a SecurityGroupRule (with from OR to) from an editor row. */
export function rowToRule(row: RuleRow, dir: "from" | "to"): SecurityGroupRule | null {
  const type = ruleTypeById(row.typeId);
  const peer = rowToPeer(row);
  if (!peer) return null;
  const ports = type.custom
    ? Number(row.customPort)
      ? [Number(row.customPort)]
      : []
    : type.ports;
  const rule: SecurityGroupRule = { protocol: type.protocol, [dir]: [peer] } as SecurityGroupRule;
  if (ports.length) rule.ports = ports;
  return rule;
}

export function rowValid(row: RuleRow): boolean {
  const type = ruleTypeById(row.typeId);
  if (type.custom) {
    const p = Number(row.customPort);
    if (!p || p < 1 || p > 65535) return false;
  }
  const peerSpec = PEER_KINDS.find((k) => k.id === row.peerKind);
  if (peerSpec?.needsValue && !row.peerValue.trim()) return false;
  return true;
}

/** Human summary of a rule (for the list table): "SSH ← 192.0.2.0/24". */
export function peerText(p: SecurityGroupPeer): string {
  if (p.cidr) return p.cidr === "0.0.0.0/0" ? "Anywhere" : p.cidr;
  if (p.securityGroup) return `sg:${p.securityGroup}`;
  if (p.namespace) return `ns:${p.namespace}`;
  return "?";
}

/** Build a SecurityGroup spec from the editor rows. Ingress is always present
 * (empty = deny all inbound); egress only when restricted (else all outbound). */
export function buildSpec(inbound: RuleRow[], outbound: RuleRow[]): Record<string, unknown> {
  const spec: Record<string, unknown> = {
    ingress: inbound.map((r) => rowToRule(r, "from")).filter(Boolean),
  };
  if (outbound.length) {
    spec.egress = outbound.map((r) => rowToRule(r, "to")).filter(Boolean);
  }
  return spec;
}

let RID = 0;

/** Parse stored SecurityGroup rules back into editor rows (one row per peer×port),
 * so an existing group can be edited. Inverse of buildSpec. */
export function rulesToRows(rules: SecurityGroupRule[] | undefined, dir: "from" | "to"): RuleRow[] {
  const rows: RuleRow[] = [];
  for (const rule of rules ?? []) {
    const proto = rule.protocol === "UDP" ? "UDP" : "TCP";
    const peers = (rule[dir] ?? []) as SecurityGroupPeer[];
    const ports: (number | null)[] = rule.ports && rule.ports.length ? rule.ports : [null];
    for (const peer of peers.length ? peers : [{} as SecurityGroupPeer]) {
      for (const port of ports) {
        rows.push(rowFromParts(proto, port, peer));
      }
    }
  }
  return rows;
}

function rowFromParts(proto: "TCP" | "UDP", port: number | null, peer: SecurityGroupPeer): RuleRow {
  let typeId: string;
  let customPort = "";
  if (port == null) {
    typeId = proto === "UDP" ? "all-udp" : "all-tcp";
  } else {
    const named = RULE_TYPES.find(
      (t) => !t.custom && t.protocol === proto && t.ports.length === 1 && t.ports[0] === port,
    );
    if (named) {
      typeId = named.id;
    } else {
      typeId = proto === "UDP" ? "custom-udp" : "custom-tcp";
      customPort = String(port);
    }
  }
  let peerKind: PeerKind = "anywhere";
  let peerValue = "";
  if (peer.cidr) {
    if (peer.cidr === "0.0.0.0/0") peerKind = "anywhere";
    else {
      peerKind = "cidr";
      peerValue = peer.cidr;
    }
  } else if (peer.securityGroup) {
    peerKind = "securityGroup";
    peerValue = peer.securityGroup;
  } else if (peer.namespace) {
    peerKind = "namespace";
    peerValue = peer.namespace;
  }
  return { id: `p${RID++}`, typeId, customPort, peerKind, peerValue };
}
