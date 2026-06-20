import { type ColumnDef } from "@tanstack/react-table";
import { Badge } from "@/components/ui/badge";
import { age } from "@/lib/format";
import type { Ingress, NetworkPolicy, Service } from "@/types/k8s";

function nameCol<T extends { metadata: { name: string } }>(): ColumnDef<
  T,
  unknown
> {
  return {
    id: "name",
    header: "Name",
    accessorFn: (r) => r.metadata.name,
    cell: ({ row }) => (
      <span className="font-medium">{row.original.metadata.name}</span>
    ),
    size: 220,
  };
}

function namespaceCol<T extends { metadata: { namespace?: string } }>(): ColumnDef<
  T,
  unknown
> {
  return {
    id: "namespace",
    header: "Namespace",
    accessorFn: (r) => r.metadata.namespace ?? "",
    cell: ({ row }) => (
      <span className="text-muted-foreground">
        {row.original.metadata.namespace}
      </span>
    ),
    size: 140,
  };
}

function ageCol<T extends { metadata: { creationTimestamp?: string } }>(): ColumnDef<
  T,
  unknown
> {
  return {
    id: "age",
    header: "Age",
    accessorFn: (r) => r.metadata.creationTimestamp ?? "",
    cell: ({ row }) => (
      <span className="text-muted-foreground">
        {age(row.original.metadata.creationTimestamp)}
      </span>
    ),
    size: 80,
  };
}

/* ----------------------- Load Balancers (Services) ----------------------- */

export function lbExternalIPs(s: Service): string[] {
  return (s.status?.loadBalancer?.ingress ?? [])
    .map((i) => i.ip || i.hostname)
    .filter((v): v is string => Boolean(v));
}

function svcPorts(s: Service): string {
  const ports = s.spec?.ports ?? [];
  if (!ports.length) return "—";
  return ports
    .map((p) => `${p.port}/${p.protocol ?? "TCP"}`)
    .join(", ");
}

export const loadBalancerColumns: ColumnDef<Service, unknown>[] = [
  nameCol<Service>(),
  namespaceCol<Service>(),
  {
    id: "externalIP",
    header: "External IP (MetalLB)",
    accessorFn: (s) => lbExternalIPs(s).join(", "),
    cell: ({ row }) => {
      const ips = lbExternalIPs(row.original);
      return ips.length ? (
        <code className="text-xs text-primary">{ips.join(", ")}</code>
      ) : (
        <span className="text-warning text-xs">pending</span>
      );
    },
    size: 200,
  },
  {
    id: "ports",
    header: "Ports",
    accessorFn: (s) => svcPorts(s),
    cell: ({ row }) => (
      <code className="text-xs">{svcPorts(row.original)}</code>
    ),
    size: 160,
  },
  ageCol<Service>(),
];

/* ------------------------------ Ingresses ------------------------------ */

function ingressHosts(i: Ingress): string[] {
  return (i.spec?.rules ?? [])
    .map((r) => r.host)
    .filter((h): h is string => Boolean(h));
}

function ingressAddress(i: Ingress): string {
  const addrs = (i.status?.loadBalancer?.ingress ?? [])
    .map((x) => x.ip || x.hostname)
    .filter(Boolean);
  return addrs.length ? addrs.join(", ") : "—";
}

export const ingressColumns: ColumnDef<Ingress, unknown>[] = [
  nameCol<Ingress>(),
  namespaceCol<Ingress>(),
  {
    id: "hosts",
    header: "Hosts",
    accessorFn: (i) => ingressHosts(i).join(", "),
    cell: ({ row }) => {
      const hosts = ingressHosts(row.original);
      return hosts.length ? (
        <span className="flex flex-col gap-0.5">
          {hosts.map((h) => (
            <code key={h} className="text-xs">
              {h}
            </code>
          ))}
        </span>
      ) : (
        <span className="text-muted-foreground">—</span>
      );
    },
    size: 260,
  },
  {
    id: "address",
    header: "Address",
    accessorFn: (i) => ingressAddress(i),
    cell: ({ row }) => (
      <code className="text-xs text-muted-foreground">
        {ingressAddress(row.original)}
      </code>
    ),
    size: 150,
  },
  {
    id: "tls",
    header: "TLS",
    accessorFn: (i) => ((i.spec?.tls?.length ?? 0) > 0 ? "yes" : "no"),
    cell: ({ row }) =>
      (row.original.spec?.tls?.length ?? 0) > 0 ? (
        <Badge variant="secondary">TLS</Badge>
      ) : (
        <span className="text-muted-foreground text-xs">—</span>
      ),
    size: 80,
  },
  {
    id: "class",
    header: "Class",
    accessorFn: (i) => i.spec?.ingressClassName ?? "",
    cell: ({ row }) => (
      <span className="text-xs text-muted-foreground">
        {row.original.spec?.ingressClassName ?? "—"}
      </span>
    ),
    size: 110,
  },
  ageCol<Ingress>(),
];

/* --------------------------- Network Policies --------------------------- */

function netpolSelector(np: NetworkPolicy): string {
  const labels = np.spec?.podSelector?.matchLabels;
  if (!labels || Object.keys(labels).length === 0) return "all pods";
  return Object.entries(labels)
    .map(([k, v]) => `${k}=${v}`)
    .join(", ");
}

export const networkPolicyColumns: ColumnDef<NetworkPolicy, unknown>[] = [
  nameCol<NetworkPolicy>(),
  namespaceCol<NetworkPolicy>(),
  {
    id: "selector",
    header: "Applies to",
    accessorFn: (np) => netpolSelector(np),
    cell: ({ row }) => (
      <code className="text-xs">{netpolSelector(row.original)}</code>
    ),
    size: 240,
  },
  {
    id: "types",
    header: "Policy types",
    accessorFn: (np) => (np.spec?.policyTypes ?? []).join(", "),
    cell: ({ row }) => {
      const types = row.original.spec?.policyTypes ?? [];
      return types.length ? (
        <span className="flex gap-1">
          {types.map((t) => (
            <Badge key={t} variant="secondary">
              {t}
            </Badge>
          ))}
        </span>
      ) : (
        <span className="text-muted-foreground text-xs">—</span>
      );
    },
    size: 180,
  },
  ageCol<NetworkPolicy>(),
];
