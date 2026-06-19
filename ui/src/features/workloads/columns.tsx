import { type ColumnDef } from "@tanstack/react-table";
import { StatusBadge } from "@/components/common/status-badge";
import { Badge } from "@/components/ui/badge";
import { age, statusTone } from "@/lib/format";
import type { Deployment, Pod, Service } from "@/types/k8s";

const nameCol = <T extends { metadata: { name: string } }>(): ColumnDef<
  T,
  unknown
> => ({
  id: "name",
  header: "Name",
  accessorFn: (r) => r.metadata.name,
  cell: ({ row }) => (
    <span className="font-medium">{row.original.metadata.name}</span>
  ),
  size: 260,
});

const namespaceCol = <T extends { metadata: { namespace?: string } }>(): ColumnDef<
  T,
  unknown
> => ({
  id: "namespace",
  header: "Namespace",
  accessorFn: (r) => r.metadata.namespace ?? "",
  cell: ({ row }) => (
    <span className="text-muted-foreground">
      {row.original.metadata.namespace}
    </span>
  ),
  size: 150,
});

const ageCol = <T extends { metadata: { creationTimestamp?: string } }>(): ColumnDef<
  T,
  unknown
> => ({
  id: "age",
  header: "Age",
  accessorFn: (r) => r.metadata.creationTimestamp ?? "",
  cell: ({ row }) => (
    <span className="text-muted-foreground">
      {age(row.original.metadata.creationTimestamp)}
    </span>
  ),
  size: 90,
});

/* ------------------------------- Pods ------------------------------- */

function podReady(pod: Pod): string {
  const statuses = pod.status?.containerStatuses ?? [];
  const ready = statuses.filter((s) => s.ready).length;
  const total = statuses.length || pod.spec?.containers?.length || 0;
  return `${ready}/${total}`;
}

function podPhase(pod: Pod): string {
  // Surface a waiting/terminated container reason when present (more useful
  // than the bare phase, e.g. CrashLoopBackOff).
  const waiting = pod.status?.containerStatuses?.find(
    (s) => s.state && "waiting" in s.state,
  );
  if (waiting?.state && typeof waiting.state === "object") {
    const w = (waiting.state as { waiting?: { reason?: string } }).waiting;
    if (w?.reason) return w.reason;
  }
  return pod.status?.reason || pod.status?.phase || "Unknown";
}

function podRestarts(pod: Pod): number {
  return (pod.status?.containerStatuses ?? []).reduce(
    (sum, s) => sum + (s.restartCount ?? 0),
    0,
  );
}

export const podColumns: ColumnDef<Pod, unknown>[] = [
  nameCol<Pod>(),
  namespaceCol<Pod>(),
  {
    id: "ready",
    header: "Ready",
    accessorFn: (p) => podReady(p),
    cell: ({ row }) => (
      <span className="font-mono text-xs">{podReady(row.original)}</span>
    ),
    size: 80,
  },
  {
    id: "status",
    header: "Status",
    accessorFn: (p) => podPhase(p),
    cell: ({ row }) => <StatusBadge status={podPhase(row.original)} />,
    size: 170,
  },
  {
    id: "restarts",
    header: "Restarts",
    accessorFn: (p) => podRestarts(p),
    cell: ({ row }) => {
      const r = podRestarts(row.original);
      return (
        <span className={r > 0 ? "font-medium text-warning" : "text-muted-foreground"}>
          {r}
        </span>
      );
    },
    size: 90,
  },
  {
    id: "node",
    header: "Node",
    accessorFn: (p) => p.spec?.nodeName ?? "",
    cell: ({ row }) => (
      <span className="text-muted-foreground">
        {row.original.spec?.nodeName ?? "—"}
      </span>
    ),
    size: 160,
  },
  ageCol<Pod>(),
];

/* ---------------------------- Deployments ---------------------------- */

function deploymentReady(d: Deployment): string {
  const ready = d.status?.readyReplicas ?? 0;
  const desired = d.spec?.replicas ?? d.status?.replicas ?? 0;
  return `${ready}/${desired}`;
}

function deploymentTone(d: Deployment) {
  const ready = d.status?.readyReplicas ?? 0;
  const desired = d.spec?.replicas ?? 0;
  if (desired === 0) return statusTone("paused");
  return ready >= desired ? statusTone("available") : statusTone("progressing");
}

export const deploymentColumns: ColumnDef<Deployment, unknown>[] = [
  nameCol<Deployment>(),
  namespaceCol<Deployment>(),
  {
    id: "ready",
    header: "Ready",
    accessorFn: (d) => deploymentReady(d),
    cell: ({ row }) => (
      <StatusBadge
        status={deploymentReady(row.original)}
        tone={deploymentTone(row.original)}
      />
    ),
    size: 110,
  },
  {
    id: "uptodate",
    header: "Up-to-date",
    accessorFn: (d) => d.status?.updatedReplicas ?? 0,
    cell: ({ row }) => (
      <span className="font-mono text-xs">
        {row.original.status?.updatedReplicas ?? 0}
      </span>
    ),
    size: 110,
  },
  {
    id: "available",
    header: "Available",
    accessorFn: (d) => d.status?.availableReplicas ?? 0,
    cell: ({ row }) => (
      <span className="font-mono text-xs">
        {row.original.status?.availableReplicas ?? 0}
      </span>
    ),
    size: 100,
  },
  ageCol<Deployment>(),
];

/* ------------------------------ Services ------------------------------ */

function servicePorts(s: Service): string {
  const ports = s.spec?.ports ?? [];
  if (ports.length === 0) return "—";
  return ports
    .map((p) => `${p.port}${p.nodePort ? `:${p.nodePort}` : ""}/${p.protocol ?? "TCP"}`)
    .join(", ");
}

export const serviceColumns: ColumnDef<Service, unknown>[] = [
  nameCol<Service>(),
  namespaceCol<Service>(),
  {
    id: "type",
    header: "Type",
    accessorFn: (s) => s.spec?.type ?? "ClusterIP",
    cell: ({ row }) => (
      <Badge variant="secondary">{row.original.spec?.type ?? "ClusterIP"}</Badge>
    ),
    size: 130,
  },
  {
    id: "clusterIP",
    header: "Cluster IP",
    accessorFn: (s) => s.spec?.clusterIP ?? "",
    cell: ({ row }) => (
      <code className="text-xs text-muted-foreground">
        {row.original.spec?.clusterIP ?? "—"}
      </code>
    ),
    size: 150,
  },
  {
    id: "ports",
    header: "Ports",
    accessorFn: (s) => servicePorts(s),
    cell: ({ row }) => (
      <code className="block max-w-[18rem] truncate text-xs">
        {servicePorts(row.original)}
      </code>
    ),
    size: 220,
  },
  ageCol<Service>(),
];
