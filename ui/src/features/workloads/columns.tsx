import { type ColumnDef } from "@tanstack/react-table";
import { AlertTriangle } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { Badge } from "@/components/ui/badge";
import { age, statusTone, type StatusTone } from "@/lib/format";
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

/**
 * What to show in the Status column. When the pod's node is offline, its
 * reported phase (often still "Running") is stale, so we override it — this is
 * what stops the Workloads view from claiming pods run on a dead node.
 */
function podStatusView(
  pod: Pod,
  offlineNodes: Set<string>,
): { label: string; tone?: StatusTone } {
  const node = pod.spec?.nodeName;
  if (node && offlineNodes.has(node) && !pod.metadata.deletionTimestamp) {
    return { label: "Node down", tone: "destructive" };
  }
  return { label: podPhase(pod) };
}

function podRestarts(pod: Pod): number {
  return (pod.status?.containerStatuses ?? []).reduce(
    (sum, s) => sum + (s.restartCount ?? 0),
    0,
  );
}

/**
 * Pod columns are a factory (not a const) because Status and Node both depend on
 * which nodes are currently offline — passed in from the Workloads page's node
 * watch so the table can flag pods stranded on a dead node.
 */
export function podColumns(
  offlineNodes: Set<string> = new Set(),
): ColumnDef<Pod, unknown>[] {
  return [
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
      accessorFn: (p) => podStatusView(p, offlineNodes).label,
      cell: ({ row }) => {
        const v = podStatusView(row.original, offlineNodes);
        return <StatusBadge status={v.label} tone={v.tone} />;
      },
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
      cell: ({ row }) => {
        const node = row.original.spec?.nodeName;
        if (!node) return <span className="text-muted-foreground">—</span>;
        const offline = offlineNodes.has(node);
        return (
          <span
            className={
              offline
                ? "flex items-center gap-1 font-medium text-destructive"
                : "text-muted-foreground"
            }
            title={offline ? "Node is NotReady" : undefined}
          >
            {offline ? <AlertTriangle className="size-3.5" /> : null}
            {node}
          </span>
        );
      },
      size: 180,
    },
    ageCol<Pod>(),
  ];
}

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
