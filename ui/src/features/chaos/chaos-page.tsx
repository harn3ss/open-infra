import { useMemo } from "react";
import { useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { Bomb, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { kindDocsUrl } from "@/lib/kind-docs";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useConfig } from "@/lib/config-context";
import { EmptyState } from "@/components/common/states";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import { type Condition, type FaultInjection, type FaultInjectionType } from "@/types/k8s";

// type -> friendly label + which extra knobs to show in the form.
export const TYPES: { value: FaultInjectionType; label: string; group: string }[] = [
  { value: "pod-kill", label: "Pod kill", group: "Pod" },
  { value: "pod-failure", label: "Pod failure (unavailable)", group: "Pod" },
  { value: "network-latency", label: "Network latency", group: "Network" },
  { value: "network-loss", label: "Network packet loss", group: "Network" },
  { value: "network-partition", label: "Network partition", group: "Network" },
  { value: "stress-cpu", label: "CPU stress", group: "Stress" },
  { value: "stress-memory", label: "Memory stress", group: "Stress" },
  { value: "clock-skew", label: "Clock skew", group: "Time" },
  { value: "io-latency", label: "Disk I/O latency", group: "IO" },
];
const TYPE_LABEL = Object.fromEntries(TYPES.map((t) => [t.value, t.label]));

function fiStatus(f: FaultInjection): { label: string; tone: StatusTone } {
  const ready = (f.status as { conditions?: Condition[] } | undefined)?.conditions?.find(
    (c) => c.type === "Ready",
  );
  if (ready?.status === "True") return { label: "Active", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

function targetSummary(f: FaultInjection): string {
  const t = f.spec?.target;
  if (!t) return "—";
  const sel = Object.entries(t.labelSelector ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join(",");
  return `${t.namespace ?? f.metadata.namespace}/${sel || "*"}`;
}

// Chaos is a privileged, non-essential capability (NIST CM-7): if the deployment hasn't
// opted in, don't render the tool even on a hand-typed /chaos URL. The nav hides it; this
// is the route-level backstop. (The authoritative control is RBAC on the FaultInjection
// resource — this is defense in depth against surfacing it.)
export function ChaosPage() {
  const config = useConfig();
  if (!config.chaosUiEnabled) {
    return (
      <EmptyState
        icon={<Bomb />}
        title="Chaos tooling is disabled"
        description="Fault injection is turned off on this deployment. An operator can enable it by setting CHAOS_UI_ENABLED=true on the console."
      />
    );
  }
  return <ChaosPageInner />;
}

function ChaosPageInner() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<FaultInjection, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (f) => f.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 180,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (f) => f.metadata.namespace,
        cell: ({ row }) => <span className="text-muted-foreground">{row.original.metadata.namespace}</span>,
        size: 110,
      },
      {
        id: "type",
        header: "Fault",
        accessorFn: (f) => f.spec?.type,
        cell: ({ row }) => <Badge variant="secondary">{TYPE_LABEL[row.original.spec?.type ?? ""] ?? row.original.spec?.type}</Badge>,
        size: 150,
      },
      {
        id: "target",
        header: "Target (blast radius)",
        accessorFn: (f) => targetSummary(f),
        cell: ({ row }) => <code className="text-xs">{targetSummary(row.original)}</code>,
        size: 220,
      },
      {
        id: "duration",
        header: "Duration",
        accessorFn: (f) => f.spec?.duration ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground text-xs">
            {row.original.spec?.type === "pod-kill" ? "instant" : row.original.spec?.duration ?? "60s"}
          </span>
        ),
        size: 90,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (f) => fiStatus(f).label,
        cell: ({ row }) => {
          const s = fiStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 120,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (f) => f.metadata.creationTimestamp ?? "",
        cell: ({ row }) => <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>,
        size: 70,
      },
    ],
    [],
  );

  return (
    <>
      <ResourceTablePage<FaultInjection>
        icon={<Bomb />}
        title="Chaos"
        description="Fault injection — open-infra's Fault Injection Simulator (Chaos Mesh). Inject pod kills, network faults, resource stress, clock skew, or disk-IO latency to prove the platform's resilience. Every experiment is scoped to a namespace + label selector (blast radius enforced) and time-boxed."
        listPath={openinfraPaths.faultinjections}
        columns={columns}
        onRowClick={(f) =>
          navigate({
            to: "/chaos/$namespace/$name",
            params: {
              namespace: f.metadata.namespace ?? "default",
              name: f.metadata.name ?? "",
            },
          })
        }
        search={(f) => [f.metadata.name, f.metadata.namespace, f.spec?.type, targetSummary(f)]}
        singular="Fault Injection"
        plural="Fault Injections"
        emptyTitle="No experiments yet"
        emptyDescription="Run a fault injection scoped to a namespace + label selector."
        docsHref={kindDocsUrl("FaultInjection")}
        headerActions={
          <Button onClick={() => navigate({ to: "/chaos/new" })}>
            <Plus className="size-4" /> New Fault Injection
          </Button>
        }
      />
    </>
  );
}
