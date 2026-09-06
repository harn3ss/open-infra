import { useMemo } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { type ColumnDef } from "@tanstack/react-table";
import { ScrollText, Plus } from "lucide-react";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { kindDocsUrl } from "@/lib/kind-docs";
import { StatusBadge } from "@/components/common/status-badge";
import { Button } from "@/components/ui/button";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { StatusTone } from "@/lib/format";
import { type Condition, type FlowLog } from "@/types/k8s";

function flowLogStatus(f: FlowLog): { label: string; tone: StatusTone } {
  const ready = (f.status as { conditions?: Condition[] } | undefined)?.conditions?.find(
    (c) => c.type === "Ready",
  );
  if (ready?.status === "True" || f.status?.ready === true) return { label: "Ready", tone: "success" };
  return { label: "Provisioning", tone: "warning" };
}

/** Human summary of a FlowLog's node placement: its nodeSelector, or "All nodes". */
function nodesSummary(f: FlowLog): string {
  const sel = f.spec?.nodeSelector;
  const entries = sel ? Object.entries(sel) : [];
  if (!entries.length) return "All nodes";
  return entries.map(([k, v]) => `${k}=${v}`).join(", ");
}

/**
 * VPC Flow Logs list (kube-ovn → OVS sFlow → Loki). Unlike AWS, flow logging is a
 * node-wide sampled capture — typically zero or one FlowLog per cluster; scoping to a
 * VPC/subnet is a query-time CIDR filter over the records, not a per-resource capture.
 */
export function FlowLogsPage() {
  const navigate = useNavigate();

  const columns = useMemo<ColumnDef<FlowLog, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (f) => f.metadata.name,
        cell: ({ row }) => (
          <Link
            to="/flow-logs/$namespace/$name"
            params={{
              namespace: row.original.metadata.namespace ?? "default",
              name: row.original.metadata.name ?? "",
            }}
            className="font-medium text-primary hover:underline"
          >
            {row.original.metadata.name}
          </Link>
        ),
        size: 220,
      },
      {
        id: "sampling",
        header: "Sampling",
        accessorFn: (f) => f.spec?.samplingRate ?? 64,
        cell: ({ row }) => (
          <span className="text-muted-foreground">1:{row.original.spec?.samplingRate ?? 64}</span>
        ),
        size: 100,
      },
      {
        id: "nodes",
        header: "Nodes",
        accessorFn: (f) => nodesSummary(f),
        cell: ({ row }) => (
          <span className="text-muted-foreground">{nodesSummary(row.original)}</span>
        ),
        size: 240,
      },
      {
        id: "namespace",
        header: "Collector namespace",
        accessorFn: (f) => f.spec?.namespace ?? "kube-system",
        cell: ({ row }) => (
          <code className="text-xs text-muted-foreground">
            {row.original.spec?.namespace ?? "kube-system"}
          </code>
        ),
        size: 180,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (f) => flowLogStatus(f).label,
        cell: ({ row }) => {
          const s = flowLogStatus(row.original);
          return <StatusBadge status={s.label} tone={s.tone} />;
        },
        size: 110,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (f) => f.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 70,
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<FlowLog>
      icon={<ScrollText />}
      title="Flow Logs"
      description="Node-wide packet sampling (OVS sFlow → Loki). Scope to a VPC or subnet by filtering records on CIDR — this is a sampled 1:N record stream, not a per-connection ledger. There is no CloudWatch/S3/Firehose destination choice; records always land in Loki."
      listPath={openinfraPaths.flowlogs}
      columns={columns}
      onRowClick={(f) =>
        navigate({
          to: "/flow-logs/$namespace/$name",
          params: {
            namespace: f.metadata.namespace ?? "default",
            name: f.metadata.name ?? "",
          },
        })
      }
      search={(f) => [f.metadata.name, f.metadata.namespace]}
      singular="Flow Log"
      plural="Flow Logs"
      emptyTitle="No flow logs yet"
      emptyDescription="Create a flow log to start sampling node traffic to Loki; view records filtered by CIDR."
      docsHref={kindDocsUrl("FlowLog")}
      headerActions={
        <Button onClick={() => navigate({ to: "/flow-logs/new" })}>
          <Plus className="size-4" /> New Flow Log
        </Button>
      }
    />
  );
}
