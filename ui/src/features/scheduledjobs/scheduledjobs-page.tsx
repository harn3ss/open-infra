import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "@tanstack/react-router";
import { CalendarClock, Plus } from "lucide-react";
import { StatusBadge } from "@/components/common/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ResourceTablePage } from "@/components/common/resource-table-page";
import { kindDocsUrl } from "@/lib/kind-docs";
import { claimHealth } from "@/lib/resource-health";
import { openinfraPaths } from "@/lib/k8s-paths";
import { age } from "@/lib/format";
import type { ScheduledJob } from "@/types/k8s";

/** kind: ScheduledJob — run a container to completion on a schedule (an AWS scheduled task /
 *  EventBridge-Scheduler analog). Backed by a CronJob whose runs are Jobs; run history is on the
 *  detail page's Runs tab. */
export function ScheduledJobsPage() {
  const navigate = useNavigate();
  const columns = useMemo<ColumnDef<ScheduledJob, unknown>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        accessorFn: (s) => s.metadata.name,
        cell: ({ row }) => <span className="font-medium">{row.original.metadata.name}</span>,
        size: 200,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (s) => s.metadata.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.metadata.namespace}</span>
        ),
        size: 130,
      },
      {
        id: "schedule",
        header: "Schedule",
        accessorFn: (s) => s.spec?.schedule ?? "",
        cell: ({ row }) => <code className="text-xs">{row.original.spec?.schedule ?? "—"}</code>,
        size: 150,
      },
      {
        id: "image",
        header: "Image",
        accessorFn: (s) => s.spec?.image ?? "",
        cell: ({ row }) => (
          <code className="truncate text-xs text-muted-foreground" title={row.original.spec?.image}>
            {row.original.spec?.image ?? "—"}
          </code>
        ),
        size: 240,
      },
      {
        id: "suspended",
        header: "Suspended",
        accessorFn: (s) => (s.spec?.suspend ? "Suspended" : "Active"),
        cell: ({ row }) =>
          row.original.spec?.suspend ? (
            <Badge variant="warning">Suspended</Badge>
          ) : (
            <span className="text-muted-foreground">No</span>
          ),
        size: 120,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (s) => claimHealth(s).label,
        cell: ({ row }) => {
          const h = claimHealth(row.original);
          return <StatusBadge status={h.label} tone={h.tone} />;
        },
        size: 140,
      },
      {
        id: "age",
        header: "Age",
        accessorFn: (s) => s.metadata.creationTimestamp ?? "",
        cell: ({ row }) => (
          <span className="text-muted-foreground">{age(row.original.metadata.creationTimestamp)}</span>
        ),
        size: 90,
      },
    ],
    [],
  );

  return (
    <ResourceTablePage<ScheduledJob>
      icon={<CalendarClock />}
      title="Scheduled Jobs"
      description="Run a container to completion on a schedule — open-infra's scheduled task (EventBridge Scheduler). Each run is a Job, with retries, a concurrency policy, and a per-run timeout."
      listPath={openinfraPaths.scheduledjobs}
      columns={columns}
      search={(s) => [s.metadata.name, s.metadata.namespace, s.spec?.schedule, s.spec?.image]}
      singular="Scheduled Job"
      plural="Scheduled Jobs"
      emptyTitle="No Scheduled Jobs yet"
      emptyDescription="Schedule a container to run on a cron/rate expression; pick an image and a schedule, and open-infra runs it to completion each time."
      docsHref={kindDocsUrl("ScheduledJob")}
      headerActions={
        <Button onClick={() => navigate({ to: "/scheduled-jobs/new" })}>
          <Plus className="size-4" />
          New Scheduled Job
        </Button>
      }
      onRowClick={(s) =>
        navigate({
          to: "/scheduled-jobs/$namespace/$name",
          params: { namespace: s.metadata.namespace ?? "default", name: s.metadata.name ?? "" },
        })
      }
    />
  );
}
