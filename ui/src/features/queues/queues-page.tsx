import { useMemo, useState } from "react";
import { type ColumnDef, type SortingState } from "@tanstack/react-table";
import { Send, RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/common/page-header";
import { Button } from "@/components/ui/button";
import { LiveIndicator } from "@/components/common/live-indicator";
import { VirtualDataTable } from "@/components/common/virtual-data-table";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/common/states";
import { useK8sWatch } from "@/hooks/use-k8s-watch";
import { useListFilter } from "@/hooks/use-list-filter";
import { useNamespace } from "@/lib/namespace-context";
import { openinfraPaths } from "@/lib/k8s-paths";
import type { Application } from "@/types/k8s";

interface QueueRow {
  id: string;
  queue: string;
  app: string;
  namespace: string;
}

// Queues (NATS subjects) are declared by Applications (spec.queues); surface them
// aggregated across Applications with their owning app.
export function QueuesPage() {
  const { scoped } = useNamespace();
  const { items, isLoading, isError, error, live, refetch } =
    useK8sWatch<Application>(openinfraPaths.applications(scoped));

  const rows = useMemo<QueueRow[]>(
    () =>
      items.flatMap((a) =>
        (a.spec?.queues ?? []).map((q) => ({
          id: `${a.metadata.namespace}/${a.metadata.name}/${q}`,
          queue: q,
          app: a.metadata.name ?? "",
          namespace: a.metadata.namespace ?? "",
        })),
      ),
    [items],
  );

  const { filtered } = useListFilter(rows, (r) => [r.queue, r.app, r.namespace]);
  const [sorting, setSorting] = useState<SortingState>([
    { id: "queue", desc: false },
  ]);

  const columns = useMemo<ColumnDef<QueueRow, unknown>[]>(
    () => [
      {
        id: "queue",
        header: "Queue",
        accessorFn: (r) => r.queue,
        cell: ({ row }) => (
          <span className="font-medium">{row.original.queue}</span>
        ),
        size: 280,
      },
      {
        id: "app",
        header: "Application",
        accessorFn: (r) => r.app,
        cell: ({ row }) => (
          <span className="text-muted-foreground">{row.original.app}</span>
        ),
        size: 220,
      },
      {
        id: "namespace",
        header: "Namespace",
        accessorFn: (r) => r.namespace,
        cell: ({ row }) => (
          <span className="text-muted-foreground">
            {row.original.namespace}
          </span>
        ),
        size: 160,
      },
    ],
    [],
  );

  return (
    <div className="space-y-5">
      <PageHeader
        icon={<Send />}
        title="Queues"
        description="Messaging — open-infra's SQS/SNS (NATS JetStream). Declared by Applications via `queues`; the app gets NATS_URL + OPENINFRA_QUEUES."
        actions={
          <>
            <LiveIndicator live={live} />
            <Button
              variant="outline"
              size="icon"
              onClick={refetch}
              aria-label="Refresh"
            >
              <RefreshCw className="size-4" />
            </Button>
          </>
        }
      />
      {isLoading ? (
        <LoadingState label="Loading queues…" />
      ) : isError ? (
        <ErrorState error={error} onRetry={refetch} />
      ) : rows.length === 0 ? (
        <EmptyState
          icon={<Send className="size-6" />}
          title="No queues yet"
          description="Add `queues: [jobs]` to an Application — the app is wired to NATS with NATS_URL and OPENINFRA_QUEUES."
        />
      ) : (
        <>
          <p className="text-sm text-muted-foreground">
            {filtered.length} of {rows.length}{" "}
            {rows.length === 1 ? "queue" : "queues"}
          </p>
          <VirtualDataTable
            data={filtered}
            columns={columns}
            getRowId={(r) => r.id}
            sorting={sorting}
            onSortingChange={setSorting}
            emptyState={
              <EmptyState
                title="No matches"
                description="No queues match the current filter."
              />
            }
          />
        </>
      )}
    </div>
  );
}
